package password

import (
	"context"
	"errors"
	"testing"
	"time"

	"ddone-server-auth/internal/domain/user"

	"golang.org/x/crypto/bcrypt"
)

type fakeUserStore struct {
	byID    map[string]*user.User
	byPhone map[string]*user.User
	updated *user.User
}

func (f *fakeUserStore) GetByID(_ context.Context, id string) (*user.User, error) {
	userModel, ok := f.byID[id]
	if !ok {
		return nil, user.ErrUserNotFound
	}

	copyValue := *userModel
	return &copyValue, nil
}

func (f *fakeUserStore) GetByPhoneNumber(_ context.Context, phoneNumber string) (*user.User, error) {
	userModel, ok := f.byPhone[phoneNumber]
	if !ok {
		return nil, user.ErrUserNotFound
	}

	copyValue := *userModel
	return &copyValue, nil
}

func (f *fakeUserStore) Update(_ context.Context, userModel *user.User) error {
	copyValue := *userModel
	f.updated = &copyValue
	f.byID[userModel.ID] = &copyValue
	f.byPhone[userModel.PhoneNumber] = &copyValue
	return nil
}

type fakeResetStore struct {
	states   map[string]*ResetTicketState
	counters map[string]int64
}

func (f *fakeResetStore) Save(_ context.Context, state *ResetTicketState, _ time.Duration) error {
	copyValue := *state
	f.states[state.TicketID] = &copyValue
	return nil
}

func (f *fakeResetStore) Get(_ context.Context, ticketID string) (*ResetTicketState, error) {
	state, ok := f.states[ticketID]
	if !ok {
		return nil, ErrPasswordResetTicketNotFound
	}

	copyValue := *state
	return &copyValue, nil
}

func (f *fakeResetStore) Delete(_ context.Context, ticketID string) error {
	delete(f.states, ticketID)
	return nil
}

func (f *fakeResetStore) IncrementCounter(_ context.Context, key string, _ time.Duration) (int64, error) {
	f.counters[key]++
	return f.counters[key], nil
}

func (f *fakeResetStore) DeleteCounter(_ context.Context, key string) error {
	delete(f.counters, key)
	return nil
}

type fakeSender struct {
	phoneNumber string
	message     string
	err         error
}

func (f *fakeSender) SendOTP(_ context.Context, phoneNumber string, message string) error {
	f.phoneNumber = phoneNumber
	f.message = message
	return f.err
}

type fakeRevoker struct {
	userID string
	reason string
	calls  int
	err    error
}

func (f *fakeRevoker) RevokeByUserID(_ context.Context, userID string, reason string, _ time.Time) error {
	if f.err != nil {
		return f.err
	}

	f.calls++
	f.userID = userID
	f.reason = reason
	return nil
}

func TestForgotPasswordCreatesResetTicketAndSendsOTP(t *testing.T) {
	hashed, err := bcrypt.GenerateFromPassword([]byte("secretpass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	users := &fakeUserStore{
		byID: map[string]*user.User{
			"user-1": {ID: "user-1", PhoneNumber: "2012345678", PasswordHash: string(hashed)},
		},
		byPhone: map[string]*user.User{
			"2012345678": {ID: "user-1", PhoneNumber: "2012345678", PasswordHash: string(hashed)},
		},
	}
	store := &fakeResetStore{states: map[string]*ResetTicketState{}, counters: map[string]int64{}}
	sender := &fakeSender{}
	refreshRevoker := &fakeRevoker{}
	loginRevoker := &fakeRevoker{}
	service := NewService(users, store, sender, refreshRevoker, loginRevoker)
	service.now = func() time.Time { return time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC) }
	service.ticketGenerator = func() (string, error) { return "pwd_fixed123", nil }
	service.otpGenerator = func(int) (string, error) { return "123456", nil }

	result, err := service.ForgotPassword(context.Background(), ForgotPasswordInput{
		PhoneNumber: "+8562012345678",
	})
	if err != nil {
		t.Fatalf("forgot password: %v", err)
	}
	if result.TicketID != "pwd_fixed123" {
		t.Fatalf("expected ticket id to be persisted, got %q", result.TicketID)
	}
	if sender.phoneNumber != "2012345678" {
		t.Fatalf("expected normalized phone number, got %q", sender.phoneNumber)
	}
	if _, ok := store.states["pwd_fixed123"]; !ok {
		t.Fatal("expected reset ticket to be stored")
	}
}

func TestVerifyForgotPasswordUpdatesPasswordAndRevokesSessions(t *testing.T) {
	currentHash, err := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	userModel := &user.User{
		ID:           "user-1",
		PhoneNumber:  "2012345678",
		PasswordHash: string(currentHash),
		UpdatedAt:    time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC),
	}
	users := &fakeUserStore{
		byID:    map[string]*user.User{"user-1": userModel},
		byPhone: map[string]*user.User{"2012345678": userModel},
	}
	store := &fakeResetStore{
		states: map[string]*ResetTicketState{
			"pwd_fixed123": {
				TicketID:     "pwd_fixed123",
				UserID:       "user-1",
				PhoneNumber:  "2012345678",
				OTPCodeHash:  hashResetOTP("pwd_fixed123", "123456"),
				OTPExpiresAt: time.Date(2026, 5, 24, 0, 5, 0, 0, time.UTC),
				CreatedAt:    time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
			},
		},
		counters: map[string]int64{},
	}
	refreshRevoker := &fakeRevoker{}
	loginRevoker := &fakeRevoker{}
	service := NewService(users, store, &fakeSender{}, refreshRevoker, loginRevoker)
	service.now = func() time.Time { return time.Date(2026, 5, 24, 0, 1, 0, 0, time.UTC) }

	if err := service.VerifyForgotPassword(context.Background(), VerifyForgotPasswordInput{
		TicketID:    "pwd_fixed123",
		OTPCode:     "123456",
		NewPassword: "new-password",
	}); err != nil {
		t.Fatalf("verify forgot password: %v", err)
	}
	if users.updated == nil {
		t.Fatal("expected user to be updated")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(users.updated.PasswordHash), []byte("new-password")); err != nil {
		t.Fatal("expected password hash to be replaced")
	}
	if users.updated.PasswordChangedAt == nil {
		t.Fatal("expected password changed at to be recorded")
	}
	if refreshRevoker.calls != 1 || loginRevoker.calls != 1 {
		t.Fatal("expected both session stores to be revoked")
	}
	if _, ok := store.states["pwd_fixed123"]; ok {
		t.Fatal("expected reset ticket to be deleted after success")
	}
}

func TestChangePasswordUpdatesPasswordAndRevokesSessions(t *testing.T) {
	currentHash, err := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	userModel := &user.User{
		ID:           "user-1",
		PhoneNumber:  "2012345678",
		PasswordHash: string(currentHash),
	}
	users := &fakeUserStore{
		byID:    map[string]*user.User{"user-1": userModel},
		byPhone: map[string]*user.User{"2012345678": userModel},
	}
	refreshRevoker := &fakeRevoker{}
	loginRevoker := &fakeRevoker{}
	service := NewService(
		users,
		&fakeResetStore{states: map[string]*ResetTicketState{}, counters: map[string]int64{}},
		&fakeSender{},
		refreshRevoker,
		loginRevoker,
	)
	service.now = func() time.Time { return time.Date(2026, 5, 24, 1, 0, 0, 0, time.UTC) }

	err = service.ChangePassword(context.Background(), ChangePasswordInput{
		UserID:          "user-1",
		CurrentPassword: "old-password",
		NewPassword:     "new-password",
	})
	if err != nil {
		t.Fatalf("ChangePassword returned error: %v", err)
	}
	if users.updated == nil {
		t.Fatal("expected user to be updated")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(users.updated.PasswordHash), []byte("new-password")); err != nil {
		t.Fatal("expected password hash to be replaced")
	}
	if users.updated.PasswordChangedAt == nil {
		t.Fatal("expected password changed at to be recorded")
	}
	if refreshRevoker.calls != 1 || loginRevoker.calls != 1 {
		t.Fatal("expected both session stores to be revoked")
	}
}

func TestChangePasswordRejectsInvalidCurrentPassword(t *testing.T) {
	currentHash, err := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	userModel := &user.User{
		ID:           "user-1",
		PhoneNumber:  "2012345678",
		PasswordHash: string(currentHash),
	}
	users := &fakeUserStore{
		byID:    map[string]*user.User{"user-1": userModel},
		byPhone: map[string]*user.User{"2012345678": userModel},
	}
	service := NewService(
		users,
		&fakeResetStore{states: map[string]*ResetTicketState{}, counters: map[string]int64{}},
		&fakeSender{},
		&fakeRevoker{},
		&fakeRevoker{},
	)

	err = service.ChangePassword(context.Background(), ChangePasswordInput{
		UserID:          "user-1",
		CurrentPassword: "wrong-password",
		NewPassword:     "new-password",
	})
	if !errors.Is(err, ErrInvalidCurrentPassword) {
		t.Fatalf("expected ErrInvalidCurrentPassword, got %v", err)
	}
}
