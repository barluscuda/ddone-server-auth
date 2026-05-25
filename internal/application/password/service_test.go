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
	telCode     string
	phoneNumber string
	message     string
	err         error
}

func (f *fakeSender) SendOTP(_ context.Context, telCode string, number string, message string) error {
	f.telCode = telCode
	f.phoneNumber = number
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
			"user-1": {ID: "user-1", PhoneNumber: "+8562012345678", PasswordHash: string(hashed)},
		},
		byPhone: map[string]*user.User{
			"+8562012345678": {ID: "user-1", PhoneNumber: "+8562012345678", PasswordHash: string(hashed)},
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
	if sender.telCode != "856" {
		t.Fatalf("expected sms tel code %q, got %q", "856", sender.telCode)
	}
	if sender.phoneNumber != "2012345678" {
		t.Fatalf("expected sms phone number %q, got %q", "2012345678", sender.phoneNumber)
	}
	if _, ok := store.states["pwd_fixed123"]; !ok {
		t.Fatal("expected reset ticket to be stored")
	}
}

func TestForgotPasswordRejectsPasswordCooldown(t *testing.T) {
	hashed, err := bcrypt.GenerateFromPassword([]byte("secretpass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	changedAt := time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC)
	userModel := &user.User{
		ID:                "user-1",
		PhoneNumber:       "+8562012345678",
		PasswordHash:      string(hashed),
		PasswordChangedAt: &changedAt,
	}
	users := &fakeUserStore{
		byID:    map[string]*user.User{"user-1": userModel},
		byPhone: map[string]*user.User{"+8562012345678": userModel},
	}
	store := &fakeResetStore{states: map[string]*ResetTicketState{}, counters: map[string]int64{}}
	service := NewService(users, store, &fakeSender{}, &fakeRevoker{}, &fakeRevoker{})
	service.now = func() time.Time { return changedAt.Add(24 * time.Hour) }

	err = func() error {
		_, err := service.ForgotPassword(context.Background(), ForgotPasswordInput{
			PhoneNumber: "+8562012345678",
		})
		return err
	}()
	if !errors.Is(err, ErrPasswordCooldownActive) {
		t.Fatalf("expected ErrPasswordCooldownActive, got %v", err)
	}
	if len(store.states) != 0 {
		t.Fatal("expected no reset ticket to be stored during cooldown")
	}
}

func TestForgotPasswordRateLimitsByIP(t *testing.T) {
	hashed, err := bcrypt.GenerateFromPassword([]byte("secretpass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	firstUser := &user.User{
		ID:           "user-1",
		PhoneNumber:  "+8562012345678",
		PasswordHash: string(hashed),
	}
	secondUser := &user.User{
		ID:           "user-2",
		PhoneNumber:  "+8562098765432",
		PasswordHash: string(hashed),
	}
	users := &fakeUserStore{
		byID: map[string]*user.User{
			firstUser.ID:  firstUser,
			secondUser.ID: secondUser,
		},
		byPhone: map[string]*user.User{
			firstUser.PhoneNumber:  firstUser,
			secondUser.PhoneNumber: secondUser,
		},
	}
	store := &fakeResetStore{states: map[string]*ResetTicketState{}, counters: map[string]int64{}}
	policy := defaultOTPPolicy
	policy.MaxPhoneRequests = 10
	policy.MaxIPRequests = 1
	service := NewServiceWithSettings(users, store, &fakeSender{}, &fakeRevoker{}, &fakeRevoker{}, Settings{OTPPolicy: policy})

	_, err = service.ForgotPassword(context.Background(), ForgotPasswordInput{
		PhoneNumber: firstUser.PhoneNumber,
		ClientIP:    "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("unexpected forgot password error on first attempt: %v", err)
	}

	_, err = service.ForgotPassword(context.Background(), ForgotPasswordInput{
		PhoneNumber: secondUser.PhoneNumber,
		ClientIP:    "127.0.0.1",
	})
	if !errors.Is(err, ErrResetRateLimited) {
		t.Fatalf("expected ErrResetRateLimited, got %v", err)
	}
}

func TestVerifyForgotPasswordUpdatesPasswordAndRevokesSessions(t *testing.T) {
	currentHash, err := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	userModel := &user.User{
		ID:           "user-1",
		PhoneNumber:  "+8562012345678",
		PasswordHash: string(currentHash),
		UpdatedAt:    time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC),
	}
	users := &fakeUserStore{
		byID:    map[string]*user.User{"user-1": userModel},
		byPhone: map[string]*user.User{"+8562012345678": userModel},
	}
	store := &fakeResetStore{
		states: map[string]*ResetTicketState{
			"pwd_fixed123": {
				TicketID:     "pwd_fixed123",
				UserID:       "user-1",
				PhoneNumber:  "+8562012345678",
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

func TestVerifyForgotPasswordRejectsPasswordCooldown(t *testing.T) {
	currentHash, err := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	changedAt := time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC)
	userModel := &user.User{
		ID:                "user-1",
		PhoneNumber:       "+8562012345678",
		PasswordHash:      string(currentHash),
		PasswordChangedAt: &changedAt,
	}
	users := &fakeUserStore{
		byID:    map[string]*user.User{"user-1": userModel},
		byPhone: map[string]*user.User{"+8562012345678": userModel},
	}
	store := &fakeResetStore{
		states: map[string]*ResetTicketState{
			"pwd_fixed123": {
				TicketID:     "pwd_fixed123",
				UserID:       "user-1",
				PhoneNumber:  "+8562012345678",
				OTPCodeHash:  hashResetOTP("pwd_fixed123", "123456"),
				OTPExpiresAt: changedAt.Add(25 * time.Hour),
				CreatedAt:    changedAt.Add(24 * time.Hour),
			},
		},
		counters: map[string]int64{},
	}
	refreshRevoker := &fakeRevoker{}
	loginRevoker := &fakeRevoker{}
	service := NewService(users, store, &fakeSender{}, refreshRevoker, loginRevoker)
	service.now = func() time.Time { return changedAt.Add(24 * time.Hour) }

	err = service.VerifyForgotPassword(context.Background(), VerifyForgotPasswordInput{
		TicketID:    "pwd_fixed123",
		OTPCode:     "123456",
		NewPassword: "new-password",
	})
	if !errors.Is(err, ErrPasswordCooldownActive) {
		t.Fatalf("expected ErrPasswordCooldownActive, got %v", err)
	}
	if users.updated != nil {
		t.Fatal("expected password not to be updated during cooldown")
	}
	if refreshRevoker.calls != 0 || loginRevoker.calls != 0 {
		t.Fatal("expected no revocation during cooldown")
	}
}

func TestChangePasswordUpdatesPasswordAndRevokesSessions(t *testing.T) {
	currentHash, err := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	userModel := &user.User{
		ID:           "user-1",
		PhoneNumber:  "+8562012345678",
		PasswordHash: string(currentHash),
	}
	users := &fakeUserStore{
		byID:    map[string]*user.User{"user-1": userModel},
		byPhone: map[string]*user.User{"+8562012345678": userModel},
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

func TestChangePasswordRejectsPasswordCooldown(t *testing.T) {
	currentHash, err := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	changedAt := time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC)
	userModel := &user.User{
		ID:                "user-1",
		PhoneNumber:       "+8562012345678",
		PasswordHash:      string(currentHash),
		PasswordChangedAt: &changedAt,
	}
	users := &fakeUserStore{
		byID:    map[string]*user.User{"user-1": userModel},
		byPhone: map[string]*user.User{"+8562012345678": userModel},
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
	service.now = func() time.Time { return changedAt.Add(24 * time.Hour) }

	err = service.ChangePassword(context.Background(), ChangePasswordInput{
		UserID:          "user-1",
		CurrentPassword: "old-password",
		NewPassword:     "new-password",
	})
	if !errors.Is(err, ErrPasswordCooldownActive) {
		t.Fatalf("expected ErrPasswordCooldownActive, got %v", err)
	}
	if users.updated != nil {
		t.Fatal("expected password not to be updated during cooldown")
	}
	if refreshRevoker.calls != 0 || loginRevoker.calls != 0 {
		t.Fatal("expected no revocation during cooldown")
	}
}

func TestChangePasswordRejectsInvalidCurrentPassword(t *testing.T) {
	currentHash, err := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	userModel := &user.User{
		ID:           "user-1",
		PhoneNumber:  "+8562012345678",
		PasswordHash: string(currentHash),
	}
	users := &fakeUserStore{
		byID:    map[string]*user.User{"user-1": userModel},
		byPhone: map[string]*user.User{"+8562012345678": userModel},
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
