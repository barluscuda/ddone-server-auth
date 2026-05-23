package password

import (
	"context"
	"errors"
	"testing"
	"time"

	"ddone-server-auth/internal/domain/account"

	"golang.org/x/crypto/bcrypt"
)

type fakeAccountStore struct {
	byID    map[string]*account.AccountModel
	byPhone map[string]*account.AccountModel
	updated *account.AccountModel
}

func (f *fakeAccountStore) GetByID(_ context.Context, id string) (*account.AccountModel, error) {
	accountModel, ok := f.byID[id]
	if !ok {
		return nil, account.ErrAccountNotFound
	}

	copyValue := *accountModel
	return &copyValue, nil
}

func (f *fakeAccountStore) GetByPhoneNumber(_ context.Context, phoneNumber string) (*account.AccountModel, error) {
	accountModel, ok := f.byPhone[phoneNumber]
	if !ok {
		return nil, account.ErrAccountNotFound
	}

	copyValue := *accountModel
	return &copyValue, nil
}

func (f *fakeAccountStore) Update(_ context.Context, accountModel *account.AccountModel) error {
	copyValue := *accountModel
	f.updated = &copyValue
	f.byID[accountModel.ID] = &copyValue
	f.byPhone[accountModel.PhoneNumber] = &copyValue
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
	accountID string
	reason    string
	calls     int
	err       error
}

func (f *fakeRevoker) RevokeByAccountID(_ context.Context, accountID string, reason string, _ time.Time) error {
	if f.err != nil {
		return f.err
	}

	f.calls++
	f.accountID = accountID
	f.reason = reason
	return nil
}

func TestForgotPasswordCreatesResetTicketAndSendsOTP(t *testing.T) {
	hashed, err := bcrypt.GenerateFromPassword([]byte("secretpass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	accounts := &fakeAccountStore{
		byID: map[string]*account.AccountModel{
			"account-1": {ID: "account-1", PhoneNumber: "2012345678", PasswordHash: string(hashed)},
		},
		byPhone: map[string]*account.AccountModel{
			"2012345678": {ID: "account-1", PhoneNumber: "2012345678", PasswordHash: string(hashed)},
		},
	}
	store := &fakeResetStore{states: map[string]*ResetTicketState{}, counters: map[string]int64{}}
	sender := &fakeSender{}
	refreshRevoker := &fakeRevoker{}
	loginRevoker := &fakeRevoker{}
	service := NewService(accounts, store, sender, refreshRevoker, loginRevoker)
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

	accountModel := &account.AccountModel{
		ID:           "account-1",
		PhoneNumber:  "2012345678",
		PasswordHash: string(currentHash),
		UpdatedAt:    time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC),
	}
	accounts := &fakeAccountStore{
		byID:    map[string]*account.AccountModel{"account-1": accountModel},
		byPhone: map[string]*account.AccountModel{"2012345678": accountModel},
	}
	store := &fakeResetStore{
		states: map[string]*ResetTicketState{
			"pwd_fixed123": {
				TicketID:     "pwd_fixed123",
				AccountID:    "account-1",
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
	service := NewService(accounts, store, &fakeSender{}, refreshRevoker, loginRevoker)
	service.now = func() time.Time { return time.Date(2026, 5, 24, 0, 1, 0, 0, time.UTC) }

	if err := service.VerifyForgotPassword(context.Background(), VerifyForgotPasswordInput{
		TicketID:    "pwd_fixed123",
		OTPCode:     "123456",
		NewPassword: "new-password",
	}); err != nil {
		t.Fatalf("verify forgot password: %v", err)
	}
	if accounts.updated == nil {
		t.Fatal("expected account to be updated")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(accounts.updated.PasswordHash), []byte("new-password")); err != nil {
		t.Fatal("expected password hash to be replaced")
	}
	if refreshRevoker.calls != 1 || loginRevoker.calls != 1 {
		t.Fatal("expected both session stores to be revoked")
	}
	if _, ok := store.states["pwd_fixed123"]; ok {
		t.Fatal("expected reset ticket to be deleted after success")
	}
}

func TestChangePasswordRejectsInvalidCurrentPassword(t *testing.T) {
	currentHash, err := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	accountModel := &account.AccountModel{
		ID:           "account-1",
		PhoneNumber:  "2012345678",
		PasswordHash: string(currentHash),
	}
	accounts := &fakeAccountStore{
		byID:    map[string]*account.AccountModel{"account-1": accountModel},
		byPhone: map[string]*account.AccountModel{"2012345678": accountModel},
	}
	service := NewService(
		accounts,
		&fakeResetStore{states: map[string]*ResetTicketState{}, counters: map[string]int64{}},
		&fakeSender{},
		&fakeRevoker{},
		&fakeRevoker{},
	)

	err = service.ChangePassword(context.Background(), ChangePasswordInput{
		AccountID:       "account-1",
		CurrentPassword: "wrong-password",
		NewPassword:     "new-password",
	})
	if !errors.Is(err, ErrInvalidCurrentPassword) {
		t.Fatalf("expected ErrInvalidCurrentPassword, got %v", err)
	}
}
