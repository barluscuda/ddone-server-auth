package services

import (
	"context"
	"ddone-server-auth/internal/domain/account"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type fakeAccountRepository struct {
	accountsByPhone map[string]*account.AccountModel
	accountsByUser  map[string]*account.AccountModel
	created         *account.AccountModel
}

func (r *fakeAccountRepository) Create(_ context.Context, accountModel *account.AccountModel) error {
	r.created = accountModel
	if r.accountsByPhone == nil {
		r.accountsByPhone = map[string]*account.AccountModel{}
	}
	r.accountsByPhone[accountModel.PhoneNumber] = accountModel

	if accountModel.Username != nil {
		if r.accountsByUser == nil {
			r.accountsByUser = map[string]*account.AccountModel{}
		}
		r.accountsByUser[*accountModel.Username] = accountModel
	}

	return nil
}

func (r *fakeAccountRepository) GetByID(_ context.Context, _ string) (*account.AccountModel, error) {
	return nil, account.ErrAccountNotFound
}

func (r *fakeAccountRepository) GetByPhoneNumber(_ context.Context, phoneNumber string) (*account.AccountModel, error) {
	if accountModel, ok := r.accountsByPhone[phoneNumber]; ok {
		return accountModel, nil
	}

	return nil, account.ErrAccountNotFound
}

func (r *fakeAccountRepository) GetByUsername(_ context.Context, username string) (*account.AccountModel, error) {
	if accountModel, ok := r.accountsByUser[username]; ok {
		return accountModel, nil
	}

	return nil, account.ErrAccountNotFound
}

func (r *fakeAccountRepository) GetByProvider(_ context.Context, _ account.AuthProvider, _ string) (*account.AccountModel, error) {
	return nil, account.ErrAccountNotFound
}

func (r *fakeAccountRepository) Update(_ context.Context, _ *account.AccountModel) error {
	return nil
}

func (r *fakeAccountRepository) Delete(_ context.Context, _ string) error {
	return nil
}

type fakeRegistrationStore struct {
	values       map[string]*account.RegisterModel
	deletedPhone string
}

func (s *fakeRegistrationStore) Save(_ context.Context, registration *account.RegisterModel, _ time.Duration) error {
	if s.values == nil {
		s.values = map[string]*account.RegisterModel{}
	}
	s.values[registration.PhoneNumber] = registration
	return nil
}

func (s *fakeRegistrationStore) Get(_ context.Context, phoneNumber string) (*account.RegisterModel, error) {
	if registration, ok := s.values[phoneNumber]; ok {
		return registration, nil
	}

	return nil, account.ErrPendingRegistrationNotFound
}

func (s *fakeRegistrationStore) Delete(_ context.Context, phoneNumber string) error {
	s.deletedPhone = phoneNumber
	delete(s.values, phoneNumber)
	return nil
}

type fakeOTPSender struct {
	phoneNumber string
	message     string
	err         error
}

func (s *fakeOTPSender) SendOTP(_ context.Context, phoneNumber string, msg string) error {
	s.phoneNumber = phoneNumber
	s.message = msg
	return s.err
}

func TestRegisterServiceRegisterSavesRegistrationAndSendsSMS(t *testing.T) {
	repo := &fakeAccountRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{}
	service := NewRegisterService(repo, store, sender)
	service.usernameGenerator = func() (string, error) { return "user_fixed123", nil }

	result, err := service.Register(context.Background(), RegisterInput{
		PhoneNumber: "  +8562012345678  ",
		Password:    "secretpass",
	})
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	if result.ExpiresAt.IsZero() {
		t.Fatal("expected non-zero expiry time")
	}

	registration, err := store.Get(context.Background(), "+8562012345678")
	if err != nil {
		t.Fatalf("expected saved registration: %v", err)
	}

	if registration.Username == nil || *registration.Username != "user_fixed123" {
		t.Fatalf("expected generated username, got %#v", registration.Username)
	}

	if registration.PasswordHash == "" {
		t.Fatal("expected password hash to be stored")
	}

	if registration.PasswordHash == "secretpass" {
		t.Fatal("expected password to be hashed before storage")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(registration.PasswordHash), []byte("secretpass")); err != nil {
		t.Fatalf("expected password hash to match original password: %v", err)
	}

	if len(registration.OTPCode) != registerOTPLength {
		t.Fatalf("expected otp length %d, got %d", registerOTPLength, len(registration.OTPCode))
	}

	if sender.phoneNumber != "+8562012345678" {
		t.Fatalf("expected sms phone number to be trimmed, got %s", sender.phoneNumber)
	}

	if !strings.Contains(sender.message, registration.OTPCode) {
		t.Fatalf("expected sms message to contain otp code, got %q", sender.message)
	}
}

func TestRegisterServiceRegisterDeletesCacheWhenSMSFails(t *testing.T) {
	repo := &fakeAccountRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{err: errors.New("sms unavailable")}
	service := NewRegisterService(repo, store, sender)

	_, err := service.Register(context.Background(), RegisterInput{
		PhoneNumber: "+8562012345678",
		Password:    "secretpass",
	})
	if err == nil {
		t.Fatal("expected sms failure")
	}

	if store.deletedPhone != "+8562012345678" {
		t.Fatalf("expected cache cleanup for phone number, got %q", store.deletedPhone)
	}
}

func TestRegisterServiceRegisterRejectsWhitespacePhoneNumber(t *testing.T) {
	repo := &fakeAccountRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{}
	service := NewRegisterService(repo, store, sender)

	_, err := service.Register(context.Background(), RegisterInput{
		PhoneNumber: "        ",
		Password:    "secretpass",
	})
	if !errors.Is(err, ErrPhoneNumberRequired) {
		t.Fatalf("expected ErrPhoneNumberRequired, got %v", err)
	}
}

func TestRegisterServiceRegisterRejectsWhitespacePassword(t *testing.T) {
	repo := &fakeAccountRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{}
	service := NewRegisterService(repo, store, sender)

	_, err := service.Register(context.Background(), RegisterInput{
		PhoneNumber: "+8562012345678",
		Password:    "        ",
	})
	if !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("expected ErrPasswordRequired, got %v", err)
	}
}

func TestRegisterServiceVerifyRegisterCreatesAccountAndDeletesCache(t *testing.T) {
	repo := &fakeAccountRepository{}
	store := &fakeRegistrationStore{
		values: map[string]*account.RegisterModel{},
	}
	sender := &fakeOTPSender{}
	service := NewRegisterService(repo, store, sender)

	now := time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }

	username := "user_fixed123"
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("secretpass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("generate password hash: %v", err)
	}

	store.values["+8562012345678"] = &account.RegisterModel{
		Username:     &username,
		PasswordHash: string(passwordHash),
		PhoneNumber:  "+8562012345678",
		OTPCode:      "123456",
		OTPExpiresAt: now.Add(time.Minute),
		CreatedAt:    now.Add(-time.Minute),
	}

	accountModel, err := service.VerifyRegister(context.Background(), VerifyRegisterInput{
		PhoneNumber: "+8562012345678",
		OTPCode:     "123456",
	})
	if err != nil {
		t.Fatalf("VerifyRegister returned error: %v", err)
	}

	if accountModel.PhoneVerifiedAt != now {
		t.Fatalf("expected verified at %v, got %v", now, accountModel.PhoneVerifiedAt)
	}

	if repo.created == nil {
		t.Fatal("expected account to be created")
	}

	if repo.created.Username == nil || *repo.created.Username != username {
		t.Fatalf("expected generated username to be carried to account, got %#v", repo.created.Username)
	}

	if repo.created.PasswordHash != string(passwordHash) {
		t.Fatal("expected password hash to be persisted on account creation")
	}

	if store.deletedPhone != "+8562012345678" {
		t.Fatalf("expected pending registration to be deleted, got %q", store.deletedPhone)
	}
}

func TestRegisterServiceVerifyRegisterRejectsInvalidCode(t *testing.T) {
	repo := &fakeAccountRepository{}
	store := &fakeRegistrationStore{
		values: map[string]*account.RegisterModel{
			"+8562012345678": {
				PhoneNumber:  "+8562012345678",
				OTPCode:      "123456",
				OTPExpiresAt: time.Now().UTC().Add(time.Minute),
			},
		},
	}
	sender := &fakeOTPSender{}
	service := NewRegisterService(repo, store, sender)

	_, err := service.VerifyRegister(context.Background(), VerifyRegisterInput{
		PhoneNumber: "+8562012345678",
		OTPCode:     "654321",
	})
	if !errors.Is(err, account.ErrInvalidOTPCode) {
		t.Fatalf("expected invalid otp error, got %v", err)
	}

	if repo.created != nil {
		t.Fatal("did not expect account creation on invalid otp")
	}
}

func TestRegisterServiceVerifyRegisterRejectsWhitespaceOTPCode(t *testing.T) {
	repo := &fakeAccountRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{}
	service := NewRegisterService(repo, store, sender)

	_, err := service.VerifyRegister(context.Background(), VerifyRegisterInput{
		PhoneNumber: "+8562012345678",
		OTPCode:     "      ",
	})
	if !errors.Is(err, ErrOTPCodeRequired) {
		t.Fatalf("expected ErrOTPCodeRequired, got %v", err)
	}
}

func TestRegisterServiceVerifyRegisterRejectsPendingRegistrationWithoutPasswordHash(t *testing.T) {
	repo := &fakeAccountRepository{}
	store := &fakeRegistrationStore{
		values: map[string]*account.RegisterModel{
			"+8562012345678": {
				Username:     stringPtr("user_fixed123"),
				PhoneNumber:  "+8562012345678",
				OTPCode:      "123456",
				OTPExpiresAt: time.Now().UTC().Add(time.Minute),
			},
		},
	}
	sender := &fakeOTPSender{}
	service := NewRegisterService(repo, store, sender)

	_, err := service.VerifyRegister(context.Background(), VerifyRegisterInput{
		PhoneNumber: "+8562012345678",
		OTPCode:     "123456",
	})
	if !errors.Is(err, ErrPendingRegistrationInvalid) {
		t.Fatalf("expected ErrPendingRegistrationInvalid, got %v", err)
	}

	if store.deletedPhone != "+8562012345678" {
		t.Fatalf("expected stale pending registration to be deleted, got %q", store.deletedPhone)
	}
}

func TestRegisterServiceVerifyRegisterRegeneratesUsernameWhenStoredOneIsTaken(t *testing.T) {
	takenUsername := "user_taken"
	repo := &fakeAccountRepository{
		accountsByUser: map[string]*account.AccountModel{
			takenUsername: {Username: &takenUsername},
		},
	}
	store := &fakeRegistrationStore{
		values: map[string]*account.RegisterModel{
			"+8562012345678": {
				Username:     &takenUsername,
				PasswordHash: "hashed-password",
				PhoneNumber:  "+8562012345678",
				OTPCode:      "123456",
				OTPExpiresAt: time.Now().UTC().Add(time.Minute),
			},
		},
	}
	sender := &fakeOTPSender{}
	service := NewRegisterService(repo, store, sender)
	service.usernameGenerator = func() (string, error) { return "user_fresh123", nil }

	accountModel, err := service.VerifyRegister(context.Background(), VerifyRegisterInput{
		PhoneNumber: "+8562012345678",
		OTPCode:     "123456",
	})
	if err != nil {
		t.Fatalf("VerifyRegister returned error: %v", err)
	}

	if accountModel.Username == nil || *accountModel.Username != "user_fresh123" {
		t.Fatalf("expected username to be regenerated, got %#v", accountModel.Username)
	}
}

func stringPtr(value string) *string {
	return &value
}
