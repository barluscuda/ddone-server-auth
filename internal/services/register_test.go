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
	values        map[string]*account.RegisterModel
	deletedTicket string
	counters      map[string]int64
	deletedKeys   []string
}

func (s *fakeRegistrationStore) Save(_ context.Context, registration *account.RegisterModel, _ time.Duration) error {
	if s.values == nil {
		s.values = map[string]*account.RegisterModel{}
	}
	s.values[registration.TicketID] = registration
	return nil
}

func (s *fakeRegistrationStore) Get(_ context.Context, ticketID string) (*account.RegisterModel, error) {
	if registration, ok := s.values[ticketID]; ok {
		return registration, nil
	}

	return nil, account.ErrPendingRegistrationNotFound
}

func (s *fakeRegistrationStore) Delete(_ context.Context, ticketID string) error {
	s.deletedTicket = ticketID
	delete(s.values, ticketID)
	return nil
}

func (s *fakeRegistrationStore) IncrementCounter(_ context.Context, key string, _ time.Duration) (int64, error) {
	if s.counters == nil {
		s.counters = map[string]int64{}
	}

	s.counters[key]++
	return s.counters[key], nil
}

func (s *fakeRegistrationStore) DeleteCounter(_ context.Context, key string) error {
	s.deletedKeys = append(s.deletedKeys, key)
	if s.counters != nil {
		delete(s.counters, key)
	}
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
	service.otpGenerator = func(int) (string, error) { return "123456", nil }
	service.ticketGenerator = func() (string, error) { return "reg_fixed123", nil }
	service.usernameGenerator = func() (string, error) { return "user_fixed123", nil }

	result, err := service.Register(context.Background(), RegisterInput{
		PhoneNumber: "  856 20 1234 5678  ",
		Password:    "secretpass",
		ClientID:    "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	if result.ExpiresAt.IsZero() {
		t.Fatal("expected non-zero expiry time")
	}
	if result.TicketID != "reg_fixed123" {
		t.Fatalf("expected returned ticket id %q, got %q", "reg_fixed123", result.TicketID)
	}

	registration, err := store.Get(context.Background(), "reg_fixed123")
	if err != nil {
		t.Fatalf("expected saved registration: %v", err)
	}
	if registration.TicketID != "reg_fixed123" {
		t.Fatalf("expected stored ticket id %q, got %q", "reg_fixed123", registration.TicketID)
	}
	if registration.OTPCodeHash == "" {
		t.Fatal("expected otp hash to be stored")
	}
	if registration.OTPCodeHash == "123456" {
		t.Fatal("expected raw otp code not to be stored")
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

	if sender.phoneNumber != "+8562012345678" {
		t.Fatalf("expected sms phone number to be normalized, got %s", sender.phoneNumber)
	}

	if !strings.Contains(sender.message, "123456") {
		t.Fatalf("expected sms message to contain otp code, got %q", sender.message)
	}
}

func TestRegisterServiceRegisterDeletesCacheWhenSMSFails(t *testing.T) {
	repo := &fakeAccountRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{err: errors.New("sms unavailable")}
	service := NewRegisterService(repo, store, sender)
	service.otpGenerator = func(int) (string, error) { return "123456", nil }
	service.ticketGenerator = func() (string, error) { return "reg_fixed123", nil }

	_, err := service.Register(context.Background(), RegisterInput{
		PhoneNumber: "+8562012345678",
		Password:    "secretpass",
		ClientID:    "127.0.0.1",
	})
	if err == nil {
		t.Fatal("expected sms failure")
	}

	if store.deletedTicket != "reg_fixed123" {
		t.Fatalf("expected cache cleanup for ticket id, got %q", store.deletedTicket)
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

func TestRegisterServiceRegisterRejectsInvalidPhoneNumber(t *testing.T) {
	repo := &fakeAccountRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{}
	service := NewRegisterService(repo, store, sender)

	_, err := service.Register(context.Background(), RegisterInput{
		PhoneNumber: "+85620ABC5678",
		Password:    "secretpass",
	})
	if !errors.Is(err, ErrInvalidPhoneNumber) {
		t.Fatalf("expected ErrInvalidPhoneNumber, got %v", err)
	}
}

func TestRegisterServiceRegisterRateLimitsByPhoneNumber(t *testing.T) {
	repo := &fakeAccountRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{}
	service := NewRegisterService(repo, store, sender)
	service.otpGenerator = func(int) (string, error) { return "123456", nil }
	service.ticketGenerator = sequentialTicketGenerator("reg_a", "reg_b", "reg_c", "reg_d")
	service.usernameGenerator = sequentialUsernameGenerator("user_a", "user_b", "user_c", "user_d")

	for i := 0; i < maxPhoneRequests; i++ {
		_, err := service.Register(context.Background(), RegisterInput{
			PhoneNumber: "+8562012345678",
			Password:    "secretpass",
		})
		if err != nil {
			t.Fatalf("unexpected register error on attempt %d: %v", i+1, err)
		}
	}

	_, err := service.Register(context.Background(), RegisterInput{
		PhoneNumber: "+8562012345678",
		Password:    "secretpass",
	})
	if !errors.Is(err, ErrRegisterRateLimited) {
		t.Fatalf("expected ErrRegisterRateLimited, got %v", err)
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

	ticketID := "reg_fixed123"
	username := "user_fixed123"
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("secretpass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("generate password hash: %v", err)
	}

	store.values[ticketID] = &account.RegisterModel{
		TicketID:     ticketID,
		Username:     &username,
		PasswordHash: string(passwordHash),
		PhoneNumber:  "+8562012345678",
		OTPCodeHash:  hashRegisterOTP(ticketID, "123456"),
		OTPExpiresAt: now.Add(time.Minute),
		CreatedAt:    now.Add(-time.Minute),
	}

	accountModel, err := service.VerifyRegister(context.Background(), VerifyRegisterInput{
		TicketID: ticketID,
		OTPCode:  "123456",
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

	if store.deletedTicket != ticketID {
		t.Fatalf("expected pending registration to be deleted, got %q", store.deletedTicket)
	}
	if !containsString(store.deletedKeys, verifyAttemptKey(ticketID)) {
		t.Fatalf("expected verify counter cleanup for %q", ticketID)
	}
}

func TestRegisterServiceVerifyRegisterRejectsInvalidCode(t *testing.T) {
	repo := &fakeAccountRepository{}
	store := &fakeRegistrationStore{
		values: map[string]*account.RegisterModel{
			"reg_fixed123": {
				TicketID:     "reg_fixed123",
				PasswordHash: "hashed-password",
				PhoneNumber:  "+8562012345678",
				OTPCodeHash:  hashRegisterOTP("reg_fixed123", "123456"),
				OTPExpiresAt: time.Now().UTC().Add(time.Minute),
			},
		},
	}
	sender := &fakeOTPSender{}
	service := NewRegisterService(repo, store, sender)

	_, err := service.VerifyRegister(context.Background(), VerifyRegisterInput{
		TicketID: "reg_fixed123",
		OTPCode:  "654321",
	})
	if !errors.Is(err, account.ErrInvalidOTPCode) {
		t.Fatalf("expected invalid otp error, got %v", err)
	}

	if repo.created != nil {
		t.Fatal("did not expect account creation on invalid otp")
	}
}

func TestRegisterServiceVerifyRegisterRateLimitsInvalidOTPAttempts(t *testing.T) {
	repo := &fakeAccountRepository{}
	store := &fakeRegistrationStore{
		values: map[string]*account.RegisterModel{
			"reg_fixed123": {
				TicketID:     "reg_fixed123",
				PasswordHash: "hashed-password",
				PhoneNumber:  "+8562012345678",
				OTPCodeHash:  hashRegisterOTP("reg_fixed123", "123456"),
				OTPExpiresAt: time.Now().UTC().Add(time.Minute),
			},
		},
	}
	sender := &fakeOTPSender{}
	service := NewRegisterService(repo, store, sender)

	for i := 0; i < maxVerifyAttempts-1; i++ {
		_, err := service.VerifyRegister(context.Background(), VerifyRegisterInput{
			TicketID: "reg_fixed123",
			OTPCode:  "654321",
		})
		if !errors.Is(err, account.ErrInvalidOTPCode) {
			t.Fatalf("expected invalid otp on attempt %d, got %v", i+1, err)
		}
	}

	_, err := service.VerifyRegister(context.Background(), VerifyRegisterInput{
		TicketID: "reg_fixed123",
		OTPCode:  "654321",
	})
	if !errors.Is(err, ErrVerifyRateLimited) {
		t.Fatalf("expected ErrVerifyRateLimited, got %v", err)
	}

	if store.deletedTicket != "reg_fixed123" {
		t.Fatalf("expected ticket cleanup after attempt limit, got %q", store.deletedTicket)
	}
}

func TestRegisterServiceVerifyRegisterRejectsWhitespaceTicketID(t *testing.T) {
	repo := &fakeAccountRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{}
	service := NewRegisterService(repo, store, sender)

	_, err := service.VerifyRegister(context.Background(), VerifyRegisterInput{
		TicketID: "      ",
		OTPCode:  "123456",
	})
	if !errors.Is(err, ErrRegisterTicketRequired) {
		t.Fatalf("expected ErrRegisterTicketRequired, got %v", err)
	}
}

func TestRegisterServiceVerifyRegisterRejectsWhitespaceOTPCode(t *testing.T) {
	repo := &fakeAccountRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{}
	service := NewRegisterService(repo, store, sender)

	_, err := service.VerifyRegister(context.Background(), VerifyRegisterInput{
		TicketID: "reg_fixed123",
		OTPCode:  "      ",
	})
	if !errors.Is(err, ErrOTPCodeRequired) {
		t.Fatalf("expected ErrOTPCodeRequired, got %v", err)
	}
}

func TestRegisterServiceVerifyRegisterRejectsPendingRegistrationWithoutPasswordHash(t *testing.T) {
	repo := &fakeAccountRepository{}
	store := &fakeRegistrationStore{
		values: map[string]*account.RegisterModel{
			"reg_fixed123": {
				TicketID:     "reg_fixed123",
				Username:     stringPtr("user_fixed123"),
				PhoneNumber:  "+8562012345678",
				OTPCodeHash:  hashRegisterOTP("reg_fixed123", "123456"),
				OTPExpiresAt: time.Now().UTC().Add(time.Minute),
			},
		},
	}
	sender := &fakeOTPSender{}
	service := NewRegisterService(repo, store, sender)

	_, err := service.VerifyRegister(context.Background(), VerifyRegisterInput{
		TicketID: "reg_fixed123",
		OTPCode:  "123456",
	})
	if !errors.Is(err, ErrPendingRegistrationInvalid) {
		t.Fatalf("expected ErrPendingRegistrationInvalid, got %v", err)
	}

	if store.deletedTicket != "reg_fixed123" {
		t.Fatalf("expected stale pending registration to be deleted, got %q", store.deletedTicket)
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
			"reg_fixed123": {
				TicketID:     "reg_fixed123",
				Username:     &takenUsername,
				PasswordHash: "hashed-password",
				PhoneNumber:  "+8562012345678",
				OTPCodeHash:  hashRegisterOTP("reg_fixed123", "123456"),
				OTPExpiresAt: time.Now().UTC().Add(time.Minute),
			},
		},
	}
	sender := &fakeOTPSender{}
	service := NewRegisterService(repo, store, sender)
	service.usernameGenerator = func() (string, error) { return "user_fresh123", nil }

	accountModel, err := service.VerifyRegister(context.Background(), VerifyRegisterInput{
		TicketID: "reg_fixed123",
		OTPCode:  "123456",
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

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}

	return false
}

func sequentialTicketGenerator(values ...string) func() (string, error) {
	index := 0

	return func() (string, error) {
		if index >= len(values) {
			return "", errors.New("no more ticket values")
		}

		value := values[index]
		index++
		return value, nil
	}
}

func sequentialUsernameGenerator(values ...string) func() (string, error) {
	index := 0

	return func() (string, error) {
		if index >= len(values) {
			return "", errors.New("no more username values")
		}

		value := values[index]
		index++
		return value, nil
	}
}
