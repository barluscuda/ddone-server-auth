package register

import (
	"context"
	"ddone-server-auth/internal/application/dexbotkiller"
	"ddone-server-auth/internal/domain/user"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type fakeUserRepository struct {
	usersByPhone map[string]*user.User
	usersByUser  map[string]*user.User
	created      *user.User
}

func (r *fakeUserRepository) Create(_ context.Context, userModel *user.User) error {
	r.created = userModel
	if r.usersByPhone == nil {
		r.usersByPhone = map[string]*user.User{}
	}
	r.usersByPhone[userModel.PhoneNumber] = userModel

	if userModel.Username != nil {
		if r.usersByUser == nil {
			r.usersByUser = map[string]*user.User{}
		}
		r.usersByUser[*userModel.Username] = userModel
	}

	return nil
}

func (r *fakeUserRepository) GetByID(_ context.Context, _ string) (*user.User, error) {
	return nil, user.ErrUserNotFound
}

func (r *fakeUserRepository) GetByPhoneNumber(_ context.Context, phoneNumber string) (*user.User, error) {
	if userModel, ok := r.usersByPhone[phoneNumber]; ok {
		return userModel, nil
	}

	return nil, user.ErrUserNotFound
}

func (r *fakeUserRepository) GetByUsername(_ context.Context, username string) (*user.User, error) {
	if userModel, ok := r.usersByUser[username]; ok {
		return userModel, nil
	}

	return nil, user.ErrUserNotFound
}

func (r *fakeUserRepository) Update(_ context.Context, _ *user.User) error {
	return nil
}

func (r *fakeUserRepository) Delete(_ context.Context, _ string) error {
	return nil
}

type fakeRegistrationStore struct {
	values        map[string]*user.PendingRegistration
	deletedTicket string
	counters      map[string]int64
	counterTTLs   map[string]time.Duration
	deletedKeys   []string
	saveErr       error
	deleteErr     error
}

func (s *fakeRegistrationStore) Save(_ context.Context, registration *user.PendingRegistration, _ time.Duration) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	if s.values == nil {
		s.values = map[string]*user.PendingRegistration{}
	}
	s.values[registration.TicketID] = registration
	return nil
}

func (s *fakeRegistrationStore) Get(_ context.Context, ticketID string) (*user.PendingRegistration, error) {
	if registration, ok := s.values[ticketID]; ok {
		return registration, nil
	}

	return nil, user.ErrPendingRegistrationNotFound
}

func (s *fakeRegistrationStore) Delete(_ context.Context, ticketID string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deletedTicket = ticketID
	delete(s.values, ticketID)
	return nil
}

func (s *fakeRegistrationStore) IncrementCounter(_ context.Context, key string, ttl time.Duration) (int64, error) {
	if s.counters == nil {
		s.counters = map[string]int64{}
	}
	if s.counterTTLs == nil {
		s.counterTTLs = map[string]time.Duration{}
	}

	s.counters[key]++
	s.counterTTLs[key] = ttl
	return s.counters[key], nil
}

func (s *fakeRegistrationStore) DeleteCounter(_ context.Context, key string) error {
	s.deletedKeys = append(s.deletedKeys, key)
	if s.counters != nil {
		delete(s.counters, key)
	}
	if s.counterTTLs != nil {
		delete(s.counterTTLs, key)
	}
	return nil
}

type fakeOTPSender struct {
	telCode     string
	phoneNumber string
	message     string
	err         error
	called      bool
}

func (s *fakeOTPSender) SendOTP(_ context.Context, telCode string, number string, msg string) error {
	s.called = true
	s.telCode = telCode
	s.phoneNumber = number
	s.message = msg
	return s.err
}

type fakeChallengeVerifier struct {
	token    string
	remoteIP string
	err      error
	called   bool
}

func (v *fakeChallengeVerifier) Verify(_ context.Context, verification dexbotkiller.ChallengeVerification) error {
	v.called = true
	v.token = verification.Token
	v.remoteIP = verification.RemoteIP
	return v.err
}

func TestRegisterServiceRegisterSavesRegistrationAndSendsSMS(t *testing.T) {
	repo := &fakeUserRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{}
	service := NewService(repo, store, sender)
	service.otpGenerator = func(int) (string, error) { return "123456", nil }
	service.ticketGenerator = func() (string, error) { return "reg_fixed123", nil }
	service.usernameGenerator = func() (string, error) { return "user_fixed123", nil }

	result, err := service.Register(context.Background(), RegisterInput{
		PhoneNumber: "  856 20 1234 5678  ",
		Password:    "secretpass",
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
	if result.RemainingResendCount != defaultOTPPolicy.MaxResends {
		t.Fatalf("expected remaining resend count %d, got %d", defaultOTPPolicy.MaxResends, result.RemainingResendCount)
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

	if sender.telCode != "856" {
		t.Fatalf("expected sms tel code %q, got %q", "856", sender.telCode)
	}
	if sender.phoneNumber != "2012345678" {
		t.Fatalf("expected sms phone number %q, got %q", "2012345678", sender.phoneNumber)
	}

	if !strings.Contains(sender.message, "123456") {
		t.Fatalf("expected sms message to contain otp code, got %q", sender.message)
	}
}

func TestRegisterServiceReturnsCloudflareChallengeBeforeSendingSMS(t *testing.T) {
	repo := &fakeUserRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{}
	verifier := &fakeChallengeVerifier{}
	service := newChallengeRegisterService(t, repo, store, sender, verifier)

	_, err := service.Register(clientContext(), RegisterInput{
		PhoneNumber: "8562012345678",
		Password:    "secretpass",
	})
	if !errors.Is(err, ErrChallengeRequired) {
		t.Fatalf("expected challenge required, got %v", err)
	}
	challenge, ok := ChallengeFromError(err)
	if !ok {
		t.Fatal("expected challenge metadata")
	}
	if challenge.Provider != string(dexbotkiller.ChallengeProviderCloudflareTurnstile) {
		t.Fatalf("expected cloudflare turnstile provider, got %q", challenge.Provider)
	}
	if challenge.SiteKey != "site-key" {
		t.Fatalf("expected site key, got %q", challenge.SiteKey)
	}
	if sender.called {
		t.Fatal("expected sms not to be sent until challenge is solved")
	}
	if verifier.called {
		t.Fatal("expected verifier not to be called without challenge token")
	}
}

func TestRegisterServiceVerifiesCloudflareChallengeBeforeSendingSMS(t *testing.T) {
	repo := &fakeUserRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{}
	verifier := &fakeChallengeVerifier{}
	service := newChallengeRegisterService(t, repo, store, sender, verifier)
	service.otpGenerator = func(int) (string, error) { return "123456", nil }
	service.ticketGenerator = func() (string, error) { return "reg_fixed123", nil }
	service.usernameGenerator = func() (string, error) { return "user_fixed123", nil }

	_, err := service.Register(clientContext(), RegisterInput{
		PhoneNumber:    "8562012345678",
		Password:       "secretpass",
		ChallengeToken: "turnstile-token",
	})
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if !verifier.called {
		t.Fatal("expected challenge verifier to be called")
	}
	if verifier.token != "turnstile-token" {
		t.Fatalf("expected verifier token %q, got %q", "turnstile-token", verifier.token)
	}
	if verifier.remoteIP != "192.0.2.10" {
		t.Fatalf("expected verifier remote ip %q, got %q", "192.0.2.10", verifier.remoteIP)
	}
	if !sender.called {
		t.Fatal("expected sms to be sent after challenge verification")
	}
}

func newChallengeRegisterService(
	t *testing.T,
	repo *fakeUserRepository,
	store *fakeRegistrationStore,
	sender *fakeOTPSender,
	verifier *fakeChallengeVerifier,
) *Service {
	t.Helper()

	hasher, err := dexbotkiller.NewHasher("test-pepper")
	if err != nil {
		t.Fatalf("new hasher: %v", err)
	}
	engine := dexbotkiller.NewEngine(dexbotkiller.NoopStore{}, dexbotkiller.Policy{
		Mode: dexbotkiller.ModeChallenge,
		Thresholds: dexbotkiller.Thresholds{
			DelayScore:     1,
			ChallengeScore: 1,
			BlockScore:     2,
		},
		Challenge: dexbotkiller.Challenge{
			Provider: dexbotkiller.ChallengeProviderCloudflareTurnstile,
			SiteKey:  "site-key",
		},
	}, hasher)

	return NewServiceWithSettings(repo, store, sender, Settings{
		DexBotKiller:      engine,
		ChallengeVerifier: verifier,
	})
}

func clientContext() context.Context {
	return dexbotkiller.ContextWithClientContext(context.Background(), dexbotkiller.ClientContext{
		IP: "192.0.2.10",
	})
}

func TestNormalizePhoneNumber(t *testing.T) {
	testCases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "local with leading zero", input: "02012345678", want: "+8562012345678"},
		{name: "local with spaces", input: "020 1234 5678", want: "+8562012345678"},
		{name: "country code with plus", input: "+8562012345678", want: "+8562012345678"},
		{name: "country code without plus", input: "8562012345678", want: "+8562012345678"},
		{name: "country code with international prefix", input: "008562012345678", want: "+8562012345678"},
		{name: "country code with extra zero", input: "+85602012345678", want: "+8562012345678"},
		{name: "already normalized", input: "+8562012345678", want: "+8562012345678"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizePhoneNumber(tc.input)
			if err != nil {
				t.Fatalf("normalizePhoneNumber returned error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestNormalizePhoneNumberRejectsInvalidFormat(t *testing.T) {
	testCases := []string{
		"201234567",
		"20123456789",
		"0212345678",
		"+85630ABC5678",
	}

	for _, input := range testCases {
		t.Run(input, func(t *testing.T) {
			_, err := normalizePhoneNumber(input)
			if !errors.Is(err, ErrInvalidPhoneNumber) {
				t.Fatalf("expected ErrInvalidPhoneNumber, got %v", err)
			}
		})
	}
}

func TestRegisterServiceRegisterDoesNotSaveRegistrationWhenSMSFails(t *testing.T) {
	repo := &fakeUserRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{err: errors.New("sms unavailable")}
	service := NewService(repo, store, sender)
	service.otpGenerator = func(int) (string, error) { return "123456", nil }
	service.ticketGenerator = func() (string, error) { return "reg_fixed123", nil }

	_, err := service.Register(context.Background(), RegisterInput{
		PhoneNumber: "+8562012345678",
		Password:    "secretpass",
	})
	if err == nil {
		t.Fatal("expected sms failure")
	}
	if _, getErr := store.Get(context.Background(), "reg_fixed123"); !errors.Is(getErr, user.ErrPendingRegistrationNotFound) {
		t.Fatalf("expected saved registration to be cleaned up after sms failure, got %v", getErr)
	}
	if store.deletedTicket != "reg_fixed123" {
		t.Fatalf("expected cleanup delete for failed sms send, got %q", store.deletedTicket)
	}
}

func TestRegisterServiceRegisterDoesNotSendSMSWhenSaveFails(t *testing.T) {
	repo := &fakeUserRepository{}
	store := &fakeRegistrationStore{saveErr: errors.New("redis unavailable")}
	sender := &fakeOTPSender{}
	service := NewService(repo, store, sender)
	service.otpGenerator = func(int) (string, error) { return "123456", nil }
	service.ticketGenerator = func() (string, error) { return "reg_fixed123", nil }

	_, err := service.Register(context.Background(), RegisterInput{
		PhoneNumber: "+8562012345678",
		Password:    "secretpass",
	})
	if err == nil {
		t.Fatal("expected save failure")
	}
	if sender.called {
		t.Fatal("expected sms sender not to be called when save fails")
	}
}

func TestRegisterServiceRegisterRejectsWhitespacePhoneNumber(t *testing.T) {
	repo := &fakeUserRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{}
	service := NewService(repo, store, sender)

	_, err := service.Register(context.Background(), RegisterInput{
		PhoneNumber: "        ",
		Password:    "secretpass",
	})
	if !errors.Is(err, ErrPhoneNumberRequired) {
		t.Fatalf("expected ErrPhoneNumberRequired, got %v", err)
	}
}

func TestRegisterServiceRegisterRejectsWhitespacePassword(t *testing.T) {
	repo := &fakeUserRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{}
	service := NewService(repo, store, sender)

	_, err := service.Register(context.Background(), RegisterInput{
		PhoneNumber: "+8562012345678",
		Password:    "        ",
	})
	if !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("expected ErrPasswordRequired, got %v", err)
	}
}

func TestRegisterServiceRegisterRejectsInvalidPhoneNumber(t *testing.T) {
	repo := &fakeUserRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{}
	service := NewService(repo, store, sender)

	_, err := service.Register(context.Background(), RegisterInput{
		PhoneNumber: "+85620ABC5678",
		Password:    "secretpass",
	})
	if !errors.Is(err, ErrInvalidPhoneNumber) {
		t.Fatalf("expected ErrInvalidPhoneNumber, got %v", err)
	}
}

func TestRegisterServiceRegisterRateLimitsByPhoneNumber(t *testing.T) {
	repo := &fakeUserRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{}
	service := NewService(repo, store, sender)
	service.otpGenerator = func(int) (string, error) { return "123456", nil }
	service.ticketGenerator = sequentialTicketGenerator("reg_a", "reg_b")
	service.usernameGenerator = sequentialUsernameGenerator("user_a", "user_b")

	_, err := service.Register(context.Background(), RegisterInput{
		PhoneNumber: "+8562012345678",
		Password:    "secretpass",
	})
	if err != nil {
		t.Fatalf("unexpected register error on first attempt: %v", err)
	}

	_, err = service.Register(context.Background(), RegisterInput{
		PhoneNumber: "+8562012345678",
		Password:    "secretpass",
	})
	if !errors.Is(err, ErrRegisterRateLimited) {
		t.Fatalf("expected ErrRegisterRateLimited, got %v", err)
	}
}

func TestRegisterServiceRegisterRateLimitsBySystemDefault(t *testing.T) {
	repo := &fakeUserRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{}
	policy := defaultOTPPolicy
	policy.MaxPhoneRequests = 10
	service := NewServiceWithSettings(repo, store, sender, Settings{OTPPolicy: policy})
	service.otpGenerator = func(int) (string, error) { return "123456", nil }
	service.ticketGenerator = numberedTicketGenerator()
	service.usernameGenerator = numberedUsernameGenerator()

	for i := 0; i < defaultSystemRateLimitPolicy.MaxRequests; i++ {
		_, err := service.Register(context.Background(), RegisterInput{
			PhoneNumber: fmt.Sprintf("+85620%08d", i+1),
			Password:    "secretpass",
		})
		if err != nil {
			t.Fatalf("unexpected register error on request %d: %v", i+1, err)
		}
	}

	_, err := service.Register(context.Background(), RegisterInput{
		PhoneNumber: "+8562000009999",
		Password:    "secretpass",
	})
	if !errors.Is(err, ErrRegisterRateLimited) {
		t.Fatalf("expected ErrRegisterRateLimited after default system request limit, got %v", err)
	}
}

func TestRegisterServiceRegisterUsesCustomSystemRateLimit(t *testing.T) {
	repo := &fakeUserRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{}
	policy := defaultOTPPolicy
	policy.MaxPhoneRequests = 10
	service := NewServiceWithSettings(repo, store, sender, Settings{
		OTPPolicy: policy,
		SystemRateLimitPolicy: &SystemRateLimitPolicy{
			Window:      2 * time.Minute,
			MaxRequests: 1,
		},
	})
	service.otpGenerator = func(int) (string, error) { return "123456", nil }
	service.ticketGenerator = sequentialTicketGenerator("reg_a", "reg_b")
	service.usernameGenerator = sequentialUsernameGenerator("user_a", "user_b")

	_, err := service.Register(context.Background(), RegisterInput{
		PhoneNumber: "+8562012345678",
		Password:    "secretpass",
	})
	if err != nil {
		t.Fatalf("unexpected register error on first request: %v", err)
	}
	if got, want := store.counterTTLs[registerSystemRateKey()], 2*time.Minute; got != want {
		t.Fatalf("expected custom system rate limit window %v, got %v", want, got)
	}

	_, err = service.Register(context.Background(), RegisterInput{
		PhoneNumber: "+8562098765432",
		Password:    "secretpass",
	})
	if !errors.Is(err, ErrRegisterRateLimited) {
		t.Fatalf("expected ErrRegisterRateLimited after custom system request limit, got %v", err)
	}
}

func TestRegisterServiceResendRegisterOTPRefreshesCodeAndExpiry(t *testing.T) {
	repo := &fakeUserRepository{}
	store := &fakeRegistrationStore{
		values: map[string]*user.PendingRegistration{
			"reg_fixed123": {
				TicketID:      "reg_fixed123",
				Username:      stringPtr("user_fixed123"),
				PasswordHash:  "hashed-password",
				PhoneNumber:   "+8562012345678",
				OTPCodeHash:   hashRegisterOTP("reg_fixed123", "123456"),
				OTPExpiresAt:  time.Date(2026, 5, 21, 10, 5, 0, 0, time.UTC),
				LastOTPSentAt: time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC),
				CreatedAt:     time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC),
			},
		},
	}
	sender := &fakeOTPSender{}
	service := NewService(repo, store, sender)
	now := time.Date(2026, 5, 21, 10, 1, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	service.otpGenerator = func(int) (string, error) { return "654321", nil }

	result, err := service.ResendRegisterOTP(context.Background(), ResendRegisterOTPInput{
		TicketID: "reg_fixed123",
	})
	if err != nil {
		t.Fatalf("ResendRegisterOTP returned error: %v", err)
	}

	if result.TicketID != "reg_fixed123" {
		t.Fatalf("expected ticket id %q, got %q", "reg_fixed123", result.TicketID)
	}
	if result.RemainingResendCount != defaultOTPPolicy.MaxResends-1 {
		t.Fatalf("expected remaining resend count %d, got %d", defaultOTPPolicy.MaxResends-1, result.RemainingResendCount)
	}

	if got, want := result.ExpiresAt, now.Add(defaultOTPPolicy.TTL); !got.Equal(want) {
		t.Fatalf("expected expiry %v, got %v", want, got)
	}

	registration, err := store.Get(context.Background(), "reg_fixed123")
	if err != nil {
		t.Fatalf("expected stored registration: %v", err)
	}

	if registration.OTPCodeHash != hashRegisterOTP("reg_fixed123", "654321") {
		t.Fatalf("expected refreshed otp hash, got %q", registration.OTPCodeHash)
	}

	if !registration.OTPExpiresAt.Equal(now.Add(defaultOTPPolicy.TTL)) {
		t.Fatalf("expected refreshed otp expiry, got %v", registration.OTPExpiresAt)
	}
	if registration.ResendCount != 1 {
		t.Fatalf("expected resend count %d, got %d", 1, registration.ResendCount)
	}
	if !registration.LastOTPSentAt.Equal(now) {
		t.Fatalf("expected last otp sent at %v, got %v", now, registration.LastOTPSentAt)
	}

	if sender.telCode != "856" {
		t.Fatalf("expected resend sms tel code %q, got %q", "856", sender.telCode)
	}
	if sender.phoneNumber != "2012345678" {
		t.Fatalf("expected resend sms phone number %q, got %q", "2012345678", sender.phoneNumber)
	}

	if !strings.Contains(sender.message, "654321") {
		t.Fatalf("expected resend sms message to contain otp code, got %q", sender.message)
	}
}

func TestRegisterServiceResendRegisterOTPRestoresPreviousCodeWhenSMSFails(t *testing.T) {
	repo := &fakeUserRepository{}
	store := &fakeRegistrationStore{
		values: map[string]*user.PendingRegistration{
			"reg_fixed123": {
				TicketID:      "reg_fixed123",
				Username:      stringPtr("user_fixed123"),
				PasswordHash:  "hashed-password",
				PhoneNumber:   "+8562012345678",
				OTPCodeHash:   hashRegisterOTP("reg_fixed123", "123456"),
				OTPExpiresAt:  time.Date(2026, 5, 21, 10, 5, 0, 0, time.UTC),
				LastOTPSentAt: time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC),
				CreatedAt:     time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC),
			},
		},
	}
	sender := &fakeOTPSender{err: errors.New("sms unavailable")}
	service := NewService(repo, store, sender)
	now := time.Date(2026, 5, 21, 10, 1, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	service.otpGenerator = func(int) (string, error) { return "654321", nil }

	_, err := service.ResendRegisterOTP(context.Background(), ResendRegisterOTPInput{
		TicketID: "reg_fixed123",
	})
	if err == nil {
		t.Fatal("expected sms failure")
	}

	registration, getErr := store.Get(context.Background(), "reg_fixed123")
	if getErr != nil {
		t.Fatalf("expected registration to be restored: %v", getErr)
	}

	if registration.OTPCodeHash != hashRegisterOTP("reg_fixed123", "123456") {
		t.Fatalf("expected previous otp hash to be restored, got %q", registration.OTPCodeHash)
	}

	if !registration.OTPExpiresAt.Equal(time.Date(2026, 5, 21, 10, 5, 0, 0, time.UTC)) {
		t.Fatalf("expected previous expiry to be restored, got %v", registration.OTPExpiresAt)
	}
	if registration.ResendCount != 0 {
		t.Fatalf("expected resend count to be restored, got %d", registration.ResendCount)
	}
	if !registration.LastOTPSentAt.Equal(time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("expected last otp sent at to be restored, got %v", registration.LastOTPSentAt)
	}
}

func TestRegisterServiceResendRegisterOTPEnforcesCooldown(t *testing.T) {
	repo := &fakeUserRepository{}
	now := time.Date(2026, 5, 21, 10, 0, 30, 0, time.UTC)
	store := &fakeRegistrationStore{
		values: map[string]*user.PendingRegistration{
			"reg_fixed123": {
				TicketID:      "reg_fixed123",
				Username:      stringPtr("user_fixed123"),
				PasswordHash:  "hashed-password",
				PhoneNumber:   "+8562012345678",
				OTPCodeHash:   hashRegisterOTP("reg_fixed123", "123456"),
				OTPExpiresAt:  now.Add(4 * time.Minute),
				LastOTPSentAt: now.Add(-30 * time.Second),
				CreatedAt:     now.Add(-time.Minute),
			},
		},
	}
	service := NewService(repo, store, &fakeOTPSender{})
	service.now = func() time.Time { return now }

	_, err := service.ResendRegisterOTP(context.Background(), ResendRegisterOTPInput{
		TicketID: "reg_fixed123",
	})
	if !errors.Is(err, ErrResendCooldownActive) {
		t.Fatalf("expected ErrResendCooldownActive, got %v", err)
	}
}

func TestRegisterServiceResendRegisterOTPRateLimitsAfterThreeResends(t *testing.T) {
	repo := &fakeUserRepository{}
	now := time.Date(2026, 5, 21, 10, 5, 0, 0, time.UTC)
	store := &fakeRegistrationStore{
		values: map[string]*user.PendingRegistration{
			"reg_fixed123": {
				TicketID:      "reg_fixed123",
				Username:      stringPtr("user_fixed123"),
				PasswordHash:  "hashed-password",
				PhoneNumber:   "+8562012345678",
				OTPCodeHash:   hashRegisterOTP("reg_fixed123", "123456"),
				OTPExpiresAt:  now.Add(time.Minute),
				ResendCount:   3,
				LastOTPSentAt: now.Add(-2 * time.Minute),
				CreatedAt:     now.Add(-5 * time.Minute),
			},
		},
	}
	service := NewService(repo, store, &fakeOTPSender{})
	service.now = func() time.Time { return now }

	_, err := service.ResendRegisterOTP(context.Background(), ResendRegisterOTPInput{
		TicketID: "reg_fixed123",
	})
	if !errors.Is(err, ErrResendRateLimited) {
		t.Fatalf("expected ErrResendRateLimited, got %v", err)
	}
}

func TestRegisterServiceVerifyRegisterCreatesUserAndDeletesCache(t *testing.T) {
	repo := &fakeUserRepository{}
	store := &fakeRegistrationStore{
		values: map[string]*user.PendingRegistration{},
	}
	sender := &fakeOTPSender{}
	service := NewService(repo, store, sender)

	now := time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }

	ticketID := "reg_fixed123"
	username := "user_fixed123"
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("secretpass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("generate password hash: %v", err)
	}

	store.values[ticketID] = &user.PendingRegistration{
		TicketID:     ticketID,
		Username:     &username,
		PasswordHash: string(passwordHash),
		PhoneNumber:  "+8562012345678",
		OTPCodeHash:  hashRegisterOTP(ticketID, "123456"),
		OTPExpiresAt: now.Add(time.Minute),
		CreatedAt:    now.Add(-time.Minute),
	}

	userModel, err := service.VerifyRegister(context.Background(), VerifyRegisterInput{
		TicketID: ticketID,
		OTPCode:  "123456",
	})
	if err != nil {
		t.Fatalf("VerifyRegister returned error: %v", err)
	}

	if userModel.PhoneVerifiedAt != now {
		t.Fatalf("expected verified at %v, got %v", now, userModel.PhoneVerifiedAt)
	}

	if repo.created == nil {
		t.Fatal("expected user to be created")
	}

	if repo.created.Username == nil || *repo.created.Username != username {
		t.Fatalf("expected generated username to be carried to user, got %#v", repo.created.Username)
	}

	if repo.created.PasswordHash != string(passwordHash) {
		t.Fatal("expected password hash to be persisted on user creation")
	}

	if store.deletedTicket != ticketID {
		t.Fatalf("expected pending registration to be deleted, got %q", store.deletedTicket)
	}
	if !containsString(store.deletedKeys, verifyAttemptKey(ticketID)) {
		t.Fatalf("expected verify counter cleanup for %q", ticketID)
	}
}

func TestRegisterServiceVerifyRegisterRejectsInvalidCode(t *testing.T) {
	repo := &fakeUserRepository{}
	store := &fakeRegistrationStore{
		values: map[string]*user.PendingRegistration{
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
	service := NewService(repo, store, sender)

	_, err := service.VerifyRegister(context.Background(), VerifyRegisterInput{
		TicketID: "reg_fixed123",
		OTPCode:  "654321",
	})
	if !errors.Is(err, user.ErrInvalidOTPCode) {
		t.Fatalf("expected invalid otp error, got %v", err)
	}

	if repo.created != nil {
		t.Fatal("did not expect user creation on invalid otp")
	}
}

func TestRegisterServiceVerifyRegisterRateLimitsInvalidOTPAttempts(t *testing.T) {
	repo := &fakeUserRepository{}
	store := &fakeRegistrationStore{
		values: map[string]*user.PendingRegistration{
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
	service := NewService(repo, store, sender)

	for i := 0; i < defaultOTPPolicy.MaxVerifyAttempts-1; i++ {
		_, err := service.VerifyRegister(context.Background(), VerifyRegisterInput{
			TicketID: "reg_fixed123",
			OTPCode:  "654321",
		})
		if !errors.Is(err, user.ErrInvalidOTPCode) {
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
	repo := &fakeUserRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{}
	service := NewService(repo, store, sender)

	_, err := service.VerifyRegister(context.Background(), VerifyRegisterInput{
		TicketID: "      ",
		OTPCode:  "123456",
	})
	if !errors.Is(err, ErrRegisterTicketRequired) {
		t.Fatalf("expected ErrRegisterTicketRequired, got %v", err)
	}
}

func TestRegisterServiceResendRegisterOTPRejectsWhitespaceTicketID(t *testing.T) {
	repo := &fakeUserRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{}
	service := NewService(repo, store, sender)

	_, err := service.ResendRegisterOTP(context.Background(), ResendRegisterOTPInput{
		TicketID: "      ",
	})
	if !errors.Is(err, ErrRegisterTicketRequired) {
		t.Fatalf("expected ErrRegisterTicketRequired, got %v", err)
	}
}

func TestRegisterServiceVerifyRegisterRejectsWhitespaceOTPCode(t *testing.T) {
	repo := &fakeUserRepository{}
	store := &fakeRegistrationStore{}
	sender := &fakeOTPSender{}
	service := NewService(repo, store, sender)

	_, err := service.VerifyRegister(context.Background(), VerifyRegisterInput{
		TicketID: "reg_fixed123",
		OTPCode:  "      ",
	})
	if !errors.Is(err, ErrOTPCodeRequired) {
		t.Fatalf("expected ErrOTPCodeRequired, got %v", err)
	}
}

func TestRegisterServiceVerifyRegisterRejectsPendingRegistrationWithoutPasswordHash(t *testing.T) {
	repo := &fakeUserRepository{}
	store := &fakeRegistrationStore{
		values: map[string]*user.PendingRegistration{
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
	service := NewService(repo, store, sender)

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
	repo := &fakeUserRepository{
		usersByUser: map[string]*user.User{
			takenUsername: {Username: &takenUsername},
		},
	}
	store := &fakeRegistrationStore{
		values: map[string]*user.PendingRegistration{
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
	service := NewService(repo, store, sender)
	service.usernameGenerator = func() (string, error) { return "user_fresh123", nil }

	userModel, err := service.VerifyRegister(context.Background(), VerifyRegisterInput{
		TicketID: "reg_fixed123",
		OTPCode:  "123456",
	})
	if err != nil {
		t.Fatalf("VerifyRegister returned error: %v", err)
	}

	if userModel.Username == nil || *userModel.Username != "user_fresh123" {
		t.Fatalf("expected username to be regenerated, got %#v", userModel.Username)
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

func numberedTicketGenerator() func() (string, error) {
	index := 0

	return func() (string, error) {
		index++
		return fmt.Sprintf("reg_%d", index), nil
	}
}

func numberedUsernameGenerator() func() (string, error) {
	index := 0

	return func() (string, error) {
		index++
		return fmt.Sprintf("user_%d", index), nil
	}
}
