package register

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"ddone-server-auth/internal/application/otp"
	"ddone-server-auth/internal/domain/user"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	registerOTPLength    = 6
	registerTicketPrefix = "reg_"
	registerTicketBytes  = 12
	usernamePrefix       = "user_"
	usernameBytes        = 6
	usernameAttempts     = 5
)

var ErrPhoneNumberRequired = errors.New("phone number is required")
var ErrInvalidPhoneNumber = user.ErrInvalidPhoneNumber
var ErrRegisterTicketRequired = errors.New("ticket id is required")
var ErrOTPCodeRequired = errors.New("otp code is required")
var ErrPasswordRequired = errors.New("password is required")
var ErrPendingRegistrationInvalid = errors.New("pending registration is invalid, request otp again")
var ErrRegisterRateLimited = errors.New("too many registration requests, try again later")
var ErrResendRateLimited = errors.New("too many otp resend requests, request a new registration")
var ErrResendCooldownActive = errors.New("otp resend cooldown is active")
var ErrVerifyRateLimited = errors.New("too many invalid otp attempts, request a new code")

var defaultOTPPolicy = otp.Policy{
	TTL:                 5 * time.Minute,
	PhoneWindow:         5 * time.Minute,
	ResendCooldown:      60 * time.Second,
	VerifyAttemptWindow: 5 * time.Minute,
	MaxPhoneRequests:    1,
	MaxResends:          3,
	MaxVerifyAttempts:   5,
}

var defaultSystemRateLimitPolicy = SystemRateLimitPolicy{
	Window:      10 * time.Minute,
	MaxRequests: 30,
}

type Service struct {
	users                 UserStore
	store                 RegistrationStore
	sender                OTPSender
	otpPolicy             otp.Policy
	systemRateLimitPolicy SystemRateLimitPolicy
	now                   func() time.Time
	otpGenerator          func(int) (string, error)
	ticketGenerator       func() (string, error)
	usernameGenerator     func() (string, error)
	passwordHasher        func(string) (string, error)
}

func NewService(
	users UserStore,
	store RegistrationStore,
	sender OTPSender,
) *Service {
	return NewServiceWithSettings(users, store, sender, Settings{})
}

func NewServiceWithSettings(
	users UserStore,
	store RegistrationStore,
	sender OTPSender,
	settings Settings,
) *Service {
	systemRateLimitPolicy := defaultSystemRateLimitPolicy
	if settings.SystemRateLimitPolicy != nil {
		systemRateLimitPolicy = systemRateLimitPolicyWithDefaults(*settings.SystemRateLimitPolicy)
	}

	return &Service{
		users:                 users,
		store:                 store,
		sender:                sender,
		otpPolicy:             settings.OTPPolicy.WithDefaults(defaultOTPPolicy),
		systemRateLimitPolicy: systemRateLimitPolicy,
		now:                   func() time.Time { return time.Now().UTC() },
		otpGenerator:          GenerateOTP,
		ticketGenerator:       generateRegisterTicket,
		usernameGenerator:     generateUsername,
		passwordHasher:        hashPassword,
	}
}

func (s *Service) Register(
	ctx context.Context,
	input RegisterInput,
) (*RegisterResult, error) {
	phoneNumber, err := parsePhoneNumber(input.PhoneNumber)
	if err != nil {
		return nil, err
	}
	globalPhoneNumber := phoneNumber.Global()
	if globalPhoneNumber == "" {
		return nil, ErrPhoneNumberRequired
	}
	if strings.TrimSpace(input.Password) == "" {
		return nil, ErrPasswordRequired
	}
	if err := s.enforceRegisterRateLimits(ctx, globalPhoneNumber); err != nil {
		return nil, err
	}

	if _, err := s.users.GetByPhoneNumber(ctx, globalPhoneNumber); err == nil {
		return nil, user.ErrPhoneNumberAlreadyRegistered
	} else if !errors.Is(err, user.ErrUserNotFound) {
		return nil, err
	}

	username, err := s.generateUniqueUsername(ctx)
	if err != nil {
		return nil, err
	}

	passwordHash, err := s.passwordHasher(input.Password)
	if err != nil {
		return nil, err
	}

	otpCode, err := s.otpGenerator(registerOTPLength)
	if err != nil {
		return nil, err
	}
	ticketID, err := s.ticketGenerator()
	if err != nil {
		return nil, err
	}
	otpCodeHash := hashRegisterOTP(ticketID, otpCode)

	now := s.now()
	pendingRegistration := &user.PendingRegistration{
		TicketID:      ticketID,
		Username:      username,
		PasswordHash:  passwordHash,
		PhoneNumber:   globalPhoneNumber,
		OTPCodeHash:   otpCodeHash,
		OTPExpiresAt:  now.Add(s.otpPolicy.TTL),
		ResendCount:   0,
		LastOTPSentAt: now,
		CreatedAt:     now,
	}
	if err := s.store.Save(ctx, pendingRegistration, s.otpPolicy.TTL); err != nil {
		return nil, err
	}

	message := RegisterOTPMessage(otpCode, s.otpPolicy.TTL)
	if err := s.sender.SendOTP(ctx, phoneNumber.TelCode, phoneNumber.Number, message); err != nil {
		_ = s.store.Delete(ctx, ticketID)
		return nil, err
	}

	return &RegisterResult{
		TicketID:             ticketID,
		ExpiresAt:            pendingRegistration.OTPExpiresAt,
		ResendCooldown:       s.otpPolicy.ResendCooldown,
		RemainingResendCount: s.otpPolicy.MaxResends,
	}, nil
}

func (s *Service) VerifyRegister(
	ctx context.Context,
	input VerifyRegisterInput,
) (*user.User, error) {
	ticketID := strings.TrimSpace(input.TicketID)
	otpCode := strings.TrimSpace(input.OTPCode)
	if ticketID == "" {
		return nil, ErrRegisterTicketRequired
	}
	if otpCode == "" {
		return nil, ErrOTPCodeRequired
	}

	pendingRegistration, err := s.store.Get(ctx, ticketID)
	if err != nil {
		return nil, err
	}
	phoneNumber := pendingRegistration.PhoneNumber

	now := s.now()
	if now.After(pendingRegistration.OTPExpiresAt) {
		_ = s.store.Delete(ctx, ticketID)
		_ = s.store.DeleteCounter(ctx, verifyAttemptKey(ticketID))
		return nil, user.ErrOTPExpired
	}
	if pendingRegistration.PasswordHash == "" || phoneNumber == "" || pendingRegistration.OTPCodeHash == "" {
		_ = s.store.Delete(ctx, ticketID)
		_ = s.store.DeleteCounter(ctx, verifyAttemptKey(ticketID))
		return nil, ErrPendingRegistrationInvalid
	}

	if !matchRegisterOTP(pendingRegistration.OTPCodeHash, ticketID, otpCode) {
		attempts, err := s.store.IncrementCounter(ctx, verifyAttemptKey(ticketID), s.otpPolicy.VerifyAttemptWindow)
		if err != nil {
			return nil, err
		}
		if attempts >= int64(s.otpPolicy.MaxVerifyAttempts) {
			_ = s.store.Delete(ctx, ticketID)
			_ = s.store.DeleteCounter(ctx, verifyAttemptKey(ticketID))
			return nil, ErrVerifyRateLimited
		}

		return nil, user.ErrInvalidOTPCode
	}

	if _, err := s.users.GetByPhoneNumber(ctx, phoneNumber); err == nil {
		_ = s.store.Delete(ctx, ticketID)
		_ = s.store.DeleteCounter(ctx, verifyAttemptKey(ticketID))
		return nil, user.ErrPhoneNumberAlreadyRegistered
	} else if !errors.Is(err, user.ErrUserNotFound) {
		return nil, err
	}

	username := pendingRegistration.Username
	if username == nil {
		username, err = s.generateUniqueUsername(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		if _, err := s.users.GetByUsername(ctx, *username); err == nil {
			username, err = s.generateUniqueUsername(ctx)
			if err != nil {
				return nil, err
			}
		} else if !errors.Is(err, user.ErrUserNotFound) {
			return nil, err
		}
	}

	userModel := &user.User{
		Username:          username,
		PasswordHash:      pendingRegistration.PasswordHash,
		PhoneNumber:       phoneNumber,
		PhoneVerifiedAt:   now,
		PasswordChangedAt: &now,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := s.users.Create(ctx, userModel); err != nil {
		return nil, err
	}

	if err := s.store.Delete(ctx, ticketID); err != nil {
		return nil, err
	}
	if err := s.store.DeleteCounter(ctx, verifyAttemptKey(ticketID)); err != nil {
		return nil, err
	}

	return userModel, nil
}

func (s *Service) ResendRegisterOTP(
	ctx context.Context,
	input ResendRegisterOTPInput,
) (*RegisterResult, error) {
	ticketID := strings.TrimSpace(input.TicketID)
	if ticketID == "" {
		return nil, ErrRegisterTicketRequired
	}

	pendingRegistration, err := s.store.Get(ctx, ticketID)
	if err != nil {
		return nil, err
	}

	now := s.now()
	if now.After(pendingRegistration.OTPExpiresAt) {
		_ = s.store.Delete(ctx, ticketID)
		_ = s.store.DeleteCounter(ctx, verifyAttemptKey(ticketID))
		return nil, user.ErrOTPExpired
	}
	if pendingRegistration.PasswordHash == "" || pendingRegistration.PhoneNumber == "" || pendingRegistration.OTPCodeHash == "" {
		_ = s.store.Delete(ctx, ticketID)
		_ = s.store.DeleteCounter(ctx, verifyAttemptKey(ticketID))
		return nil, ErrPendingRegistrationInvalid
	}

	if _, err := s.users.GetByPhoneNumber(ctx, pendingRegistration.PhoneNumber); err == nil {
		_ = s.store.Delete(ctx, ticketID)
		_ = s.store.DeleteCounter(ctx, verifyAttemptKey(ticketID))
		return nil, user.ErrPhoneNumberAlreadyRegistered
	} else if !errors.Is(err, user.ErrUserNotFound) {
		return nil, err
	}

	if pendingRegistration.ResendCount >= s.otpPolicy.MaxResends {
		return nil, ErrResendRateLimited
	}

	lastOTPSentAt := pendingRegistration.LastOTPSentAt
	if lastOTPSentAt.IsZero() {
		lastOTPSentAt = pendingRegistration.CreatedAt
	}
	if !lastOTPSentAt.IsZero() && now.Sub(lastOTPSentAt) < s.otpPolicy.ResendCooldown {
		return nil, ErrResendCooldownActive
	}

	otpCode, err := s.otpGenerator(registerOTPLength)
	if err != nil {
		return nil, err
	}

	previousRegistration := *pendingRegistration
	previousTTL := pendingRegistration.OTPExpiresAt.Sub(now)

	pendingRegistration.OTPCodeHash = hashRegisterOTP(ticketID, otpCode)
	pendingRegistration.OTPExpiresAt = now.Add(s.otpPolicy.TTL)
	pendingRegistration.ResendCount++
	pendingRegistration.LastOTPSentAt = now

	if err := s.store.Save(ctx, pendingRegistration, s.otpPolicy.TTL); err != nil {
		return nil, err
	}

	message := RegisterOTPMessage(otpCode, s.otpPolicy.TTL)
	parsedPhoneNumber, err := parsePhoneNumber(pendingRegistration.PhoneNumber)
	if err != nil {
		return nil, err
	}
	if err := s.sender.SendOTP(ctx, parsedPhoneNumber.TelCode, parsedPhoneNumber.Number, message); err != nil {
		if restoreErr := s.store.Save(ctx, &previousRegistration, previousTTL); restoreErr != nil {
			return nil, restoreErr
		}

		return nil, err
	}

	return &RegisterResult{
		TicketID:             ticketID,
		ExpiresAt:            pendingRegistration.OTPExpiresAt,
		ResendCooldown:       s.otpPolicy.ResendCooldown,
		RemainingResendCount: s.otpPolicy.MaxResends - pendingRegistration.ResendCount,
	}, nil
}

func (s *Service) enforceRegisterRateLimits(ctx context.Context, phoneNumber string) error {
	if err := s.enforceSystemRegisterRateLimit(ctx); err != nil {
		return err
	}

	phoneCount, err := s.store.IncrementCounter(ctx, registerPhoneRateKey(phoneNumber), s.otpPolicy.PhoneWindow)
	if err != nil {
		return err
	}
	if phoneCount > int64(s.otpPolicy.MaxPhoneRequests) {
		return ErrRegisterRateLimited
	}

	return nil
}

func (s *Service) enforceSystemRegisterRateLimit(ctx context.Context) error {
	count, err := s.store.IncrementCounter(
		ctx,
		registerSystemRateKey(),
		s.systemRateLimitPolicy.Window,
	)
	if err != nil {
		return err
	}
	if count > int64(s.systemRateLimitPolicy.MaxRequests) {
		return ErrRegisterRateLimited
	}

	return nil
}

func (s *Service) generateUniqueUsername(ctx context.Context) (*string, error) {
	for range usernameAttempts {
		candidate, err := s.usernameGenerator()
		if err != nil {
			return nil, err
		}

		if _, err := s.users.GetByUsername(ctx, candidate); errors.Is(err, user.ErrUserNotFound) {
			return &candidate, nil
		} else if err != nil {
			return nil, err
		}
	}

	return nil, user.ErrUsernameAlreadyRegistered
}

func systemRateLimitPolicyWithDefaults(policy SystemRateLimitPolicy) SystemRateLimitPolicy {
	if policy.Window <= 0 {
		policy.Window = defaultSystemRateLimitPolicy.Window
	}
	if policy.MaxRequests <= 0 {
		policy.MaxRequests = defaultSystemRateLimitPolicy.MaxRequests
	}

	return policy
}

func generateRegisterTicket() (string, error) {
	randomBytes := make([]byte, registerTicketBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	return registerTicketPrefix + hex.EncodeToString(randomBytes), nil
}

func generateUsername() (string, error) {
	randomBytes := make([]byte, usernameBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	return usernamePrefix + hex.EncodeToString(randomBytes), nil
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func normalizePhoneNumber(raw string) (string, error) {
	return user.NormalizePhoneNumber(raw)
}

func parsePhoneNumber(raw string) (user.PhoneNumber, error) {
	return user.ParsePhoneNumber(raw)
}

func hashRegisterOTP(ticketID string, otpCode string) string {
	sum := sha256.Sum256([]byte(ticketID + ":" + otpCode))
	return hex.EncodeToString(sum[:])
}

func matchRegisterOTP(expectedHash string, ticketID string, otpCode string) bool {
	actualHash := hashRegisterOTP(ticketID, otpCode)
	return subtle.ConstantTimeCompare([]byte(expectedHash), []byte(actualHash)) == 1
}

func registerPhoneRateKey(phoneNumber string) string {
	return fmt.Sprintf("register:rate:phone:%s", phoneNumber)
}

func registerSystemRateKey() string {
	return "register:rate:system"
}

func verifyAttemptKey(ticketID string) string {
	return fmt.Sprintf("register:verify:attempts:%s", ticketID)
}
