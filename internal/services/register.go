package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"ddone-server-auth/internal/adapters/sms"
	"ddone-server-auth/internal/domain/account"
	"ddone-server-auth/internal/ports"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	registerOTPLength    = 6
	registerOTPTTL       = 5 * time.Minute
	registerPhoneWindow  = 5 * time.Minute
	resendOTPCooldown    = 60 * time.Second
	verifyAttemptWindow  = registerOTPTTL
	maxPhoneRequests     = 1
	maxRegisterResends   = 3
	maxVerifyAttempts    = 5
	registerTicketPrefix = "reg_"
	registerTicketBytes  = 12
	usernamePrefix       = "user_"
	usernameBytes        = 6
	usernameAttempts     = 5
)

var ErrPhoneNumberRequired = errors.New("phone number is required")
var ErrInvalidPhoneNumber = errors.New("phone number format is invalid")
var ErrRegisterTicketRequired = errors.New("ticket id is required")
var ErrOTPCodeRequired = errors.New("otp code is required")
var ErrPasswordRequired = errors.New("password is required")
var ErrPendingRegistrationInvalid = errors.New("pending registration is invalid, request otp again")
var ErrRegisterRateLimited = errors.New("too many registration requests, try again later")
var ErrResendRateLimited = errors.New("too many otp resend requests, request a new registration")
var ErrResendCooldownActive = errors.New("please wait 60 seconds before requesting another otp")
var ErrVerifyRateLimited = errors.New("too many invalid otp attempts, request a new code")

type RegisterService struct {
	accounts          ports.AccountRepository
	store             ports.RegistrationStore
	sender            ports.OTPSender
	now               func() time.Time
	otpGenerator      func(int) (string, error)
	ticketGenerator   func() (string, error)
	usernameGenerator func() (string, error)
	passwordHasher    func(string) (string, error)
}

type RegisterInput struct {
	PhoneNumber string
	Password    string
	ClientID    string
}

type RegisterResult struct {
	TicketID  string
	ExpiresAt time.Time
}

type ResendRegisterOTPInput struct {
	TicketID string
	ClientID string
}

type VerifyRegisterInput struct {
	TicketID string
	OTPCode  string
	ClientID string
}

func NewRegisterService(
	accounts ports.AccountRepository,
	store ports.RegistrationStore,
	sender ports.OTPSender,
) *RegisterService {
	return &RegisterService{
		accounts:          accounts,
		store:             store,
		sender:            sender,
		now:               func() time.Time { return time.Now().UTC() },
		otpGenerator:      sms.GenerateOTP,
		ticketGenerator:   generateRegisterTicket,
		usernameGenerator: generateUsername,
		passwordHasher:    hashPassword,
	}
}

func (s *RegisterService) Register(
	ctx context.Context,
	input RegisterInput,
) (*RegisterResult, error) {
	phoneNumber, err := normalizePhoneNumber(input.PhoneNumber)
	if err != nil {
		return nil, err
	}
	if phoneNumber == "" {
		return nil, ErrPhoneNumberRequired
	}
	if strings.TrimSpace(input.Password) == "" {
		return nil, ErrPasswordRequired
	}
	if err := s.enforceRegisterRateLimits(ctx, phoneNumber); err != nil {
		return nil, err
	}

	if _, err := s.accounts.GetByPhoneNumber(ctx, phoneNumber); err == nil {
		return nil, account.ErrPhoneNumberAlreadyRegistered
	} else if !errors.Is(err, account.ErrAccountNotFound) {
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
	pendingRegistration := &account.RegisterModel{
		TicketID:      ticketID,
		Username:      username,
		PasswordHash:  passwordHash,
		PhoneNumber:   phoneNumber,
		OTPCodeHash:   otpCodeHash,
		OTPExpiresAt:  now.Add(registerOTPTTL),
		ResendCount:   0,
		LastOTPSentAt: now,
		CreatedAt:     now,
	}
	if err := s.store.Save(ctx, pendingRegistration, registerOTPTTL); err != nil {
		return nil, err
	}

	message := sms.RegisterOTPMessage(otpCode, registerOTPTTL)
	if err := s.sender.SendOTP(ctx, phoneNumber, message); err != nil {
		_ = s.store.Delete(ctx, ticketID)
		return nil, err
	}

	return &RegisterResult{
		TicketID:  ticketID,
		ExpiresAt: pendingRegistration.OTPExpiresAt,
	}, nil
}

func (s *RegisterService) VerifyRegister(
	ctx context.Context,
	input VerifyRegisterInput,
) (*account.AccountModel, error) {
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
		return nil, account.ErrOTPExpired
	}
	if pendingRegistration.PasswordHash == "" || phoneNumber == "" || pendingRegistration.OTPCodeHash == "" {
		_ = s.store.Delete(ctx, ticketID)
		_ = s.store.DeleteCounter(ctx, verifyAttemptKey(ticketID))
		return nil, ErrPendingRegistrationInvalid
	}

	if !matchRegisterOTP(pendingRegistration.OTPCodeHash, ticketID, otpCode) {
		attempts, err := s.store.IncrementCounter(ctx, verifyAttemptKey(ticketID), verifyAttemptWindow)
		if err != nil {
			return nil, err
		}
		if attempts >= maxVerifyAttempts {
			_ = s.store.Delete(ctx, ticketID)
			_ = s.store.DeleteCounter(ctx, verifyAttemptKey(ticketID))
			return nil, ErrVerifyRateLimited
		}

		return nil, account.ErrInvalidOTPCode
	}

	if _, err := s.accounts.GetByPhoneNumber(ctx, phoneNumber); err == nil {
		_ = s.store.Delete(ctx, ticketID)
		_ = s.store.DeleteCounter(ctx, verifyAttemptKey(ticketID))
		return nil, account.ErrPhoneNumberAlreadyRegistered
	} else if !errors.Is(err, account.ErrAccountNotFound) {
		return nil, err
	}

	username := pendingRegistration.Username
	if username == nil {
		username, err = s.generateUniqueUsername(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		if _, err := s.accounts.GetByUsername(ctx, *username); err == nil {
			username, err = s.generateUniqueUsername(ctx)
			if err != nil {
				return nil, err
			}
		} else if !errors.Is(err, account.ErrAccountNotFound) {
			return nil, err
		}
	}

	accountModel := &account.AccountModel{
		Username:        username,
		PasswordHash:    pendingRegistration.PasswordHash,
		PhoneNumber:     phoneNumber,
		PhoneVerifiedAt: now,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := s.accounts.Create(ctx, accountModel); err != nil {
		return nil, err
	}

	if err := s.store.Delete(ctx, ticketID); err != nil {
		return nil, err
	}
	if err := s.store.DeleteCounter(ctx, verifyAttemptKey(ticketID)); err != nil {
		return nil, err
	}

	return accountModel, nil
}

func (s *RegisterService) ResendRegisterOTP(
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
		return nil, account.ErrOTPExpired
	}
	if pendingRegistration.PasswordHash == "" || pendingRegistration.PhoneNumber == "" || pendingRegistration.OTPCodeHash == "" {
		_ = s.store.Delete(ctx, ticketID)
		_ = s.store.DeleteCounter(ctx, verifyAttemptKey(ticketID))
		return nil, ErrPendingRegistrationInvalid
	}

	if _, err := s.accounts.GetByPhoneNumber(ctx, pendingRegistration.PhoneNumber); err == nil {
		_ = s.store.Delete(ctx, ticketID)
		_ = s.store.DeleteCounter(ctx, verifyAttemptKey(ticketID))
		return nil, account.ErrPhoneNumberAlreadyRegistered
	} else if !errors.Is(err, account.ErrAccountNotFound) {
		return nil, err
	}

	if pendingRegistration.ResendCount >= maxRegisterResends {
		return nil, ErrResendRateLimited
	}

	lastOTPSentAt := pendingRegistration.LastOTPSentAt
	if lastOTPSentAt.IsZero() {
		lastOTPSentAt = pendingRegistration.CreatedAt
	}
	if !lastOTPSentAt.IsZero() && now.Sub(lastOTPSentAt) < resendOTPCooldown {
		return nil, ErrResendCooldownActive
	}

	otpCode, err := s.otpGenerator(registerOTPLength)
	if err != nil {
		return nil, err
	}

	previousRegistration := *pendingRegistration
	previousTTL := pendingRegistration.OTPExpiresAt.Sub(now)

	pendingRegistration.OTPCodeHash = hashRegisterOTP(ticketID, otpCode)
	pendingRegistration.OTPExpiresAt = now.Add(registerOTPTTL)
	pendingRegistration.ResendCount++
	pendingRegistration.LastOTPSentAt = now

	if err := s.store.Save(ctx, pendingRegistration, registerOTPTTL); err != nil {
		return nil, err
	}

	message := sms.RegisterOTPMessage(otpCode, registerOTPTTL)
	if err := s.sender.SendOTP(ctx, pendingRegistration.PhoneNumber, message); err != nil {
		if restoreErr := s.store.Save(ctx, &previousRegistration, previousTTL); restoreErr != nil {
			return nil, restoreErr
		}

		return nil, err
	}

	return &RegisterResult{
		TicketID:  ticketID,
		ExpiresAt: pendingRegistration.OTPExpiresAt,
	}, nil
}

func (s *RegisterService) enforceRegisterRateLimits(ctx context.Context, phoneNumber string) error {
	phoneCount, err := s.store.IncrementCounter(ctx, registerPhoneRateKey(phoneNumber), registerPhoneWindow)
	if err != nil {
		return err
	}
	if phoneCount > maxPhoneRequests {
		return ErrRegisterRateLimited
	}

	return nil
}

func (s *RegisterService) generateUniqueUsername(ctx context.Context) (*string, error) {
	for range usernameAttempts {
		candidate, err := s.usernameGenerator()
		if err != nil {
			return nil, err
		}

		if _, err := s.accounts.GetByUsername(ctx, candidate); errors.Is(err, account.ErrAccountNotFound) {
			return &candidate, nil
		} else if err != nil {
			return nil, err
		}
	}

	return nil, account.ErrUsernameAlreadyRegistered
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
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", ErrPhoneNumberRequired
	}

	var builder strings.Builder
	builder.Grow(len(value))

	for i, r := range value {
		switch {
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '+' && i == 0:
			continue
		case r == ' ' || r == '-' || r == '(' || r == ')':
			continue
		default:
			return "", ErrInvalidPhoneNumber
		}
	}

	digits := builder.String()
	if digits == "" {
		return "", ErrInvalidPhoneNumber
	}

	switch {
	case strings.HasPrefix(digits, "00856"):
		digits = digits[5:]
	case strings.HasPrefix(digits, "856"):
		digits = digits[3:]
	}

	if strings.HasPrefix(digits, "020") {
		digits = digits[1:]
	}

	if len(digits) != 10 || !strings.HasPrefix(digits, "20") {
		return "", ErrInvalidPhoneNumber
	}

	return digits, nil
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

func verifyAttemptKey(ticketID string) string {
	return fmt.Sprintf("register:verify:attempts:%s", ticketID)
}
