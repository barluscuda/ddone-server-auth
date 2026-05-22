package services

import (
	"context"
	"crypto/rand"
	"ddone-server-auth/internal/adapters/sms"
	"ddone-server-auth/internal/domain/account"
	"ddone-server-auth/internal/ports"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	registerOTPLength    = 6
	registerOTPTTL       = 5 * time.Minute
	registerTicketPrefix = "reg_"
	registerTicketBytes  = 12
	usernamePrefix       = "user_"
	usernameBytes        = 6
	usernameAttempts     = 5
)

var ErrPhoneNumberRequired = errors.New("phone number is required")
var ErrRegisterTicketRequired = errors.New("ticket id is required")
var ErrOTPCodeRequired = errors.New("otp code is required")
var ErrPasswordRequired = errors.New("password is required")
var ErrPendingRegistrationInvalid = errors.New("pending registration is invalid, request otp again")

type RegisterService struct {
	accounts          ports.AccountRepository
	store             ports.RegistrationStore
	sender            ports.OTPSender
	now               func() time.Time
	ticketGenerator   func() (string, error)
	usernameGenerator func() (string, error)
	passwordHasher    func(string) (string, error)
}

type RegisterInput struct {
	PhoneNumber string
	Password    string
}

type RegisterResult struct {
	TicketID  string
	ExpiresAt time.Time
}

type VerifyRegisterInput struct {
	TicketID string
	OTPCode  string
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
		ticketGenerator:   generateRegisterTicket,
		usernameGenerator: generateUsername,
		passwordHasher:    hashPassword,
	}
}

func (s *RegisterService) Register(
	ctx context.Context,
	input RegisterInput,
) (*RegisterResult, error) {
	phoneNumber := strings.TrimSpace(input.PhoneNumber)
	if phoneNumber == "" {
		return nil, ErrPhoneNumberRequired
	}
	if strings.TrimSpace(input.Password) == "" {
		return nil, ErrPasswordRequired
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

	otpCode, err := sms.GenerateOTP(registerOTPLength)
	if err != nil {
		return nil, err
	}
	ticketID, err := s.ticketGenerator()
	if err != nil {
		return nil, err
	}

	now := s.now()
	pendingRegistration := &account.RegisterModel{
		TicketID:     ticketID,
		Username:     username,
		PasswordHash: passwordHash,
		PhoneNumber:  phoneNumber,
		OTPCode:      otpCode,
		OTPExpiresAt: now.Add(registerOTPTTL),
		CreatedAt:    now,
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
		return nil, account.ErrOTPExpired
	}

	if pendingRegistration.OTPCode != otpCode {
		return nil, account.ErrInvalidOTPCode
	}
	if pendingRegistration.PasswordHash == "" || phoneNumber == "" {
		_ = s.store.Delete(ctx, ticketID)
		return nil, ErrPendingRegistrationInvalid
	}

	if _, err := s.accounts.GetByPhoneNumber(ctx, phoneNumber); err == nil {
		_ = s.store.Delete(ctx, ticketID)
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

	return accountModel, nil
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
