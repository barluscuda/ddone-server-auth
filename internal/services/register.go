package services

import (
	"context"
	"ddone-server-auth/internal/adapters/sms"
	"ddone-server-auth/internal/domain/account"
	"ddone-server-auth/internal/ports"
	"errors"
	"strings"
	"time"
)

const (
	registerOTPLength = 6
	registerOTPTTL    = 5 * time.Minute
)

type RegisterService struct {
	accounts ports.AccountRepository
	store    ports.RegistrationStore
	sender   ports.OTPSender
	now      func() time.Time
}

type RequestRegistrationInput struct {
	Username    *string
	PhoneNumber string
}

type RequestRegistrationResult struct {
	ExpiresAt time.Time
}

type VerifyRegistrationInput struct {
	PhoneNumber string
	OTPCode     string
}

func NewRegisterService(
	accounts ports.AccountRepository,
	store ports.RegistrationStore,
	sender ports.OTPSender,
) *RegisterService {
	return &RegisterService{
		accounts: accounts,
		store:    store,
		sender:   sender,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

func (s *RegisterService) RequestOTP(
	ctx context.Context,
	input RequestRegistrationInput,
) (*RequestRegistrationResult, error) {
	phoneNumber := strings.TrimSpace(input.PhoneNumber)
	if phoneNumber == "" {
		return nil, errors.New("phone number is required")
	}

	username := normalizeUsername(input.Username)

	if _, err := s.accounts.GetByPhoneNumber(ctx, phoneNumber); err == nil {
		return nil, account.ErrPhoneNumberAlreadyRegistered
	} else if !errors.Is(err, account.ErrAccountNotFound) {
		return nil, err
	}

	if username != nil {
		if _, err := s.accounts.GetByUsername(ctx, *username); err == nil {
			return nil, account.ErrUsernameAlreadyRegistered
		} else if !errors.Is(err, account.ErrAccountNotFound) {
			return nil, err
		}
	}

	otpCode, err := sms.GenerateOTP(registerOTPLength)
	if err != nil {
		return nil, err
	}

	now := s.now()
	pendingRegistration := &account.RegisterModel{
		Username:     username,
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
		_ = s.store.Delete(ctx, phoneNumber)
		return nil, err
	}

	return &RequestRegistrationResult{
		ExpiresAt: pendingRegistration.OTPExpiresAt,
	}, nil
}

func (s *RegisterService) VerifyOTP(
	ctx context.Context,
	input VerifyRegistrationInput,
) (*account.AccountModel, error) {
	phoneNumber := strings.TrimSpace(input.PhoneNumber)
	otpCode := strings.TrimSpace(input.OTPCode)
	if phoneNumber == "" {
		return nil, errors.New("phone number is required")
	}
	if otpCode == "" {
		return nil, errors.New("otp code is required")
	}

	pendingRegistration, err := s.store.Get(ctx, phoneNumber)
	if err != nil {
		return nil, err
	}

	now := s.now()
	if now.After(pendingRegistration.OTPExpiresAt) {
		_ = s.store.Delete(ctx, phoneNumber)
		return nil, account.ErrOTPExpired
	}

	if pendingRegistration.OTPCode != otpCode {
		return nil, account.ErrInvalidOTPCode
	}

	if _, err := s.accounts.GetByPhoneNumber(ctx, phoneNumber); err == nil {
		_ = s.store.Delete(ctx, phoneNumber)
		return nil, account.ErrPhoneNumberAlreadyRegistered
	} else if !errors.Is(err, account.ErrAccountNotFound) {
		return nil, err
	}

	username := normalizeUsername(pendingRegistration.Username)
	if username != nil {
		if _, err := s.accounts.GetByUsername(ctx, *username); err == nil {
			_ = s.store.Delete(ctx, phoneNumber)
			return nil, account.ErrUsernameAlreadyRegistered
		} else if !errors.Is(err, account.ErrAccountNotFound) {
			return nil, err
		}
	}

	accountModel := &account.AccountModel{
		Username:        username,
		PhoneNumber:     phoneNumber,
		PhoneVerifiedAt: now,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := s.accounts.Create(ctx, accountModel); err != nil {
		return nil, err
	}

	if err := s.store.Delete(ctx, phoneNumber); err != nil {
		return nil, err
	}

	return accountModel, nil
}

func normalizeUsername(username *string) *string {
	if username == nil {
		return nil
	}

	value := strings.TrimSpace(*username)
	if value == "" {
		return nil
	}

	return &value
}
