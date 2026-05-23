package register

import (
	"context"
	"time"

	"ddone-server-auth/internal/domain/account"
)

type UseCase interface {
	Register(ctx context.Context, input RegisterInput) (*RegisterResult, error)
	VerifyRegister(ctx context.Context, input VerifyRegisterInput) (*account.AccountModel, error)
	ResendRegisterOTP(ctx context.Context, input ResendRegisterOTPInput) (*RegisterResult, error)
}

type RegisterInput struct {
	PhoneNumber string
	Password    string
	ClientID    string
}

type RegisterResult struct {
	TicketID             string
	ExpiresAt            time.Time
	RemainingResendCount int
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
