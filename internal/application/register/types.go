package register

import (
	"context"
	"ddone-server-auth/internal/application/otp"
	"time"

	"ddone-server-auth/internal/domain/user"
)

type UseCase interface {
	Register(ctx context.Context, input RegisterInput) (*RegisterResult, error)
	VerifyRegister(ctx context.Context, input VerifyRegisterInput) (*user.User, error)
	ResendRegisterOTP(ctx context.Context, input ResendRegisterOTPInput) (*RegisterResult, error)
}

type RegisterInput struct {
	PhoneNumber string
	Password    string
	ClientIP    string
}

type RegisterResult struct {
	TicketID             string
	ExpiresAt            time.Time
	ResendCooldown       time.Duration
	RemainingResendCount int
}

type Settings struct {
	OTPPolicy otp.Policy
}

type ResendRegisterOTPInput struct {
	TicketID string
	ClientIP string
}

type VerifyRegisterInput struct {
	TicketID string
	OTPCode  string
	ClientIP string
}
