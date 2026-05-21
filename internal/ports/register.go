package ports

import (
	"context"
	"time"

	"ddone-server-auth/internal/domain/account"
)

type RegistrationStore interface {
	Save(ctx context.Context, registration *account.RegisterModel, ttl time.Duration) error
	Get(ctx context.Context, phoneNumber string) (*account.RegisterModel, error)
	Delete(ctx context.Context, phoneNumber string) error
}

type OTPSender interface {
	SendOTP(ctx context.Context, phoneNumber string, msg string) error
}
