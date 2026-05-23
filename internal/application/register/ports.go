package register

import (
	"context"
	"time"

	"ddone-server-auth/internal/domain/account"
)

type AccountStore interface {
	Create(ctx context.Context, account *account.AccountModel) error
	GetByPhoneNumber(ctx context.Context, phoneNumber string) (*account.AccountModel, error)
	GetByUsername(ctx context.Context, username string) (*account.AccountModel, error)
}

type RegistrationStore interface {
	Save(ctx context.Context, registration *account.RegisterModel, ttl time.Duration) error
	Get(ctx context.Context, ticketID string) (*account.RegisterModel, error)
	Delete(ctx context.Context, ticketID string) error
	IncrementCounter(ctx context.Context, key string, ttl time.Duration) (int64, error)
	DeleteCounter(ctx context.Context, key string) error
}

type OTPSender interface {
	SendOTP(ctx context.Context, phoneNumber string, msg string) error
}
