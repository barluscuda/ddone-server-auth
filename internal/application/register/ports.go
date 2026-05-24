package register

import (
	"context"
	"time"

	"ddone-server-auth/internal/domain/user"
)

type UserStore interface {
	Create(ctx context.Context, user *user.UserModel) error
	GetByPhoneNumber(ctx context.Context, phoneNumber string) (*user.UserModel, error)
	GetByUsername(ctx context.Context, username string) (*user.UserModel, error)
}

type RegistrationStore interface {
	Save(ctx context.Context, registration *user.RegisterModel, ttl time.Duration) error
	Get(ctx context.Context, ticketID string) (*user.RegisterModel, error)
	Delete(ctx context.Context, ticketID string) error
	IncrementCounter(ctx context.Context, key string, ttl time.Duration) (int64, error)
	DeleteCounter(ctx context.Context, key string) error
}

type OTPSender interface {
	SendOTP(ctx context.Context, phoneNumber string, msg string) error
}
