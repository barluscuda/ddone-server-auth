package password

import (
	"context"
	"time"

	"ddone-server-auth/internal/domain/user"
)

type UserStore interface {
	GetByID(ctx context.Context, id string) (*user.UserModel, error)
	GetByPhoneNumber(ctx context.Context, phoneNumber string) (*user.UserModel, error)
	Update(ctx context.Context, userModel *user.UserModel) error
}

type ResetStore interface {
	Save(ctx context.Context, state *ResetTicketState, ttl time.Duration) error
	Get(ctx context.Context, ticketID string) (*ResetTicketState, error)
	Delete(ctx context.Context, ticketID string) error
	IncrementCounter(ctx context.Context, key string, ttl time.Duration) (int64, error)
	DeleteCounter(ctx context.Context, key string) error
}

type OTPSender interface {
	SendOTP(ctx context.Context, phoneNumber string, msg string) error
}

type TokenRevoker interface {
	RevokeByUserID(ctx context.Context, userID string, reason string, revokedAt time.Time) error
}

type LoginSessionRevoker interface {
	RevokeByUserID(ctx context.Context, userID string, reason string, revokedAt time.Time) error
}
