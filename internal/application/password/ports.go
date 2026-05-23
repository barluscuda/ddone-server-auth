package password

import (
	"context"
	"time"

	"ddone-server-auth/internal/domain/account"
)

type AccountStore interface {
	GetByID(ctx context.Context, id string) (*account.AccountModel, error)
	GetByPhoneNumber(ctx context.Context, phoneNumber string) (*account.AccountModel, error)
	Update(ctx context.Context, accountModel *account.AccountModel) error
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

type RefreshSessionRevoker interface {
	RevokeByAccountID(ctx context.Context, accountID string, reason string, revokedAt time.Time) error
}

type LoginSessionRevoker interface {
	RevokeByAccountID(ctx context.Context, accountID string, reason string, revokedAt time.Time) error
}
