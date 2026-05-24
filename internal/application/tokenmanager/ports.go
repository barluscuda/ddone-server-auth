package tokenmanager

import (
	"context"
	"time"

	"ddone-server-auth/internal/domain/auth"
)

type Store interface {
	GetByID(ctx context.Context, tokenID string) (*auth.TokenRecord, error)
	ListByAccountID(ctx context.Context, accountID string) ([]auth.TokenRecord, error)
	RevokeByID(ctx context.Context, tokenID string, reason string, revokedAt time.Time) error
	RevokeByAccountID(ctx context.Context, accountID string, reason string, revokedAt time.Time) error
}
