package tokenmanager

import (
	"context"
	"time"

	"ddone-server-auth/internal/domain/auth"
)

type Store interface {
	GetByID(ctx context.Context, tokenID string) (*auth.TokenRecord, error)
	ListByUserID(ctx context.Context, userID string) ([]auth.TokenRecord, error)
	RevokeByID(ctx context.Context, tokenID string, reason string, revokedAt time.Time) error
	RevokeByUserID(ctx context.Context, userID string, reason string, revokedAt time.Time) error
}
