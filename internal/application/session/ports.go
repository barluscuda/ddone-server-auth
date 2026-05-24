package session

import (
	"context"
	"time"

	"ddone-server-auth/internal/domain/auth"
)

type Store interface {
	GetByID(ctx context.Context, sessionID string) (*auth.LoginSession, error)
	GetByCurrentAccessToken(ctx context.Context, accessToken string) (*auth.LoginSession, error)
	ListByAccountID(ctx context.Context, accountID string) ([]auth.LoginSession, error)
	RevokeByID(ctx context.Context, sessionID string, reason string, revokedAt time.Time) error
	RevokeByAccountIDExcept(
		ctx context.Context,
		accountID string,
		excludedSessionID string,
		reason string,
		revokedAt time.Time,
	) error
	RevokeByAccountID(ctx context.Context, accountID string, reason string, revokedAt time.Time) error
}
