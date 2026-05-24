package session

import (
	"context"
	"time"

	"ddone-server-auth/internal/domain/auth"
)

type Store interface {
	GetByID(ctx context.Context, sessionID string) (*auth.LoginSession, error)
	GetByCurrentAccessToken(ctx context.Context, accessToken string) (*auth.LoginSession, error)
	ListByUserID(ctx context.Context, userID string) ([]auth.LoginSession, error)
	RevokeByID(ctx context.Context, sessionID string, reason string, revokedAt time.Time) error
	RevokeByUserIDExcept(
		ctx context.Context,
		userID string,
		excludedSessionID string,
		reason string,
		revokedAt time.Time,
	) error
	RevokeByUserID(ctx context.Context, userID string, reason string, revokedAt time.Time) error
}
