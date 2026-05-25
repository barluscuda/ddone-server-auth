package session

import (
	"context"
	"time"

	appjwt "ddone-server-auth/internal/application/jwt"
	"ddone-server-auth/internal/domain/auth"
	"ddone-server-auth/internal/domain/user"
)

type Store interface {
	GetByID(ctx context.Context, sessionID string) (*auth.LoginSession, error)
	ListByUserID(ctx context.Context, userID string) ([]auth.LoginSession, error)
	RefreshAccessToken(
		ctx context.Context,
		sessionID string,
		accessToken *auth.AccessToken,
		sessionExpiresAt time.Time,
	) error
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

type UserLookup interface {
	GetByID(ctx context.Context, id string) (*user.User, error)
}

type AccessTokenIssuer = appjwt.Issuer
