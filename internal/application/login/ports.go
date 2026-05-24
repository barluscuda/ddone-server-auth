package login

import (
	"context"
	"time"

	"ddone-server-auth/internal/domain/auth"
	"ddone-server-auth/internal/domain/user"
)

type UserLookup interface {
	GetByID(ctx context.Context, id string) (*user.User, error)
	GetByPhoneNumber(ctx context.Context, phoneNumber string) (*user.User, error)
}

type TokenStore interface {
	Create(ctx context.Context, tokenRecord *auth.TokenRecord) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*auth.TokenRecord, error)
	Rotate(ctx context.Context, currentTokenID string, replacement *auth.TokenRecord, usedAt time.Time) error
	RevokeLineage(ctx context.Context, rootTokenID string, reason string, revokedAt time.Time) error
}

type LoginSessionStore interface {
	Create(ctx context.Context, session *auth.LoginSession) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*auth.LoginSession, error)
}

type AccessTokenIssuer interface {
	IssueAccessToken(ctx context.Context, userID string, phoneNumber string) (*auth.AccessToken, error)
}
