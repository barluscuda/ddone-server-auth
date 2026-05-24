package login

import (
	"context"
	"time"

	"ddone-server-auth/internal/domain/account"
	"ddone-server-auth/internal/domain/auth"
)

type AccountLookup interface {
	GetByID(ctx context.Context, id string) (*account.AccountModel, error)
	GetByPhoneNumber(ctx context.Context, phoneNumber string) (*account.AccountModel, error)
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
	UpdateAccessToken(ctx context.Context, sessionID string, accessToken *auth.AccessToken) error
}

type AccessTokenIssuer interface {
	IssueAccessToken(ctx context.Context, accountID string, phoneNumber string) (*auth.AccessToken, error)
}
