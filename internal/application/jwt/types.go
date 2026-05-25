package jwt

import (
	"context"
	"time"

	"ddone-server-auth/internal/domain/auth"
)

type UseCase interface {
	Issuer
	Verifier
}

type Issuer interface {
	IssueAccessToken(ctx context.Context, userID string, phoneNumber string) (*auth.AccessToken, error)
}

type Verifier interface {
	VerifyAccessToken(ctx context.Context, tokenValue string) (*auth.AccessTokenClaims, error)
}

type Settings struct {
	Issuer         string
	Audience       string
	AccessTokenTTL time.Duration
}
