package jwks

import (
	"context"
	"time"

	"ddone-server-auth/internal/domain/auth"
)

type UseCase interface {
	EnsureActiveSigningKey(ctx context.Context) (*auth.SigningKey, error)
	IssueAccessToken(ctx context.Context, accountID string, phoneNumber string) (*auth.AccessToken, error)
	VerifyAccessToken(ctx context.Context, tokenValue string) (*auth.AccessTokenClaims, error)
	PublicJWKS(ctx context.Context) (*auth.JWKSet, error)
}

type Settings struct {
	Issuer              string
	Audience            string
	AccessTokenTTL      time.Duration
	SigningKeyRotation  time.Duration
	SigningKeyRetention time.Duration
}
