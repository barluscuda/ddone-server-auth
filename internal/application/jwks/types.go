package jwks

import (
	"context"
	"time"

	"ddone-server-auth/internal/domain/auth"
)

type UseCase interface {
	SigningKeyProvider
	PublicJWKSetProvider
}

type SigningKeyProvider interface {
	EnsureActiveSigningKey(ctx context.Context) (*auth.SigningKey, error)
}

type PublicJWKSetProvider interface {
	PublicJWKS(ctx context.Context) (*auth.JWKSet, error)
}

type Settings struct {
	SigningKeyRotation  time.Duration
	SigningKeyRetention time.Duration
}
