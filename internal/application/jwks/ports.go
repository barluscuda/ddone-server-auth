package jwks

import (
	"context"
	"time"

	"ddone-server-auth/internal/domain/auth"
)

type SigningKeyStore interface {
	GetActive(ctx context.Context, now time.Time) (*auth.SigningKey, error)
	Create(ctx context.Context, key *auth.SigningKey) error
	Retire(ctx context.Context, keyID string) error
	ListPublicKeys(ctx context.Context, now time.Time) ([]auth.SigningKey, error)
	DeleteExpired(ctx context.Context, now time.Time) error
	WithRotationLock(ctx context.Context, fn func(context.Context) error) error
}

type TokenCodec interface {
	GenerateSigningKey(
		keyID string,
		now time.Time,
		rotationInterval time.Duration,
		retentionWindow time.Duration,
	) (*auth.SigningKey, error)
	IssueAccessToken(key *auth.SigningKey, claims auth.AccessTokenClaims) (*auth.AccessToken, error)
	PublicJWK(key auth.SigningKey) auth.JWK
}
