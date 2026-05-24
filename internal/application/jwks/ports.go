package jwks

import (
	"context"
	"time"

	"ddone-server-auth/internal/domain/auth"
)

type SigningKeyStore interface {
	Create(ctx context.Context, key *auth.SigningKey) error
	ListSigningKeys(ctx context.Context, now time.Time) ([]auth.SigningKey, error)
	ListPublicKeys(ctx context.Context, now time.Time) ([]auth.SigningKey, error)
	DeleteExpired(ctx context.Context, now time.Time) error
	WithRotationLock(ctx context.Context, fn func(context.Context) error) error
}

type TokenCodec interface {
	GenerateSigningKey(
		keyID string,
		createdAt time.Time,
		activatesAt time.Time,
		rotationInterval time.Duration,
		retentionWindow time.Duration,
	) (*auth.SigningKey, error)
	IssueAccessToken(key *auth.SigningKey, claims auth.AccessTokenClaims) (*auth.AccessToken, error)
	VerifyAccessToken(
		tokenValue string,
		keys []auth.SigningKey,
		expectedIssuer string,
		expectedAudience string,
		now time.Time,
	) (*auth.AccessTokenClaims, error)
	PublicJWK(key auth.SigningKey) auth.JWK
}
