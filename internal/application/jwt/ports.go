package jwt

import (
	"context"
	"time"

	"ddone-server-auth/internal/domain/auth"
)

type SigningKeyProvider interface {
	EnsureActiveSigningKey(ctx context.Context) (*auth.SigningKey, error)
}

type SigningKeyReader interface {
	ListPublicKeys(ctx context.Context, now time.Time) ([]auth.SigningKey, error)
	DeleteExpired(ctx context.Context, now time.Time) error
}

type TokenCodec interface {
	IssueAccessToken(key *auth.SigningKey, claims auth.AccessTokenClaims) (*auth.AccessToken, error)
	VerifyAccessToken(
		tokenValue string,
		keys []auth.SigningKey,
		expectedIssuer string,
		expectedAudience string,
		now time.Time,
	) (*auth.AccessTokenClaims, error)
}
