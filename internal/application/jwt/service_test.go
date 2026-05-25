package jwt

import (
	"context"
	"errors"
	"testing"
	"time"

	"ddone-server-auth/internal/domain/auth"
)

type fakeSigningKeyProvider struct {
	key *auth.SigningKey
	err error
}

func (p *fakeSigningKeyProvider) EnsureActiveSigningKey(_ context.Context) (*auth.SigningKey, error) {
	if p.err != nil {
		return nil, p.err
	}

	return p.key, nil
}

type fakeSigningKeyReader struct {
	keys      []auth.SigningKey
	deletedAt []time.Time
}

func (r *fakeSigningKeyReader) ListPublicKeys(_ context.Context, _ time.Time) ([]auth.SigningKey, error) {
	return append([]auth.SigningKey(nil), r.keys...), nil
}

func (r *fakeSigningKeyReader) DeleteExpired(_ context.Context, now time.Time) error {
	r.deletedAt = append(r.deletedAt, now)
	return nil
}

type fakeTokenCodec struct {
	issuedKey      *auth.SigningKey
	issuedClaims   auth.AccessTokenClaims
	verifiedToken  string
	verifiedKeys   []auth.SigningKey
	verifiedIssuer string
	verifiedAud    string
	verifiedNow    time.Time
	verifiedClaims *auth.AccessTokenClaims
}

func (c *fakeTokenCodec) IssueAccessToken(
	key *auth.SigningKey,
	claims auth.AccessTokenClaims,
) (*auth.AccessToken, error) {
	c.issuedKey = key
	c.issuedClaims = claims
	return &auth.AccessToken{
		Token:     "signed-token",
		TokenType: "Bearer",
		ExpiresAt: claims.ExpiresAt,
		ExpiresIn: int64(claims.ExpiresAt.Sub(claims.IssuedAt).Seconds()),
		KeyID:     key.KeyID,
	}, nil
}

func (c *fakeTokenCodec) VerifyAccessToken(
	tokenValue string,
	keys []auth.SigningKey,
	expectedIssuer string,
	expectedAudience string,
	now time.Time,
) (*auth.AccessTokenClaims, error) {
	c.verifiedToken = tokenValue
	c.verifiedKeys = append([]auth.SigningKey(nil), keys...)
	c.verifiedIssuer = expectedIssuer
	c.verifiedAud = expectedAudience
	c.verifiedNow = now
	if c.verifiedClaims == nil {
		return nil, auth.ErrInvalidAccessToken
	}

	return c.verifiedClaims, nil
}

func TestIssueAccessTokenUsesActiveSigningKey(t *testing.T) {
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	codec := &fakeTokenCodec{}
	service := NewService(
		&fakeSigningKeyProvider{key: &auth.SigningKey{KeyID: "kid-1"}},
		&fakeSigningKeyReader{},
		codec,
		Settings{
			Issuer:         "issuer",
			Audience:       "audience",
			AccessTokenTTL: 15 * time.Minute,
		},
	)
	service.now = func() time.Time { return now }

	token, err := service.IssueAccessToken(context.Background(), "user-1", "+8562012345678")
	if err != nil {
		t.Fatalf("IssueAccessToken returned error: %v", err)
	}

	if token.Token != "signed-token" {
		t.Fatalf("expected signed token, got %q", token.Token)
	}
	if codec.issuedKey == nil || codec.issuedKey.KeyID != "kid-1" {
		t.Fatalf("expected token to use active key, got %#v", codec.issuedKey)
	}
	if codec.issuedClaims.Issuer != "issuer" || codec.issuedClaims.Audience != "audience" {
		t.Fatalf("expected configured issuer/audience, got %#v", codec.issuedClaims)
	}
	if codec.issuedClaims.Subject != "user-1" || codec.issuedClaims.UserID != "user-1" {
		t.Fatalf("expected user id in subject and userId, got %#v", codec.issuedClaims)
	}
	if codec.issuedClaims.PhoneNumber != "+8562012345678" {
		t.Fatalf("expected phone number claim, got %q", codec.issuedClaims.PhoneNumber)
	}
	if codec.issuedClaims.JWTID == "" {
		t.Fatal("expected jwt id")
	}
	if !codec.issuedClaims.IssuedAt.Equal(now) || !codec.issuedClaims.NotBefore.Equal(now) {
		t.Fatalf("expected issued and not-before at %s, got %#v", now, codec.issuedClaims)
	}
	if !codec.issuedClaims.ExpiresAt.Equal(now.Add(15 * time.Minute)) {
		t.Fatalf("expected expiry at %s, got %s", now.Add(15*time.Minute), codec.issuedClaims.ExpiresAt)
	}
}

func TestIssueAccessTokenReturnsKeyProviderError(t *testing.T) {
	expectedErr := errors.New("key provider failed")
	service := NewService(
		&fakeSigningKeyProvider{err: expectedErr},
		&fakeSigningKeyReader{},
		&fakeTokenCodec{},
		Settings{AccessTokenTTL: 15 * time.Minute},
	)

	_, err := service.IssueAccessToken(context.Background(), "user-1", "+8562012345678")
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected key provider error, got %v", err)
	}
}

func TestVerifyAccessTokenUsesPublicKeys(t *testing.T) {
	now := time.Date(2026, 5, 24, 11, 0, 0, 0, time.UTC)
	reader := &fakeSigningKeyReader{
		keys: []auth.SigningKey{{KeyID: "kid-1"}},
	}
	codec := &fakeTokenCodec{
		verifiedClaims: &auth.AccessTokenClaims{
			UserID: "user-1",
		},
	}
	service := NewService(
		&fakeSigningKeyProvider{},
		reader,
		codec,
		Settings{
			Issuer:         "issuer",
			Audience:       "audience",
			AccessTokenTTL: 15 * time.Minute,
		},
	)
	service.now = func() time.Time { return now }

	claims, err := service.VerifyAccessToken(context.Background(), "access-token")
	if err != nil {
		t.Fatalf("VerifyAccessToken returned error: %v", err)
	}

	if claims.UserID != "user-1" {
		t.Fatalf("expected verified claims, got %#v", claims)
	}
	if len(reader.deletedAt) != 1 || !reader.deletedAt[0].Equal(now) {
		t.Fatalf("expected expired keys to be deleted at %s, got %#v", now, reader.deletedAt)
	}
	if codec.verifiedToken != "access-token" {
		t.Fatalf("expected token to verify, got %q", codec.verifiedToken)
	}
	if len(codec.verifiedKeys) != 1 || codec.verifiedKeys[0].KeyID != "kid-1" {
		t.Fatalf("expected public keys to be passed to codec, got %#v", codec.verifiedKeys)
	}
	if codec.verifiedIssuer != "issuer" || codec.verifiedAud != "audience" {
		t.Fatalf("expected issuer/audience, got %q/%q", codec.verifiedIssuer, codec.verifiedAud)
	}
	if !codec.verifiedNow.Equal(now) {
		t.Fatalf("expected verify time %s, got %s", now, codec.verifiedNow)
	}
}
