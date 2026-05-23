package jwks

import (
	"context"
	"errors"
	"testing"
	"time"

	"ddone-server-auth/internal/domain/auth"
)

type fakeSigningKeyStore struct {
	active       *auth.SigningKey
	keys         []auth.SigningKey
	deletedAt    []time.Time
	retiredKeyID string
}

func (s *fakeSigningKeyStore) GetActive(_ context.Context, _ time.Time) (*auth.SigningKey, error) {
	if s.active == nil {
		return nil, auth.ErrSigningKeyNotFound
	}

	key := *s.active
	return &key, nil
}

func (s *fakeSigningKeyStore) Create(_ context.Context, key *auth.SigningKey) error {
	s.active = key
	s.keys = append(s.keys, *key)
	return nil
}

func (s *fakeSigningKeyStore) Retire(_ context.Context, keyID string) error {
	s.retiredKeyID = keyID
	if s.active != nil && s.active.KeyID == keyID {
		s.active.Status = auth.SigningKeyStatusRetired
	}
	for i := range s.keys {
		if s.keys[i].KeyID == keyID {
			s.keys[i].Status = auth.SigningKeyStatusRetired
		}
	}
	return nil
}

func (s *fakeSigningKeyStore) ListPublicKeys(_ context.Context, _ time.Time) ([]auth.SigningKey, error) {
	return append([]auth.SigningKey(nil), s.keys...), nil
}

func (s *fakeSigningKeyStore) DeleteExpired(_ context.Context, now time.Time) error {
	s.deletedAt = append(s.deletedAt, now)
	return nil
}

func (s *fakeSigningKeyStore) WithRotationLock(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

type fakeTokenCodec struct {
	generatedKey *auth.SigningKey
	issuedClaims auth.AccessTokenClaims
}

func (c *fakeTokenCodec) GenerateSigningKey(
	keyID string,
	now time.Time,
	rotationInterval time.Duration,
	retentionWindow time.Duration,
) (*auth.SigningKey, error) {
	c.generatedKey = &auth.SigningKey{
		KeyID:         keyID,
		Algorithm:     "ES256",
		Curve:         "P-256",
		PublicX:       "x",
		PublicY:       "y",
		PrivateKeyPEM: "pem",
		Status:        auth.SigningKeyStatusActive,
		CreatedAt:     now,
		ActivatesAt:   now,
		RotatesAt:     now.Add(rotationInterval),
		RetiresAt:     now.Add(retentionWindow),
	}
	return c.generatedKey, nil
}

func (c *fakeTokenCodec) IssueAccessToken(
	key *auth.SigningKey,
	claims auth.AccessTokenClaims,
) (*auth.AccessToken, error) {
	if key == nil {
		return nil, errors.New("missing key")
	}

	c.issuedClaims = claims
	return &auth.AccessToken{
		Token:     "signed-token",
		TokenType: "Bearer",
		ExpiresAt: claims.ExpiresAt,
		ExpiresIn: int64(claims.ExpiresAt.Sub(claims.IssuedAt).Seconds()),
		KeyID:     key.KeyID,
	}, nil
}

func (c *fakeTokenCodec) PublicJWK(key auth.SigningKey) auth.JWK {
	return auth.JWK{
		KeyType:   "EC",
		Use:       "sig",
		Curve:     key.Curve,
		Algorithm: key.Algorithm,
		KeyID:     key.KeyID,
		X:         key.PublicX,
		Y:         key.PublicY,
	}
}

func TestEnsureActiveSigningKeyCreatesFirstKey(t *testing.T) {
	store := &fakeSigningKeyStore{}
	codec := &fakeTokenCodec{}
	service := NewService(store, codec, Settings{
		Issuer:              "issuer",
		Audience:            "audience",
		AccessTokenTTL:      15 * time.Minute,
		SigningKeyRotation:  90 * 24 * time.Hour,
		SigningKeyRetention: 180 * 24 * time.Hour,
	})
	now := time.Date(2026, 5, 23, 9, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }

	key, err := service.EnsureActiveSigningKey(context.Background())
	if err != nil {
		t.Fatalf("EnsureActiveSigningKey returned error: %v", err)
	}

	if key == nil {
		t.Fatal("expected key")
	}
	if key.Status != auth.SigningKeyStatusActive {
		t.Fatalf("expected active key, got %q", key.Status)
	}
	if codec.generatedKey == nil {
		t.Fatal("expected codec to generate a key")
	}
}

func TestIssueAccessTokenUsesActiveKey(t *testing.T) {
	now := time.Date(2026, 5, 23, 10, 0, 0, 0, time.UTC)
	store := &fakeSigningKeyStore{
		active: &auth.SigningKey{
			KeyID:         "kid-1",
			Algorithm:     "ES256",
			Curve:         "P-256",
			Status:        auth.SigningKeyStatusActive,
			CreatedAt:     now.Add(-time.Hour),
			RotatesAt:     now.Add(time.Hour),
			RetiresAt:     now.Add(90 * 24 * time.Hour),
			PublicX:       "x",
			PublicY:       "y",
			PrivateKeyPEM: "pem",
		},
	}
	store.keys = []auth.SigningKey{*store.active}
	codec := &fakeTokenCodec{}
	service := NewService(store, codec, Settings{
		Issuer:              "issuer",
		Audience:            "audience",
		AccessTokenTTL:      15 * time.Minute,
		SigningKeyRotation:  90 * 24 * time.Hour,
		SigningKeyRetention: 180 * 24 * time.Hour,
	})
	service.now = func() time.Time { return now }

	token, err := service.IssueAccessToken(context.Background(), "account-1", "2012345678")
	if err != nil {
		t.Fatalf("IssueAccessToken returned error: %v", err)
	}

	if token.Token != "signed-token" {
		t.Fatalf("expected signed token, got %q", token.Token)
	}
	if codec.issuedClaims.Subject != "account-1" {
		t.Fatalf("expected subject %q, got %q", "account-1", codec.issuedClaims.Subject)
	}
	if codec.issuedClaims.PhoneNumber != "2012345678" {
		t.Fatalf("expected phone number %q, got %q", "2012345678", codec.issuedClaims.PhoneNumber)
	}
}
