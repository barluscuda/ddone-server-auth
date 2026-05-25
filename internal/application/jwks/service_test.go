package jwks

import (
	"context"
	"testing"
	"time"

	"ddone-server-auth/internal/domain/auth"
)

type fakeSigningKeyStore struct {
	keys               []auth.SigningKey
	deletedAt          []time.Time
	signingKeyListHits int
	publicKeyListHits  int
}

func (s *fakeSigningKeyStore) Create(_ context.Context, key *auth.SigningKey) error {
	s.keys = append(s.keys, *key)
	return nil
}

func (s *fakeSigningKeyStore) ListSigningKeys(_ context.Context, _ time.Time) ([]auth.SigningKey, error) {
	s.signingKeyListHits++
	return append([]auth.SigningKey(nil), s.keys...), nil
}

func (s *fakeSigningKeyStore) ListPublicKeys(_ context.Context, _ time.Time) ([]auth.SigningKey, error) {
	s.publicKeyListHits++
	keys := append([]auth.SigningKey(nil), s.keys...)
	for i := range keys {
		keys[i].PrivateKeyPEM = ""
	}

	return keys, nil
}

func (s *fakeSigningKeyStore) DeleteExpired(_ context.Context, now time.Time) error {
	s.deletedAt = append(s.deletedAt, now)
	return nil
}

func (s *fakeSigningKeyStore) WithRotationLock(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

type fakeTokenCodec struct {
	generatedKeys []*auth.SigningKey
}

func (c *fakeTokenCodec) GenerateSigningKey(
	keyID string,
	createdAt time.Time,
	activatesAt time.Time,
	rotationInterval time.Duration,
	retentionWindow time.Duration,
) (*auth.SigningKey, error) {
	status := auth.SigningKeyStatusActive
	if activatesAt.After(createdAt) {
		status = auth.SigningKeyStatusScheduled
	}

	key := &auth.SigningKey{
		KeyID:         keyID,
		Algorithm:     "ES256",
		Curve:         "P-256",
		PublicX:       "x",
		PublicY:       "y",
		PrivateKeyPEM: "pem",
		Status:        status,
		CreatedAt:     createdAt,
		ActivatesAt:   activatesAt,
		RotatesAt:     activatesAt.Add(rotationInterval),
		RetiresAt:     activatesAt.Add(retentionWindow),
	}
	c.generatedKeys = append(c.generatedKeys, key)
	return key, nil
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
	if len(codec.generatedKeys) != 2 {
		t.Fatalf("expected 2 generated keys, got %d", len(codec.generatedKeys))
	}
	if len(store.keys) != 2 {
		t.Fatalf("expected key ring with 2 keys, got %d", len(store.keys))
	}
	if store.keys[1].Status != auth.SigningKeyStatusScheduled {
		t.Fatalf("expected successor key to be scheduled, got %q", store.keys[1].Status)
	}
	if !store.keys[1].ActivatesAt.Equal(store.keys[0].RotatesAt) {
		t.Fatalf(
			"expected successor to activate at %s, got %s",
			store.keys[0].RotatesAt,
			store.keys[1].ActivatesAt,
		)
	}
}

func TestPublicJWKSReturnsPublishedKeys(t *testing.T) {
	now := time.Date(2026, 5, 23, 10, 0, 0, 0, time.UTC)
	store := &fakeSigningKeyStore{
		keys: []auth.SigningKey{{
			KeyID:       "kid-1",
			Algorithm:   "ES256",
			Curve:       "P-256",
			PublicX:     "x",
			PublicY:     "y",
			Status:      auth.SigningKeyStatusActive,
			CreatedAt:   now.Add(-time.Hour),
			ActivatesAt: now.Add(-time.Hour),
			RotatesAt:   now.Add(time.Hour),
			RetiresAt:   now.Add(90 * 24 * time.Hour),
		}},
	}
	codec := &fakeTokenCodec{}
	service := NewService(store, codec, Settings{
		SigningKeyRotation:  90 * 24 * time.Hour,
		SigningKeyRetention: 180 * 24 * time.Hour,
	})
	service.now = func() time.Time { return now }

	jwks, err := service.PublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("PublicJWKS returned error: %v", err)
	}
	if store.publicKeyListHits == 0 {
		t.Fatal("expected public jwks to read public keys")
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 jwks entry, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].KeyID != "kid-1" {
		t.Fatalf("expected jwks key %q, got %q", "kid-1", jwks.Keys[0].KeyID)
	}
}
