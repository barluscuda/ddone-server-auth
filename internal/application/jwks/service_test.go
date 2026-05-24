package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"ddone-server-auth/internal/adapters/token"
	"ddone-server-auth/internal/domain/auth"
)

type fakeSigningKeyStore struct {
	keys      []auth.SigningKey
	deletedAt []time.Time
}

func (s *fakeSigningKeyStore) Create(_ context.Context, key *auth.SigningKey) error {
	s.keys = append(s.keys, *key)
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
	generatedKeys  []*auth.SigningKey
	issuedClaims   auth.AccessTokenClaims
	verifiedClaims *auth.AccessTokenClaims
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

func (c *fakeTokenCodec) VerifyAccessToken(
	_ string,
	_ []auth.SigningKey,
	_ string,
	_ string,
	_ time.Time,
) (*auth.AccessTokenClaims, error) {
	if c.verifiedClaims == nil {
		return nil, auth.ErrInvalidAccessToken
	}

	return c.verifiedClaims, nil
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

func TestIssueAccessTokenUsesActiveKey(t *testing.T) {
	now := time.Date(2026, 5, 23, 10, 0, 0, 0, time.UTC)
	store := &fakeSigningKeyStore{
		keys: []auth.SigningKey{{
			KeyID:         "kid-1",
			Algorithm:     "ES256",
			Curve:         "P-256",
			Status:        auth.SigningKeyStatusActive,
			CreatedAt:     now.Add(-time.Hour),
			ActivatesAt:   now.Add(-time.Hour),
			RotatesAt:     now.Add(time.Hour),
			RetiresAt:     now.Add(90 * 24 * time.Hour),
			PublicX:       "x",
			PublicY:       "y",
			PrivateKeyPEM: "pem",
		}},
	}
	codec := &fakeTokenCodec{}
	service := NewService(store, codec, Settings{
		Issuer:              "issuer",
		Audience:            "audience",
		AccessTokenTTL:      15 * time.Minute,
		SigningKeyRotation:  90 * 24 * time.Hour,
		SigningKeyRetention: 180 * 24 * time.Hour,
	})
	service.now = func() time.Time { return now }

	token, err := service.IssueAccessToken(context.Background(), "user-1", "2012345678")
	if err != nil {
		t.Fatalf("IssueAccessToken returned error: %v", err)
	}

	if token.Token != "signed-token" {
		t.Fatalf("expected signed token, got %q", token.Token)
	}
	if token.KeyID != "kid-1" {
		t.Fatalf("expected access token to use existing key %q, got %q", "kid-1", token.KeyID)
	}
	if codec.issuedClaims.Subject != "user-1" {
		t.Fatalf("expected subject %q, got %q", "user-1", codec.issuedClaims.Subject)
	}
	if codec.issuedClaims.UserID != "user-1" {
		t.Fatalf("expected user id %q, got %q", "user-1", codec.issuedClaims.UserID)
	}
	if codec.issuedClaims.PhoneNumber != "2012345678" {
		t.Fatalf("expected phone number %q, got %q", "2012345678", codec.issuedClaims.PhoneNumber)
	}
	if len(store.keys) != 2 {
		t.Fatalf("expected successor key to be created, got %d keys", len(store.keys))
	}
}

func TestIssueAccessTokenVerifiesAgainstPublishedJWKS(t *testing.T) {
	now := time.Date(2026, 5, 23, 10, 0, 0, 0, time.UTC)
	store := &fakeSigningKeyStore{}
	codec := token.NewES256Codec()
	service := NewService(store, codec, Settings{
		Issuer:              "issuer",
		Audience:            "audience",
		AccessTokenTTL:      15 * time.Minute,
		SigningKeyRotation:  90 * 24 * time.Hour,
		SigningKeyRetention: 180 * 24 * time.Hour,
	})
	service.now = func() time.Time { return now }

	issued, err := service.IssueAccessToken(context.Background(), "user-1", "2012345678")
	if err != nil {
		t.Fatalf("IssueAccessToken returned error: %v", err)
	}

	jwks, err := service.PublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("PublicJWKS returned error: %v", err)
	}
	if len(jwks.Keys) != 2 {
		t.Fatalf("expected 2 jwks entries, got %d", len(jwks.Keys))
	}

	headerSegment, payloadSegment, signatureSegment := splitJWTForVerify(t, issued.Token)
	signature := decodeJWTSegment(t, signatureSegment)
	if len(signature) != 64 {
		t.Fatalf("expected 64-byte JOSE signature, got %d bytes", len(signature))
	}
	publicJWK, ok := findJWK(jwks.Keys, issued.KeyID)
	if !ok {
		t.Fatalf("expected issued kid %q to be present in jwks", issued.KeyID)
	}

	sum := sha256.Sum256([]byte(headerSegment + "." + payloadSegment))
	publicKey := publicKeyFromJWK(t, publicJWK)
	if !ecdsa.Verify(publicKey, sum[:], decodeSignaturePart(signature[:32]), decodeSignaturePart(signature[32:])) {
		t.Fatal("expected issued token to verify against published jwk")
	}
}

func TestVerifyAccessTokenDelegatesToCodec(t *testing.T) {
	now := time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC)
	store := &fakeSigningKeyStore{}
	codec := &fakeTokenCodec{
		verifiedClaims: &auth.AccessTokenClaims{
			UserID: "user-1",
			Subject:   "user-1",
			Audience:  "audience",
			Issuer:    "issuer",
			ExpiresAt: now.Add(time.Minute),
		},
	}
	service := NewService(store, codec, Settings{
		Issuer:              "issuer",
		Audience:            "audience",
		AccessTokenTTL:      15 * time.Minute,
		SigningKeyRotation:  90 * 24 * time.Hour,
		SigningKeyRetention: 180 * 24 * time.Hour,
	})
	service.now = func() time.Time { return now }

	claims, err := service.VerifyAccessToken(context.Background(), "token")
	if err != nil {
		t.Fatalf("VerifyAccessToken returned error: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("expected subject %q, got %q", "user-1", claims.Subject)
	}
	if claims.UserID != "user-1" {
		t.Fatalf("expected user id %q, got %q", "user-1", claims.UserID)
	}
}

func findJWK(keys []auth.JWK, keyID string) (auth.JWK, bool) {
	for _, key := range keys {
		if key.KeyID == keyID {
			return key, true
		}
	}

	return auth.JWK{}, false
}

func splitJWTForVerify(t *testing.T, tokenValue string) (string, string, string) {
	t.Helper()

	parts := strings.Split(tokenValue, ".")
	if len(parts) != 3 {
		t.Fatalf("expected compact JWT with 3 segments, got %d", len(parts))
	}

	return parts[0], parts[1], parts[2]
}

func decodeJWTSegment(t *testing.T, segment string) []byte {
	t.Helper()

	payload, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("decode jwt segment: %v", err)
	}

	return payload
}

func publicKeyFromJWK(t *testing.T, key auth.JWK) *ecdsa.PublicKey {
	t.Helper()

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     decodeSignaturePart(decodeJWTSegment(t, key.X)),
		Y:     decodeSignaturePart(decodeJWTSegment(t, key.Y)),
	}
}

func decodeSignaturePart(raw []byte) *big.Int {
	return new(big.Int).SetBytes(raw)
}
