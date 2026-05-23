package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"ddone-server-auth/internal/domain/auth"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestIssueAccessTokenUsesJOSESignatureFormat(t *testing.T) {
	codec := NewES256Codec()
	now := time.Date(2026, 5, 23, 10, 0, 0, 0, time.UTC)

	key, err := codec.GenerateSigningKey("kid-1", now, now, 90*24*time.Hour, 180*24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateSigningKey returned error: %v", err)
	}

	tokenValue, err := codec.IssueAccessToken(key, auth.AccessTokenClaims{
		Issuer:      "issuer",
		Subject:     "account-1",
		Audience:    "audience",
		JWTID:       "token-1",
		PhoneNumber: "2012345678",
		IssuedAt:    now,
		NotBefore:   now,
		ExpiresAt:   now.Add(15 * time.Minute),
	})
	if err != nil {
		t.Fatalf("IssueAccessToken returned error: %v", err)
	}

	headerSegment, payloadSegment, signatureSegment := splitJWT(t, tokenValue.Token)
	signature := decodeSegment(t, signatureSegment)
	if len(signature) != 64 {
		t.Fatalf("expected 64-byte JOSE signature, got %d bytes", len(signature))
	}

	signingInput := headerSegment + "." + payloadSegment
	sum := sha256.Sum256([]byte(signingInput))
	publicKey := jwkPublicKey(t, key.PublicX, key.PublicY)
	if !ecdsa.Verify(publicKey, sum[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		t.Fatal("expected signature to verify with signing key public coordinates")
	}
}

func TestIssueAccessTokenSerializesExpectedHeaderAndClaims(t *testing.T) {
	codec := NewES256Codec()
	now := time.Date(2026, 5, 23, 10, 0, 0, 0, time.UTC)

	key, err := codec.GenerateSigningKey("kid-1", now, now, 90*24*time.Hour, 180*24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateSigningKey returned error: %v", err)
	}

	tokenValue, err := codec.IssueAccessToken(key, auth.AccessTokenClaims{
		Issuer:    "issuer",
		Subject:   "account-1",
		Audience:  "audience",
		JWTID:     "token-1",
		IssuedAt:  now,
		NotBefore: now,
		ExpiresAt: now.Add(15 * time.Minute),
	})
	if err != nil {
		t.Fatalf("IssueAccessToken returned error: %v", err)
	}

	headerSegment, payloadSegment, _ := splitJWT(t, tokenValue.Token)

	var header map[string]string
	if err := json.Unmarshal(decodeSegment(t, headerSegment), &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if header["alg"] != "ES256" || header["kid"] != "kid-1" || header["typ"] != "JWT" {
		t.Fatalf("unexpected header: %#v", header)
	}

	var payload map[string]any
	if err := json.Unmarshal(decodeSegment(t, payloadSegment), &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload["iss"] != "issuer" || payload["sub"] != "account-1" || payload["aud"] != "audience" || payload["jti"] != "token-1" {
		t.Fatalf("unexpected payload identifiers: %#v", payload)
	}
	if _, ok := payload["phone_number"]; ok {
		t.Fatal("expected phone_number claim to be omitted when empty")
	}
}

func splitJWT(t *testing.T, tokenValue string) (string, string, string) {
	t.Helper()

	parts := strings.Split(tokenValue, ".")
	if len(parts) != 3 {
		t.Fatalf("expected compact JWT with 3 segments, got %d", len(parts))
	}

	return parts[0], parts[1], parts[2]
}

func decodeSegment(t *testing.T, segment string) []byte {
	t.Helper()

	payload, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("decode segment: %v", err)
	}

	return payload
}

func jwkPublicKey(t *testing.T, xValue string, yValue string) *ecdsa.PublicKey {
	t.Helper()

	xBytes := decodeSegment(t, xValue)
	yBytes := decodeSegment(t, yValue)

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
}
