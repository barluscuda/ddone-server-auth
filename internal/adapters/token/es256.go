package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"ddone-server-auth/internal/domain/auth"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

type ES256Codec struct{}

func NewES256Codec() *ES256Codec {
	return &ES256Codec{}
}

func (c *ES256Codec) GenerateSigningKey(
	keyID string,
	now time.Time,
	rotationInterval time.Duration,
	retentionWindow time.Duration,
) (*auth.SigningKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})

	return &auth.SigningKey{
		KeyID:         keyID,
		Algorithm:     "ES256",
		Curve:         "P-256",
		PublicX:       encodeCoordinate(privateKey.PublicKey.X),
		PublicY:       encodeCoordinate(privateKey.PublicKey.Y),
		PrivateKeyPEM: string(privateKeyPEM),
		Status:        auth.SigningKeyStatusActive,
		CreatedAt:     now,
		ActivatesAt:   now,
		RotatesAt:     now.Add(rotationInterval),
		RetiresAt:     now.Add(retentionWindow),
	}, nil
}

func (c *ES256Codec) IssueAccessToken(
	key *auth.SigningKey,
	claims auth.AccessTokenClaims,
) (*auth.AccessToken, error) {
	privateKey, err := parsePrivateKeyPEM(key.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}

	header := map[string]string{
		"alg": "ES256",
		"kid": key.KeyID,
		"typ": "JWT",
	}
	payload := map[string]any{
		"iss": claims.Issuer,
		"sub": claims.Subject,
		"aud": claims.Audience,
		"jti": claims.JWTID,
		"iat": claims.IssuedAt.Unix(),
		"nbf": claims.NotBefore.Unix(),
		"exp": claims.ExpiresAt.Unix(),
	}
	if claims.PhoneNumber != "" {
		payload["phone_number"] = claims.PhoneNumber
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	headerSegment := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadSegment := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerSegment + "." + payloadSegment

	sum := sha256.Sum256([]byte(signingInput))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, sum[:])
	if err != nil {
		return nil, err
	}

	tokenValue := signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
	return &auth.AccessToken{
		Token:     tokenValue,
		TokenType: "Bearer",
		ExpiresAt: claims.ExpiresAt,
		ExpiresIn: int64(claims.ExpiresAt.Sub(claims.IssuedAt).Seconds()),
		KeyID:     key.KeyID,
	}, nil
}

func (c *ES256Codec) PublicJWK(key auth.SigningKey) auth.JWK {
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

func parsePrivateKeyPEM(raw string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("decode private key pem: missing pem block")
	}

	keyValue, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	privateKey, ok := keyValue.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("decode private key pem: unexpected key type %T", keyValue)
	}

	return privateKey, nil
}

func encodeCoordinate(value *big.Int) string {
	bytes := value.Bytes()
	if len(bytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(bytes):], bytes)
		bytes = padded
	}

	return base64.RawURLEncoding.EncodeToString(bytes)
}
