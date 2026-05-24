package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"ddone-server-auth/internal/domain/auth"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	json "github.com/bytedance/sonic"
)

type ES256Codec struct{}

func NewES256Codec() *ES256Codec {
	return &ES256Codec{}
}

var (
	p256Order     = elliptic.P256().Params().N
	p256HalfOrder = new(big.Int).Rsh(new(big.Int).Set(p256Order), 1)
)

func (c *ES256Codec) GenerateSigningKey(
	keyID string,
	createdAt time.Time,
	activatesAt time.Time,
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
		Status:        signingKeyStatus(createdAt, activatesAt),
		CreatedAt:     createdAt,
		ActivatesAt:   activatesAt,
		RotatesAt:     activatesAt.Add(rotationInterval),
		RetiresAt:     activatesAt.Add(retentionWindow),
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
	if claims.UserID != "" {
		payload["userId"] = claims.UserID
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
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, sum[:])
	if err != nil {
		return nil, err
	}
	s = canonicalECDSAS(s)
	signature := joseSignature(r, s)

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

func (c *ES256Codec) VerifyAccessToken(
	tokenValue string,
	keys []auth.SigningKey,
	expectedIssuer string,
	expectedAudience string,
	now time.Time,
) (*auth.AccessTokenClaims, error) {
	headerSegment, payloadSegment, signatureSegment, err := splitCompactJWT(tokenValue)
	if err != nil {
		return nil, auth.ErrInvalidAccessToken
	}

	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Type      string `json:"typ"`
	}
	if err := decodeJWTSegment(headerSegment, &header); err != nil {
		return nil, auth.ErrInvalidAccessToken
	}
	if header.Algorithm != "ES256" ||
		strings.TrimSpace(header.KeyID) == "" ||
		(header.Type != "" && !strings.EqualFold(header.Type, "JWT")) {
		return nil, auth.ErrInvalidAccessToken
	}

	signingKey, ok := findSigningKey(keys, header.KeyID)
	if !ok {
		return nil, auth.ErrInvalidAccessToken
	}
	if signingKey.Algorithm != "ES256" || signingKey.Curve != "P-256" || now.Before(signingKey.ActivatesAt) || !signingKey.IsPublishedAt(now) {
		return nil, auth.ErrInvalidAccessToken
	}

	signature, err := base64.RawURLEncoding.DecodeString(signatureSegment)
	if err != nil || len(signature) != 64 {
		return nil, auth.ErrInvalidAccessToken
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !validECDSASignatureValues(r, s) {
		return nil, auth.ErrInvalidAccessToken
	}

	sum := sha256.Sum256([]byte(headerSegment + "." + payloadSegment))
	publicKey, err := publicKeyFromSigningKey(signingKey)
	if err != nil {
		return nil, auth.ErrInvalidAccessToken
	}
	if !ecdsa.Verify(publicKey, sum[:], r, s) {
		return nil, auth.ErrInvalidAccessToken
	}

	var payload struct {
		Issuer       string `json:"iss"`
		UserID       string `json:"userId"`
		LegacyUserID string `json:"accountId"`
		Subject      string `json:"sub"`
		Audience     string `json:"aud"`
		JWTID        string `json:"jti"`
		IssuedAt     int64  `json:"iat"`
		NotBefore    int64  `json:"nbf"`
		ExpiresAt    int64  `json:"exp"`
		PhoneNumber  string `json:"phone_number"`
	}
	if err := decodeJWTSegment(payloadSegment, &payload); err != nil {
		return nil, auth.ErrInvalidAccessToken
	}
	if payload.Issuer != expectedIssuer ||
		payload.Audience != expectedAudience ||
		strings.TrimSpace(payload.Subject) == "" ||
		strings.TrimSpace(payload.JWTID) == "" {
		return nil, auth.ErrInvalidAccessToken
	}

	issuedAt := time.Unix(payload.IssuedAt, 0).UTC()
	notBefore := time.Unix(payload.NotBefore, 0).UTC()
	expiresAt := time.Unix(payload.ExpiresAt, 0).UTC()
	if payload.IssuedAt <= 0 ||
		payload.NotBefore <= 0 ||
		payload.ExpiresAt <= 0 ||
		expiresAt.Before(issuedAt) ||
		now.Before(notBefore) ||
		!now.Before(expiresAt) {
		return nil, auth.ErrInvalidAccessToken
	}
	userID := payload.UserID
	if userID == "" {
		userID = payload.LegacyUserID
	}
	if userID == "" {
		userID = payload.Subject
	}

	return &auth.AccessTokenClaims{
		Issuer:      payload.Issuer,
		UserID:      userID,
		Subject:     payload.Subject,
		Audience:    payload.Audience,
		JWTID:       payload.JWTID,
		PhoneNumber: payload.PhoneNumber,
		IssuedAt:    issuedAt,
		NotBefore:   notBefore,
		ExpiresAt:   expiresAt,
	}, nil
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
	return base64.RawURLEncoding.EncodeToString(paddedBytes(value, 32))
}

func joseSignature(r *big.Int, s *big.Int) []byte {
	signature := make([]byte, 64)
	copy(signature[:32], paddedBytes(r, 32))
	copy(signature[32:], paddedBytes(s, 32))
	return signature
}

func canonicalECDSAS(s *big.Int) *big.Int {
	if s.Cmp(p256HalfOrder) <= 0 {
		return s
	}

	return new(big.Int).Sub(p256Order, s)
}

func validECDSASignatureValues(r *big.Int, s *big.Int) bool {
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(p256Order) >= 0 || s.Cmp(p256Order) >= 0 {
		return false
	}

	return s.Cmp(p256HalfOrder) <= 0
}

func paddedBytes(value *big.Int, width int) []byte {
	bytes := value.Bytes()
	if len(bytes) < width {
		padded := make([]byte, width)
		copy(padded[width-len(bytes):], bytes)
		bytes = padded
	}
	return bytes
}

func signingKeyStatus(createdAt time.Time, activatesAt time.Time) string {
	if activatesAt.After(createdAt) {
		return auth.SigningKeyStatusScheduled
	}

	return auth.SigningKeyStatusActive
}

func splitCompactJWT(tokenValue string) (string, string, string, error) {
	parts := strings.Split(strings.TrimSpace(tokenValue), ".")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid jwt segments")
	}

	return parts[0], parts[1], parts[2], nil
}

func decodeJWTSegment(segment string, target any) error {
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}

	return json.Unmarshal(decoded, target)
}

func findSigningKey(keys []auth.SigningKey, keyID string) (auth.SigningKey, bool) {
	for _, key := range keys {
		if key.KeyID == keyID {
			return key, true
		}
	}

	return auth.SigningKey{}, false
}

func publicKeyFromSigningKey(key auth.SigningKey) (*ecdsa.PublicKey, error) {
	xValue, err := base64.RawURLEncoding.DecodeString(key.PublicX)
	if err != nil {
		return nil, err
	}
	yValue, err := base64.RawURLEncoding.DecodeString(key.PublicY)
	if err != nil {
		return nil, err
	}

	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xValue),
		Y:     new(big.Int).SetBytes(yValue),
	}
	if !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return nil, fmt.Errorf("public key is not on curve")
	}

	return publicKey, nil
}
