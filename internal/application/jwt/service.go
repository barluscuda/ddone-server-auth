package jwt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"ddone-server-auth/internal/domain/auth"
)

const tokenIDBytes = 16

type Service struct {
	keys     SigningKeyProvider
	reader   SigningKeyReader
	codec    TokenCodec
	settings Settings
	now      func() time.Time
}

func NewService(
	keys SigningKeyProvider,
	reader SigningKeyReader,
	codec TokenCodec,
	settings Settings,
) *Service {
	return &Service{
		keys:     keys,
		reader:   reader,
		codec:    codec,
		settings: settings,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) IssueAccessToken(
	ctx context.Context,
	userID string,
	phoneNumber string,
) (*auth.AccessToken, error) {
	key, err := s.keys.EnsureActiveSigningKey(ctx)
	if err != nil {
		return nil, err
	}

	now := s.now()
	tokenID, err := randomTokenID()
	if err != nil {
		return nil, err
	}

	return s.codec.IssueAccessToken(key, auth.AccessTokenClaims{
		Issuer:      s.settings.Issuer,
		UserID:      userID,
		Subject:     userID,
		Audience:    s.settings.Audience,
		JWTID:       tokenID,
		PhoneNumber: phoneNumber,
		IssuedAt:    now,
		NotBefore:   now,
		ExpiresAt:   now.Add(s.settings.AccessTokenTTL),
	})
}

func (s *Service) VerifyAccessToken(ctx context.Context, tokenValue string) (*auth.AccessTokenClaims, error) {
	now := s.now()
	if err := s.reader.DeleteExpired(ctx, now); err != nil {
		return nil, err
	}

	keys, err := s.reader.ListPublicKeys(ctx, now)
	if err != nil {
		return nil, err
	}

	return s.codec.VerifyAccessToken(
		tokenValue,
		keys,
		s.settings.Issuer,
		s.settings.Audience,
		now,
	)
}

func randomTokenID() (string, error) {
	randomBytes := make([]byte, tokenIDBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(randomBytes), nil
}
