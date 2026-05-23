package jwks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"ddone-server-auth/internal/domain/auth"
)

const tokenIDBytes = 16

type UseCase interface {
	EnsureActiveSigningKey(ctx context.Context) (*auth.SigningKey, error)
	IssueAccessToken(ctx context.Context, subject string, phoneNumber string) (*auth.AccessToken, error)
	PublicJWKS(ctx context.Context) (*auth.JWKSet, error)
}

type Settings struct {
	Issuer              string
	Audience            string
	AccessTokenTTL      time.Duration
	SigningKeyRotation  time.Duration
	SigningKeyRetention time.Duration
}

type Service struct {
	store    SigningKeyStore
	codec    TokenCodec
	settings Settings
	now      func() time.Time
}

func NewService(store SigningKeyStore, codec TokenCodec, settings Settings) *Service {
	return &Service{
		store:    store,
		codec:    codec,
		settings: settings,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) EnsureActiveSigningKey(ctx context.Context) (*auth.SigningKey, error) {
	now := s.now()
	if err := s.store.DeleteExpired(ctx, now); err != nil {
		return nil, err
	}

	active, err := s.store.GetActive(ctx, now)
	if err == nil && now.Before(active.RotatesAt) {
		return active, nil
	}
	if err != nil && !errors.Is(err, auth.ErrSigningKeyNotFound) {
		return nil, err
	}

	var ensured *auth.SigningKey
	if err := s.store.WithRotationLock(ctx, func(lockCtx context.Context) error {
		if err := s.store.DeleteExpired(lockCtx, now); err != nil {
			return err
		}

		lockedActive, activeErr := s.store.GetActive(lockCtx, now)
		if activeErr == nil && now.Before(lockedActive.RotatesAt) {
			ensured = lockedActive
			return nil
		}
		if activeErr != nil && !errors.Is(activeErr, auth.ErrSigningKeyNotFound) {
			return activeErr
		}

		if activeErr == nil {
			if err := s.store.Retire(lockCtx, lockedActive.KeyID); err != nil {
				return err
			}
		}

		keyID, err := randomTokenID()
		if err != nil {
			return err
		}

		newKey, err := s.codec.GenerateSigningKey(
			keyID,
			now,
			s.settings.SigningKeyRotation,
			s.settings.SigningKeyRetention,
		)
		if err != nil {
			return err
		}
		if err := s.store.Create(lockCtx, newKey); err != nil {
			return err
		}

		ensured = newKey
		return nil
	}); err != nil {
		return nil, err
	}

	return ensured, nil
}

func (s *Service) IssueAccessToken(
	ctx context.Context,
	subject string,
	phoneNumber string,
) (*auth.AccessToken, error) {
	key, err := s.EnsureActiveSigningKey(ctx)
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
		Subject:     subject,
		Audience:    s.settings.Audience,
		JWTID:       tokenID,
		PhoneNumber: phoneNumber,
		IssuedAt:    now,
		NotBefore:   now,
		ExpiresAt:   now.Add(s.settings.AccessTokenTTL),
	})
}

func (s *Service) PublicJWKS(ctx context.Context) (*auth.JWKSet, error) {
	now := s.now()
	if err := s.store.DeleteExpired(ctx, now); err != nil {
		return nil, err
	}

	keys, err := s.store.ListPublicKeys(ctx, now)
	if err != nil {
		return nil, err
	}

	publicKeys := make([]auth.JWK, 0, len(keys))
	for _, key := range keys {
		publicKeys = append(publicKeys, s.codec.PublicJWK(key))
	}

	return &auth.JWKSet{Keys: publicKeys}, nil
}

func randomTokenID() (string, error) {
	randomBytes := make([]byte, tokenIDBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(randomBytes), nil
}
