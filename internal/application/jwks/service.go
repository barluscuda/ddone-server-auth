package jwks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"ddone-server-auth/internal/domain/auth"
)

const tokenIDBytes = 16

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

	keys, err := s.store.ListPublicKeys(ctx, now)
	if err != nil {
		return nil, err
	}
	active := activeSigningKey(keys, now)
	if active != nil && hasPreparedSuccessor(keys, *active) {
		return active, nil
	}

	var ensured *auth.SigningKey
	if err := s.store.WithRotationLock(ctx, func(lockCtx context.Context) error {
		if err := s.store.DeleteExpired(lockCtx, now); err != nil {
			return err
		}

		lockedKeys, err := s.store.ListPublicKeys(lockCtx, now)
		if err != nil {
			return err
		}

		lockedActive := activeSigningKey(lockedKeys, now)
		if lockedActive == nil {
			lockedActive, err = s.generateSigningKey(now, now)
			if err != nil {
				return err
			}
			if err := s.store.Create(lockCtx, lockedActive); err != nil {
				return err
			}
			lockedKeys = append(lockedKeys, *lockedActive)
		}

		if !hasPreparedSuccessor(lockedKeys, *lockedActive) {
			nextKey, err := s.generateSigningKey(now, lockedActive.RotatesAt)
			if err != nil {
				return err
			}
			if err := s.store.Create(lockCtx, nextKey); err != nil {
				return err
			}
		}

		ensured = lockedActive
		return nil
	}); err != nil {
		return nil, err
	}

	return ensured, nil
}

func (s *Service) generateSigningKey(createdAt time.Time, activatesAt time.Time) (*auth.SigningKey, error) {
	keyID, err := randomTokenID()
	if err != nil {
		return nil, err
	}

	return s.codec.GenerateSigningKey(
		keyID,
		createdAt,
		activatesAt,
		s.settings.SigningKeyRotation,
		s.settings.SigningKeyRetention,
	)
}

func activeSigningKey(keys []auth.SigningKey, now time.Time) *auth.SigningKey {
	var current *auth.SigningKey
	for i := range keys {
		if !keys[i].IsActiveAt(now) {
			continue
		}
		if current == nil || keys[i].ActivatesAt.After(current.ActivatesAt) {
			key := keys[i]
			current = &key
		}
	}

	return current
}

func hasPreparedSuccessor(keys []auth.SigningKey, current auth.SigningKey) bool {
	for _, key := range keys {
		if key.KeyID == current.KeyID {
			continue
		}
		if key.ActivatesAt.Equal(current.RotatesAt) {
			return true
		}
	}

	return false
}

func (s *Service) IssueAccessToken(
	ctx context.Context,
	userID string,
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
		UserID:   userID,
		Subject:     userID,
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
		if !key.IsPublishedAt(now) {
			continue
		}
		publicKeys = append(publicKeys, s.codec.PublicJWK(key))
	}

	return &auth.JWKSet{Keys: publicKeys}, nil
}

func (s *Service) VerifyAccessToken(ctx context.Context, tokenValue string) (*auth.AccessTokenClaims, error) {
	now := s.now()
	if err := s.store.DeleteExpired(ctx, now); err != nil {
		return nil, err
	}

	keys, err := s.store.ListPublicKeys(ctx, now)
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
