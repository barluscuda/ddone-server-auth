package cache

import (
	"context"
	applogin "ddone-server-auth/internal/application/login"
	apppassword "ddone-server-auth/internal/application/password"
	apptokenmanager "ddone-server-auth/internal/application/tokenmanager"
	"ddone-server-auth/internal/domain/auth"
	"time"

	"github.com/redis/go-redis/v9"
)

type CachedTokenStore struct {
	next   tokenStoreBackend
	client *redis.Client
	cache  jsonCache
}

var _ applogin.TokenStore = (*CachedTokenStore)(nil)
var _ apppassword.TokenRevoker = (*CachedTokenStore)(nil)
var _ apptokenmanager.Store = (*CachedTokenStore)(nil)

type tokenStoreBackend interface {
	applogin.TokenStore
	apppassword.TokenRevoker
	apptokenmanager.Store
	ListByUserID(ctx context.Context, userID string) ([]auth.TokenRecord, error)
}

func NewCachedTokenStore(
	client *redis.Client,
	next tokenStoreBackend,
) *CachedTokenStore {
	return &CachedTokenStore{
		next:   next,
		client: client,
		cache:  newJSONCache(client),
	}
}

func (s *CachedTokenStore) Create(ctx context.Context, token *auth.TokenRecord) error {
	if err := s.next.Create(ctx, token); err != nil {
		return err
	}

	s.cacheToken(ctx, token)
	return nil
}

func (s *CachedTokenStore) GetByTokenHash(
	ctx context.Context,
	tokenHash string,
) (*auth.TokenRecord, error) {
	var cached auth.TokenRecord
	if s.cache.get(ctx, tokenByTokenHashKey(tokenHash), &cached) {
		return &cached, nil
	}

	token, err := s.next.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}

	s.cacheToken(ctx, token)
	return token, nil
}

func (s *CachedTokenStore) GetByID(ctx context.Context, tokenID string) (*auth.TokenRecord, error) {
	var cached auth.TokenRecord
	if s.cache.get(ctx, tokenByIDKey(tokenID), &cached) {
		return &cached, nil
	}

	token, err := s.next.GetByID(ctx, tokenID)
	if err != nil {
		return nil, err
	}

	s.cacheToken(ctx, token)
	return token, nil
}

func (s *CachedTokenStore) ListByUserID(
	ctx context.Context,
	userID string,
) ([]auth.TokenRecord, error) {
	return s.next.ListByUserID(ctx, userID)
}

func (s *CachedTokenStore) Rotate(
	ctx context.Context,
	currentTokenID string,
	replacement *auth.TokenRecord,
	usedAt time.Time,
) error {
	if err := s.next.Rotate(ctx, currentTokenID, replacement, usedAt); err != nil {
		return err
	}

	s.invalidateByTokenID(ctx, currentTokenID)
	s.cacheToken(ctx, replacement)
	return nil
}

func (s *CachedTokenStore) RevokeLineage(
	ctx context.Context,
	rootTokenID string,
	reason string,
	revokedAt time.Time,
) error {
	if err := s.next.RevokeLineage(ctx, rootTokenID, reason, revokedAt); err != nil {
		return err
	}

	s.invalidateLineage(ctx, rootTokenID)
	return nil
}

func (s *CachedTokenStore) RevokeByUserID(
	ctx context.Context,
	userID string,
	reason string,
	revokedAt time.Time,
) error {
	if err := s.next.RevokeByUserID(ctx, userID, reason, revokedAt); err != nil {
		return err
	}

	tokens, err := s.next.ListByUserID(ctx, userID)
	if err != nil {
		return err
	}
	for _, token := range tokens {
		s.invalidateToken(ctx, token)
	}

	return nil
}

func (s *CachedTokenStore) RevokeByID(
	ctx context.Context,
	tokenID string,
	reason string,
	revokedAt time.Time,
) error {
	token, err := s.next.GetByID(ctx, tokenID)
	if err != nil {
		return err
	}
	if err := s.next.RevokeByID(ctx, tokenID, reason, revokedAt); err != nil {
		return err
	}

	s.invalidateToken(ctx, *token)
	return nil
}

func (s *CachedTokenStore) cacheToken(ctx context.Context, token *auth.TokenRecord) {
	if token == nil {
		return
	}

	ttl := time.Until(token.ExpiresAt)
	if ttl <= 0 {
		return
	}

	tokenKey := tokenByTokenHashKey(token.TokenHash)
	idKey := tokenByIDKey(token.ID)
	s.cache.set(ctx, tokenKey, token, ttl)
	s.cache.set(ctx, idKey, token, ttl)

	if s.client == nil {
		return
	}

	rootKey := tokenRootKey(token.RootTokenID)
	if rootKey == "" {
		return
	}

	_ = s.client.SAdd(ctx, rootKey, tokenKey, idKey).Err()
	_ = s.client.Expire(ctx, rootKey, ttl).Err()
}

func (s *CachedTokenStore) invalidateByTokenID(ctx context.Context, tokenID string) {
	if tokenID == "" {
		return
	}

	var cached auth.TokenRecord
	if !s.cache.get(ctx, tokenByIDKey(tokenID), &cached) {
		s.cache.delete(ctx, tokenByIDKey(tokenID))
		return
	}

	s.cache.delete(ctx, tokenByIDKey(tokenID), tokenByTokenHashKey(cached.TokenHash))
	if s.client != nil {
		rootKey := tokenRootKey(cached.RootTokenID)
		if rootKey != "" {
			_ = s.client.SRem(
				ctx,
				rootKey,
				tokenByIDKey(tokenID),
				tokenByTokenHashKey(cached.TokenHash),
			).Err()
		}
	}
}

func (s *CachedTokenStore) invalidateToken(ctx context.Context, token auth.TokenRecord) {
	s.cache.delete(ctx, tokenByIDKey(token.ID), tokenByTokenHashKey(token.TokenHash))
	if s.client != nil {
		rootKey := tokenRootKey(token.RootTokenID)
		if rootKey != "" {
			_ = s.client.SRem(
				ctx,
				rootKey,
				tokenByIDKey(token.ID),
				tokenByTokenHashKey(token.TokenHash),
			).Err()
		}
	}
}

func (s *CachedTokenStore) invalidateLineage(ctx context.Context, rootTokenID string) {
	rootKey := tokenRootKey(rootTokenID)
	if s.client == nil || rootKey == "" {
		return
	}

	keys, err := s.client.SMembers(ctx, rootKey).Result()
	if err == nil && len(keys) > 0 {
		s.cache.delete(ctx, keys...)
	}
	s.cache.delete(ctx, rootKey)
}

func tokenByTokenHashKey(tokenHash string) string {
	return "cache:token:hash:" + tokenHash
}

func tokenByIDKey(tokenID string) string {
	return "cache:token:id:" + tokenID
}

func tokenRootKey(rootTokenID string) string {
	if rootTokenID == "" {
		return ""
	}

	return "cache:token:root:" + rootTokenID
}
