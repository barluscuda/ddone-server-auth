package cache

import (
	"context"
	applogin "ddone-server-auth/internal/application/login"
	"ddone-server-auth/internal/domain/auth"
	"time"

	"github.com/redis/go-redis/v9"
)

type CachedRefreshSessionStore struct {
	next   applogin.RefreshSessionStore
	client *redis.Client
	cache  jsonCache
}

var _ applogin.RefreshSessionStore = (*CachedRefreshSessionStore)(nil)

func NewCachedRefreshSessionStore(
	client *redis.Client,
	next applogin.RefreshSessionStore,
) *CachedRefreshSessionStore {
	return &CachedRefreshSessionStore{
		next:   next,
		client: client,
		cache:  newJSONCache(client),
	}
}

func (s *CachedRefreshSessionStore) Create(ctx context.Context, session *auth.RefreshSession) error {
	if err := s.next.Create(ctx, session); err != nil {
		return err
	}

	s.cacheSession(ctx, session)
	return nil
}

func (s *CachedRefreshSessionStore) GetByTokenHash(
	ctx context.Context,
	tokenHash string,
) (*auth.RefreshSession, error) {
	var cached auth.RefreshSession
	if s.cache.get(ctx, refreshSessionByTokenHashKey(tokenHash), &cached) {
		return &cached, nil
	}

	session, err := s.next.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}

	s.cacheSession(ctx, session)
	return session, nil
}

func (s *CachedRefreshSessionStore) Rotate(
	ctx context.Context,
	currentSessionID string,
	replacement *auth.RefreshSession,
	usedAt time.Time,
) error {
	if err := s.next.Rotate(ctx, currentSessionID, replacement, usedAt); err != nil {
		return err
	}

	s.invalidateBySessionID(ctx, currentSessionID)
	s.cacheSession(ctx, replacement)
	return nil
}

func (s *CachedRefreshSessionStore) RevokeLineage(
	ctx context.Context,
	rootSessionID string,
	reason string,
	revokedAt time.Time,
) error {
	if err := s.next.RevokeLineage(ctx, rootSessionID, reason, revokedAt); err != nil {
		return err
	}

	s.invalidateLineage(ctx, rootSessionID)
	return nil
}

func (s *CachedRefreshSessionStore) cacheSession(ctx context.Context, session *auth.RefreshSession) {
	if session == nil {
		return
	}

	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		return
	}

	tokenKey := refreshSessionByTokenHashKey(session.TokenHash)
	idKey := refreshSessionByIDKey(session.ID)
	s.cache.set(ctx, tokenKey, session, ttl)
	s.cache.set(ctx, idKey, session, ttl)

	if s.client == nil {
		return
	}

	rootKey := refreshSessionRootKey(session.RootSessionID)
	if rootKey == "" {
		return
	}

	_ = s.client.SAdd(ctx, rootKey, tokenKey, idKey).Err()
	_ = s.client.Expire(ctx, rootKey, ttl).Err()
}

func (s *CachedRefreshSessionStore) invalidateBySessionID(ctx context.Context, sessionID string) {
	if sessionID == "" {
		return
	}

	var cached auth.RefreshSession
	if !s.cache.get(ctx, refreshSessionByIDKey(sessionID), &cached) {
		s.cache.delete(ctx, refreshSessionByIDKey(sessionID))
		return
	}

	s.cache.delete(ctx, refreshSessionByIDKey(sessionID), refreshSessionByTokenHashKey(cached.TokenHash))
	if s.client != nil {
		rootKey := refreshSessionRootKey(cached.RootSessionID)
		if rootKey != "" {
			_ = s.client.SRem(
				ctx,
				rootKey,
				refreshSessionByIDKey(sessionID),
				refreshSessionByTokenHashKey(cached.TokenHash),
			).Err()
		}
	}
}

func (s *CachedRefreshSessionStore) invalidateLineage(ctx context.Context, rootSessionID string) {
	rootKey := refreshSessionRootKey(rootSessionID)
	if s.client == nil || rootKey == "" {
		return
	}

	keys, err := s.client.SMembers(ctx, rootKey).Result()
	if err == nil && len(keys) > 0 {
		s.cache.delete(ctx, keys...)
	}
	s.cache.delete(ctx, rootKey)
}

func refreshSessionByTokenHashKey(tokenHash string) string {
	return "cache:refresh_session:token:" + tokenHash
}

func refreshSessionByIDKey(sessionID string) string {
	return "cache:refresh_session:id:" + sessionID
}

func refreshSessionRootKey(rootSessionID string) string {
	if rootSessionID == "" {
		return ""
	}

	return "cache:refresh_session:root:" + rootSessionID
}
