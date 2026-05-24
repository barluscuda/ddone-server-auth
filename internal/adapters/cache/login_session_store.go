package cache

import (
	"context"
	applogin "ddone-server-auth/internal/application/login"
	apppassword "ddone-server-auth/internal/application/password"
	appsession "ddone-server-auth/internal/application/session"
	"ddone-server-auth/internal/domain/auth"
	"time"

	"github.com/redis/go-redis/v9"
)

type loginSessionStoreBackend interface {
	applogin.LoginSessionStore
	appsession.Store
	apppassword.LoginSessionRevoker
}

type CachedLoginSessionStore struct {
	next        loginSessionStoreBackend
	client      *redis.Client
	cache       jsonCache
	userListTTL time.Duration
}

var _ applogin.LoginSessionStore = (*CachedLoginSessionStore)(nil)
var _ appsession.Store = (*CachedLoginSessionStore)(nil)
var _ apppassword.LoginSessionRevoker = (*CachedLoginSessionStore)(nil)

func NewCachedLoginSessionStore(
	client *redis.Client,
	next loginSessionStoreBackend,
	userListTTL time.Duration,
) *CachedLoginSessionStore {
	return &CachedLoginSessionStore{
		next:        next,
		client:      client,
		cache:       newJSONCache(client),
		userListTTL: userListTTL,
	}
}

func (s *CachedLoginSessionStore) Create(ctx context.Context, session *auth.LoginSession) error {
	if err := s.next.Create(ctx, session); err != nil {
		return err
	}

	s.cacheSession(ctx, session)
	s.invalidateUserSessions(ctx, session.UserID)
	return nil
}

func (s *CachedLoginSessionStore) GetByTokenHash(
	ctx context.Context,
	tokenHash string,
) (*auth.LoginSession, error) {
	var cached auth.LoginSession
	if s.cache.get(ctx, loginSessionByTokenHashKey(tokenHash), &cached) {
		return &cached, nil
	}

	session, err := s.next.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}

	s.cacheSession(ctx, session)
	return session, nil
}

func (s *CachedLoginSessionStore) GetByID(ctx context.Context, sessionID string) (*auth.LoginSession, error) {
	var cached auth.LoginSession
	if s.cache.get(ctx, loginSessionByIDKey(sessionID), &cached) {
		return &cached, nil
	}

	session, err := s.next.GetByID(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	s.cacheSession(ctx, session)
	return session, nil
}

func (s *CachedLoginSessionStore) GetByCurrentAccessToken(
	ctx context.Context,
	accessToken string,
) (*auth.LoginSession, error) {
	session, err := s.next.GetByCurrentAccessToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	s.cacheSession(ctx, session)
	return session, nil
}

func (s *CachedLoginSessionStore) UpdateAccessToken(
	ctx context.Context,
	sessionID string,
	accessToken *auth.AccessToken,
) error {
	if err := s.next.UpdateAccessToken(ctx, sessionID, accessToken); err != nil {
		return err
	}

	var cached auth.LoginSession
	if s.cache.get(ctx, loginSessionByIDKey(sessionID), &cached) {
		cached.CurrentAccessToken = accessToken.Token
		cached.CurrentAccessExpires = accessToken.ExpiresAt
		s.cacheSession(ctx, &cached)
		s.invalidateUserSessions(ctx, cached.UserID)
	}
	return nil
}

func (s *CachedLoginSessionStore) ListByUserID(
	ctx context.Context,
	userID string,
) ([]auth.LoginSession, error) {
	if s.userListTTL > 0 {
		var cached []auth.LoginSession
		if s.cache.get(ctx, loginSessionsByUserKey(userID), &cached) {
			return cached, nil
		}
	}

	sessions, err := s.next.ListByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if s.userListTTL > 0 {
		s.cache.set(ctx, loginSessionsByUserKey(userID), sessions, s.userListTTL)
	}
	for i := range sessions {
		session := sessions[i]
		s.cacheSession(ctx, &session)
	}

	return sessions, nil
}

func (s *CachedLoginSessionStore) RevokeByUserID(
	ctx context.Context,
	userID string,
	reason string,
	revokedAt time.Time,
) error {
	if err := s.next.RevokeByUserID(ctx, userID, reason, revokedAt); err != nil {
		return err
	}

	sessions, err := s.next.ListByUserID(ctx, userID)
	if err != nil {
		return err
	}

	for _, session := range sessions {
		s.cache.delete(ctx, loginSessionByIDKey(session.ID), loginSessionByTokenHashKey(session.TokenHash))
	}
	s.invalidateUserSessions(ctx, userID)
	return nil
}

func (s *CachedLoginSessionStore) RevokeByID(
	ctx context.Context,
	sessionID string,
	reason string,
	revokedAt time.Time,
) error {
	session, err := s.next.GetByID(ctx, sessionID)
	if err != nil {
		return err
	}
	if err := s.next.RevokeByID(ctx, sessionID, reason, revokedAt); err != nil {
		return err
	}

	s.cache.delete(ctx, loginSessionByIDKey(session.ID), loginSessionByTokenHashKey(session.TokenHash))
	s.invalidateUserSessions(ctx, session.UserID)
	return nil
}

func (s *CachedLoginSessionStore) RevokeByUserIDExcept(
	ctx context.Context,
	userID string,
	excludedSessionID string,
	reason string,
	revokedAt time.Time,
) error {
	sessions, err := s.next.ListByUserID(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.next.RevokeByUserIDExcept(ctx, userID, excludedSessionID, reason, revokedAt); err != nil {
		return err
	}

	for _, session := range sessions {
		if session.ID == excludedSessionID {
			continue
		}
		s.cache.delete(ctx, loginSessionByIDKey(session.ID), loginSessionByTokenHashKey(session.TokenHash))
	}
	s.invalidateUserSessions(ctx, userID)
	return nil
}

func (s *CachedLoginSessionStore) invalidateUserSessions(ctx context.Context, userID string) {
	s.cache.delete(ctx, loginSessionsByUserKey(userID))
}

func loginSessionsByUserKey(userID string) string {
	return "cache:login_sessions:user:" + userID
}

func (s *CachedLoginSessionStore) cacheSession(ctx context.Context, session *auth.LoginSession) {
	if session == nil {
		return
	}

	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		return
	}

	s.cache.set(ctx, loginSessionByTokenHashKey(session.TokenHash), session, ttl)
	s.cache.set(ctx, loginSessionByIDKey(session.ID), session, ttl)
}

func loginSessionByTokenHashKey(tokenHash string) string {
	return "cache:login_session:token:" + tokenHash
}

func loginSessionByIDKey(sessionID string) string {
	return "cache:login_session:id:" + sessionID
}
