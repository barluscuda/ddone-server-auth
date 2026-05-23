package cache

import (
	"context"
	appaccountmanager "ddone-server-auth/internal/application/accountmanager"
	applogin "ddone-server-auth/internal/application/login"
	apppassword "ddone-server-auth/internal/application/password"
	"ddone-server-auth/internal/domain/auth"
	"time"

	"github.com/redis/go-redis/v9"
)

type loginSessionStoreBackend interface {
	applogin.LoginSessionStore
	appaccountmanager.SessionReader
	apppassword.LoginSessionRevoker
}

type CachedLoginSessionStore struct {
	next           loginSessionStoreBackend
	client         *redis.Client
	cache          jsonCache
	accountListTTL time.Duration
}

var _ applogin.LoginSessionStore = (*CachedLoginSessionStore)(nil)
var _ appaccountmanager.SessionReader = (*CachedLoginSessionStore)(nil)
var _ apppassword.LoginSessionRevoker = (*CachedLoginSessionStore)(nil)

func NewCachedLoginSessionStore(
	client *redis.Client,
	next loginSessionStoreBackend,
	accountListTTL time.Duration,
) *CachedLoginSessionStore {
	return &CachedLoginSessionStore{
		next:           next,
		client:         client,
		cache:          newJSONCache(client),
		accountListTTL: accountListTTL,
	}
}

func (s *CachedLoginSessionStore) Create(ctx context.Context, session *auth.LoginSession) error {
	if err := s.next.Create(ctx, session); err != nil {
		return err
	}

	s.cacheSession(ctx, session)
	s.invalidateAccountSessions(ctx, session.AccountID)
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
		s.invalidateAccountSessions(ctx, cached.AccountID)
	}
	return nil
}

func (s *CachedLoginSessionStore) ListByAccountID(
	ctx context.Context,
	accountID string,
) ([]auth.LoginSession, error) {
	if s.accountListTTL > 0 {
		var cached []auth.LoginSession
		if s.cache.get(ctx, loginSessionsByAccountKey(accountID), &cached) {
			return cached, nil
		}
	}

	sessions, err := s.next.ListByAccountID(ctx, accountID)
	if err != nil {
		return nil, err
	}

	if s.accountListTTL > 0 {
		s.cache.set(ctx, loginSessionsByAccountKey(accountID), sessions, s.accountListTTL)
	}
	for i := range sessions {
		session := sessions[i]
		s.cacheSession(ctx, &session)
	}

	return sessions, nil
}

func (s *CachedLoginSessionStore) RevokeByAccountID(
	ctx context.Context,
	accountID string,
	reason string,
	revokedAt time.Time,
) error {
	if err := s.next.RevokeByAccountID(ctx, accountID, reason, revokedAt); err != nil {
		return err
	}

	sessions, err := s.next.ListByAccountID(ctx, accountID)
	if err != nil {
		return err
	}

	for _, session := range sessions {
		s.cache.delete(ctx, loginSessionByIDKey(session.ID), loginSessionByTokenHashKey(session.TokenHash))
	}
	s.invalidateAccountSessions(ctx, accountID)
	return nil
}

func (s *CachedLoginSessionStore) invalidateAccountSessions(ctx context.Context, accountID string) {
	s.cache.delete(ctx, loginSessionsByAccountKey(accountID))
}

func loginSessionsByAccountKey(accountID string) string {
	return "cache:login_sessions:account:" + accountID
}

func (s *CachedLoginSessionStore) cacheSession(ctx context.Context, session *auth.LoginSession) {
	if session == nil {
		return
	}

	ttl := time.Until(session.CurrentAccessExpires)
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
