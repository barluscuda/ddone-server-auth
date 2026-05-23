package login

import (
	"context"
	"ddone-server-auth/internal/domain/account"
	"ddone-server-auth/internal/domain/auth"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type fakeAccountLookup struct {
	byID    map[string]*account.AccountModel
	byPhone map[string]*account.AccountModel
}

func (r *fakeAccountLookup) GetByID(_ context.Context, id string) (*account.AccountModel, error) {
	if accountModel, ok := r.byID[id]; ok {
		return accountModel, nil
	}
	return nil, account.ErrAccountNotFound
}

func (r *fakeAccountLookup) GetByPhoneNumber(_ context.Context, phoneNumber string) (*account.AccountModel, error) {
	if accountModel, ok := r.byPhone[phoneNumber]; ok {
		return accountModel, nil
	}
	return nil, account.ErrAccountNotFound
}

type fakeRefreshSessionStore struct {
	created          *auth.RefreshSession
	sessionsByHash   map[string]*auth.RefreshSession
	rotatedCurrentID string
	replacement      *auth.RefreshSession
	revokedRootID    string
	rotateErr        error
}

func (s *fakeRefreshSessionStore) Create(_ context.Context, session *auth.RefreshSession) error {
	s.created = session
	return nil
}

func (s *fakeRefreshSessionStore) GetByTokenHash(_ context.Context, tokenHash string) (*auth.RefreshSession, error) {
	if session, ok := s.sessionsByHash[tokenHash]; ok {
		return session, nil
	}
	return nil, auth.ErrRefreshSessionNotFound
}

func (s *fakeRefreshSessionStore) Rotate(
	_ context.Context,
	currentSessionID string,
	replacement *auth.RefreshSession,
	_ time.Time,
) error {
	if s.rotateErr != nil {
		return s.rotateErr
	}
	s.rotatedCurrentID = currentSessionID
	s.replacement = replacement
	return nil
}

func (s *fakeRefreshSessionStore) RevokeLineage(
	_ context.Context,
	rootSessionID string,
	_ string,
	_ time.Time,
) error {
	s.revokedRootID = rootSessionID
	return nil
}

type fakeLoginSessionStore struct {
	created              *auth.LoginSession
	sessionsByHash       map[string]*auth.LoginSession
	updatedSessionID     string
	updatedAccessToken   *auth.AccessToken
	updateAccessTokenErr error
}

func (s *fakeLoginSessionStore) Create(_ context.Context, session *auth.LoginSession) error {
	s.created = session
	return nil
}

func (s *fakeLoginSessionStore) GetByTokenHash(_ context.Context, tokenHash string) (*auth.LoginSession, error) {
	if session, ok := s.sessionsByHash[tokenHash]; ok {
		return session, nil
	}
	return nil, auth.ErrLoginSessionNotFound
}

func (s *fakeLoginSessionStore) UpdateAccessToken(
	_ context.Context,
	sessionID string,
	accessToken *auth.AccessToken,
) error {
	if s.updateAccessTokenErr != nil {
		return s.updateAccessTokenErr
	}
	s.updatedSessionID = sessionID
	s.updatedAccessToken = accessToken
	return nil
}

type fakeAccessTokenIssuer struct{}

func (i *fakeAccessTokenIssuer) IssueAccessToken(_ context.Context, accountID string, phoneNumber string) (*auth.AccessToken, error) {
	return &auth.AccessToken{
		Token:     "access-token",
		TokenType: "Bearer",
		ExpiresAt: time.Now().UTC().Add(15 * time.Minute),
		ExpiresIn: 900,
		KeyID:     accountID + ":" + phoneNumber,
	}, nil
}

func TestLoginCreatesRefreshSession(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("secretpass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	accountModel := &account.AccountModel{
		ID:           "account-1",
		PhoneNumber:  "2012345678",
		PasswordHash: string(passwordHash),
	}
	accounts := &fakeAccountLookup{
		byPhone: map[string]*account.AccountModel{"2012345678": accountModel},
		byID:    map[string]*account.AccountModel{"account-1": accountModel},
	}
	sessions := &fakeRefreshSessionStore{}
	loginSessions := &fakeLoginSessionStore{}
	service := NewService(accounts, sessions, loginSessions, &fakeAccessTokenIssuer{}, Settings{
		RefreshTokenTTL: 30 * 24 * time.Hour,
		LoginSessionTTL: 30 * 24 * time.Hour,
	})
	now := time.Date(2026, 5, 23, 10, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }

	result, err := service.Login(context.Background(), LoginInput{
		PhoneNumber: "+8562012345678",
		Password:    "secretpass",
		ClientIP:    "127.0.0.1",
		UserAgent:   "test-agent",
	})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}

	if result.RefreshToken == "" {
		t.Fatal("expected refresh token")
	}
	if sessions.created == nil {
		t.Fatal("expected session to be created")
	}
	if sessions.created.RootSessionID != sessions.created.ID {
		t.Fatalf("expected root session id to match session id, got %q and %q", sessions.created.RootSessionID, sessions.created.ID)
	}
}

func TestRefreshRevokesLineageOnReplay(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("secretpass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	accountModel := &account.AccountModel{
		ID:           "account-1",
		PhoneNumber:  "2012345678",
		PasswordHash: string(passwordHash),
	}
	accounts := &fakeAccountLookup{
		byID: map[string]*account.AccountModel{"account-1": accountModel},
	}
	service := NewService(accounts, &fakeRefreshSessionStore{
		sessionsByHash: map[string]*auth.RefreshSession{
			hashRefreshToken("refresh-token"): {
				ID:            "session-1",
				AccountID:     "account-1",
				RootSessionID: "session-1",
				ReplacedAt:    ptrTime(time.Date(2026, 5, 23, 9, 0, 0, 0, time.UTC)),
				ExpiresAt:     time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			},
		},
	}, &fakeLoginSessionStore{}, &fakeAccessTokenIssuer{}, Settings{
		RefreshTokenTTL: 30 * 24 * time.Hour,
		LoginSessionTTL: 30 * 24 * time.Hour,
	})
	service.now = func() time.Time { return time.Date(2026, 5, 23, 10, 0, 0, 0, time.UTC) }

	_, err = service.Refresh(context.Background(), RefreshInput{RefreshToken: "refresh-token"})
	if !errors.Is(err, auth.ErrRefreshTokenReplayDetected) {
		t.Fatalf("expected replay error, got %v", err)
	}
}

func TestLoginSessionCreatesPersistentSession(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("secretpass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	accountModel := &account.AccountModel{
		ID:           "account-1",
		PhoneNumber:  "2012345678",
		PasswordHash: string(passwordHash),
	}
	accounts := &fakeAccountLookup{
		byPhone: map[string]*account.AccountModel{"2012345678": accountModel},
		byID:    map[string]*account.AccountModel{"account-1": accountModel},
	}
	loginSessions := &fakeLoginSessionStore{}
	service := NewService(accounts, &fakeRefreshSessionStore{}, loginSessions, &fakeAccessTokenIssuer{}, Settings{
		RefreshTokenTTL: 30 * 24 * time.Hour,
		LoginSessionTTL: 30 * 24 * time.Hour,
	})
	now := time.Date(2026, 5, 23, 10, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }

	result, err := service.LoginSession(context.Background(), LoginInput{
		PhoneNumber: "+8562012345678",
		Password:    "secretpass",
		ClientIP:    "127.0.0.1",
		UserAgent:   "test-agent",
	})
	if err != nil {
		t.Fatalf("LoginSession returned error: %v", err)
	}

	if result.SessionToken == "" {
		t.Fatal("expected session token")
	}
	if loginSessions.created == nil {
		t.Fatal("expected login session to be created")
	}
	if loginSessions.created.CurrentAccessToken == "" {
		t.Fatal("expected current access token to be stored")
	}
	if got, want := loginSessions.created.ExpiresAt, now.Add(30*24*time.Hour); !got.Equal(want) {
		t.Fatalf("expected login session expiry %v, got %v", want, got)
	}
}

func TestSessionTokenReturnsStoredAccessTokenWhenStillValid(t *testing.T) {
	loginSessions := &fakeLoginSessionStore{
		sessionsByHash: map[string]*auth.LoginSession{
			hashSessionToken("session-token"): {
				ID:                   "session-1",
				AccountID:            "account-1",
				TokenHash:            hashSessionToken("session-token"),
				CurrentAccessToken:   "stored-access-token",
				CurrentAccessExpires: time.Date(2026, 5, 23, 10, 15, 0, 0, time.UTC),
				ExpiresAt:            time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC),
			},
		},
	}
	service := NewService(&fakeAccountLookup{}, &fakeRefreshSessionStore{}, loginSessions, &fakeAccessTokenIssuer{}, Settings{
		RefreshTokenTTL: 30 * 24 * time.Hour,
		LoginSessionTTL: 30 * 24 * time.Hour,
	})
	service.now = func() time.Time { return time.Date(2026, 5, 23, 10, 0, 0, 0, time.UTC) }

	result, err := service.SessionToken(context.Background(), SessionTokenInput{SessionToken: "session-token"})
	if err != nil {
		t.Fatalf("SessionToken returned error: %v", err)
	}

	if result.AccessToken.Token != "stored-access-token" {
		t.Fatalf("expected stored access token, got %q", result.AccessToken.Token)
	}
	if loginSessions.updatedSessionID != "" {
		t.Fatal("expected stored token to be returned without update")
	}
}

func TestSessionTokenRefreshesExpiredAccessToken(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("secretpass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	accountModel := &account.AccountModel{
		ID:           "account-1",
		PhoneNumber:  "2012345678",
		PasswordHash: string(passwordHash),
	}
	accounts := &fakeAccountLookup{
		byID: map[string]*account.AccountModel{"account-1": accountModel},
	}
	loginSessions := &fakeLoginSessionStore{
		sessionsByHash: map[string]*auth.LoginSession{
			hashSessionToken("session-token"): {
				ID:                   "session-1",
				AccountID:            "account-1",
				TokenHash:            hashSessionToken("session-token"),
				CurrentAccessToken:   "expired-access-token",
				CurrentAccessExpires: time.Date(2026, 5, 23, 9, 59, 0, 0, time.UTC),
				ExpiresAt:            time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC),
			},
		},
	}
	service := NewService(accounts, &fakeRefreshSessionStore{}, loginSessions, &fakeAccessTokenIssuer{}, Settings{
		RefreshTokenTTL: 30 * 24 * time.Hour,
		LoginSessionTTL: 30 * 24 * time.Hour,
	})
	service.now = func() time.Time { return time.Date(2026, 5, 23, 10, 0, 0, 0, time.UTC) }

	result, err := service.SessionToken(context.Background(), SessionTokenInput{SessionToken: "session-token"})
	if err != nil {
		t.Fatalf("SessionToken returned error: %v", err)
	}

	if result.AccessToken.Token != "access-token" {
		t.Fatalf("expected fresh access token, got %q", result.AccessToken.Token)
	}
	if loginSessions.updatedSessionID != "session-1" {
		t.Fatalf("expected updated session id %q, got %q", "session-1", loginSessions.updatedSessionID)
	}
	if loginSessions.updatedAccessToken == nil {
		t.Fatal("expected updated access token to be stored")
	}
}

func TestSessionTokenRejectsExpiredLoginSession(t *testing.T) {
	loginSessions := &fakeLoginSessionStore{
		sessionsByHash: map[string]*auth.LoginSession{
			hashSessionToken("session-token"): {
				ID:                   "session-1",
				AccountID:            "account-1",
				TokenHash:            hashSessionToken("session-token"),
				CurrentAccessToken:   "stored-access-token",
				CurrentAccessExpires: time.Date(2026, 5, 23, 10, 15, 0, 0, time.UTC),
				ExpiresAt:            time.Date(2026, 5, 23, 9, 59, 0, 0, time.UTC),
			},
		},
	}
	service := NewService(&fakeAccountLookup{}, &fakeRefreshSessionStore{}, loginSessions, &fakeAccessTokenIssuer{}, Settings{
		RefreshTokenTTL: 30 * 24 * time.Hour,
		LoginSessionTTL: 30 * 24 * time.Hour,
	})
	service.now = func() time.Time { return time.Date(2026, 5, 23, 10, 0, 0, 0, time.UTC) }

	_, err := service.SessionToken(context.Background(), SessionTokenInput{SessionToken: "session-token"})
	if !errors.Is(err, auth.ErrLoginSessionExpired) {
		t.Fatalf("expected login session expired error, got %v", err)
	}
	if loginSessions.updatedSessionID != "" {
		t.Fatal("expected expired login session to avoid access-token refresh")
	}
}

func ptrTime(value time.Time) *time.Time {
	return &value
}
