package login

import (
	"context"
	"ddone-server-auth/internal/domain/user"
	"ddone-server-auth/internal/domain/auth"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type fakeUserLookup struct {
	byID    map[string]*user.UserModel
	byPhone map[string]*user.UserModel
}

func (r *fakeUserLookup) GetByID(_ context.Context, id string) (*user.UserModel, error) {
	if userModel, ok := r.byID[id]; ok {
		return userModel, nil
	}
	return nil, user.ErrUserNotFound
}

func (r *fakeUserLookup) GetByPhoneNumber(_ context.Context, phoneNumber string) (*user.UserModel, error) {
	if userModel, ok := r.byPhone[phoneNumber]; ok {
		return userModel, nil
	}
	return nil, user.ErrUserNotFound
}

type fakeTokenStore struct {
	created          *auth.TokenRecord
	tokensByHash     map[string]*auth.TokenRecord
	rotatedCurrentID string
	replacement      *auth.TokenRecord
	revokedRootID    string
	rotateErr        error
}

func (s *fakeTokenStore) Create(_ context.Context, tokenRecord *auth.TokenRecord) error {
	s.created = tokenRecord
	return nil
}

func (s *fakeTokenStore) GetByTokenHash(_ context.Context, tokenHash string) (*auth.TokenRecord, error) {
	if tokenRecord, ok := s.tokensByHash[tokenHash]; ok {
		return tokenRecord, nil
	}
	return nil, auth.ErrTokenNotFound
}

func (s *fakeTokenStore) Rotate(
	_ context.Context,
	currentTokenID string,
	replacement *auth.TokenRecord,
	_ time.Time,
) error {
	if s.rotateErr != nil {
		return s.rotateErr
	}
	s.rotatedCurrentID = currentTokenID
	s.replacement = replacement
	return nil
}

func (s *fakeTokenStore) RevokeLineage(
	_ context.Context,
	rootTokenID string,
	_ string,
	_ time.Time,
) error {
	s.revokedRootID = rootTokenID
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

func (i *fakeAccessTokenIssuer) IssueAccessToken(_ context.Context, userID string, phoneNumber string) (*auth.AccessToken, error) {
	return &auth.AccessToken{
		Token:     "access-token",
		TokenType: "Bearer",
		ExpiresAt: time.Now().UTC().Add(15 * time.Minute),
		ExpiresIn: 900,
		KeyID:     userID + ":" + phoneNumber,
	}, nil
}

func TestLoginCreatesTokenRecord(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("secretpass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	userModel := &user.UserModel{
		ID:           "user-1",
		PhoneNumber:  "2012345678",
		PasswordHash: string(passwordHash),
	}
	users := &fakeUserLookup{
		byPhone: map[string]*user.UserModel{"2012345678": userModel},
		byID:    map[string]*user.UserModel{"user-1": userModel},
	}
	tokenRecords := &fakeTokenStore{}
	loginSessions := &fakeLoginSessionStore{}
	service := NewService(users, tokenRecords, loginSessions, &fakeAccessTokenIssuer{}, Settings{
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
	if tokenRecords.created == nil {
		t.Fatal("expected token record to be created")
	}
	if tokenRecords.created.RootTokenID != tokenRecords.created.ID {
		t.Fatalf("expected root token id to match token id, got %q and %q", tokenRecords.created.RootTokenID, tokenRecords.created.ID)
	}
}

func TestRefreshRevokesLineageOnReplay(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("secretpass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	userModel := &user.UserModel{
		ID:           "user-1",
		PhoneNumber:  "2012345678",
		PasswordHash: string(passwordHash),
	}
	users := &fakeUserLookup{
		byID: map[string]*user.UserModel{"user-1": userModel},
	}
	service := NewService(users, &fakeTokenStore{
		tokensByHash: map[string]*auth.TokenRecord{
			hashRefreshToken("refresh-token"): {
				ID:          "token-1",
				UserID:   "user-1",
				RootTokenID: "token-1",
				ReplacedAt:  ptrTime(time.Date(2026, 5, 23, 9, 0, 0, 0, time.UTC)),
				ExpiresAt:   time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
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

func TestRefreshRotatesTokenWithLineage(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("secretpass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	userModel := &user.UserModel{
		ID:           "user-1",
		PhoneNumber:  "2012345678",
		PasswordHash: string(passwordHash),
	}
	users := &fakeUserLookup{
		byID: map[string]*user.UserModel{"user-1": userModel},
	}
	tokenRecords := &fakeTokenStore{
		tokensByHash: map[string]*auth.TokenRecord{
			hashRefreshToken("refresh-token"): {
				ID:          "token-1",
				UserID:   "user-1",
				RootTokenID: "root-token",
				TokenHash:   hashRefreshToken("refresh-token"),
				ExpiresAt:   time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			},
		},
	}
	service := NewService(users, tokenRecords, &fakeLoginSessionStore{}, &fakeAccessTokenIssuer{}, Settings{
		RefreshTokenTTL: 30 * 24 * time.Hour,
		LoginSessionTTL: 30 * 24 * time.Hour,
	})
	service.now = func() time.Time { return time.Date(2026, 5, 23, 10, 0, 0, 0, time.UTC) }

	result, err := service.Refresh(context.Background(), RefreshInput{
		RefreshToken: "refresh-token",
		ClientIP:     "127.0.0.1",
		UserAgent:    "test-agent",
	})
	if err != nil {
		t.Fatalf("Refresh returned error: %v", err)
	}
	if result.RefreshToken == "" {
		t.Fatal("expected replacement refresh token")
	}
	if tokenRecords.rotatedCurrentID != "token-1" {
		t.Fatalf("expected rotated token id %q, got %q", "token-1", tokenRecords.rotatedCurrentID)
	}
	if tokenRecords.replacement == nil {
		t.Fatal("expected replacement token record")
	}
	if tokenRecords.replacement.RootTokenID != "root-token" {
		t.Fatalf("expected root token id %q, got %q", "root-token", tokenRecords.replacement.RootTokenID)
	}
	if tokenRecords.replacement.ParentTokenID == nil || *tokenRecords.replacement.ParentTokenID != "token-1" {
		t.Fatalf("expected parent token id %q, got %v", "token-1", tokenRecords.replacement.ParentTokenID)
	}
}

func TestLoginSessionCreatesPersistentSession(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("secretpass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	userModel := &user.UserModel{
		ID:           "user-1",
		PhoneNumber:  "2012345678",
		PasswordHash: string(passwordHash),
	}
	users := &fakeUserLookup{
		byPhone: map[string]*user.UserModel{"2012345678": userModel},
		byID:    map[string]*user.UserModel{"user-1": userModel},
	}
	loginSessions := &fakeLoginSessionStore{}
	service := NewService(users, &fakeTokenStore{}, loginSessions, &fakeAccessTokenIssuer{}, Settings{
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
				UserID:            "user-1",
				TokenHash:            hashSessionToken("session-token"),
				CurrentAccessToken:   "stored-access-token",
				CurrentAccessExpires: time.Date(2026, 5, 23, 10, 15, 0, 0, time.UTC),
				ExpiresAt:            time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC),
			},
		},
	}
	service := NewService(&fakeUserLookup{}, &fakeTokenStore{}, loginSessions, &fakeAccessTokenIssuer{}, Settings{
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

	userModel := &user.UserModel{
		ID:           "user-1",
		PhoneNumber:  "2012345678",
		PasswordHash: string(passwordHash),
	}
	users := &fakeUserLookup{
		byID: map[string]*user.UserModel{"user-1": userModel},
	}
	loginSessions := &fakeLoginSessionStore{
		sessionsByHash: map[string]*auth.LoginSession{
			hashSessionToken("session-token"): {
				ID:                   "session-1",
				UserID:            "user-1",
				TokenHash:            hashSessionToken("session-token"),
				CurrentAccessToken:   "expired-access-token",
				CurrentAccessExpires: time.Date(2026, 5, 23, 9, 59, 0, 0, time.UTC),
				ExpiresAt:            time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC),
			},
		},
	}
	service := NewService(users, &fakeTokenStore{}, loginSessions, &fakeAccessTokenIssuer{}, Settings{
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
	if loginSessions.created != nil {
		t.Fatal("expected server session token refresh to replace token without creating a new session")
	}
}

func TestSessionTokenRejectsExpiredLoginSession(t *testing.T) {
	loginSessions := &fakeLoginSessionStore{
		sessionsByHash: map[string]*auth.LoginSession{
			hashSessionToken("session-token"): {
				ID:                   "session-1",
				UserID:            "user-1",
				TokenHash:            hashSessionToken("session-token"),
				CurrentAccessToken:   "stored-access-token",
				CurrentAccessExpires: time.Date(2026, 5, 23, 10, 15, 0, 0, time.UTC),
				ExpiresAt:            time.Date(2026, 5, 23, 9, 59, 0, 0, time.UTC),
			},
		},
	}
	service := NewService(&fakeUserLookup{}, &fakeTokenStore{}, loginSessions, &fakeAccessTokenIssuer{}, Settings{
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
