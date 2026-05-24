package login

import (
	"context"
	"ddone-server-auth/internal/domain/auth"
	"ddone-server-auth/internal/domain/user"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type fakeUserLookup struct {
	byID    map[string]*user.User
	byPhone map[string]*user.User
}

func (r *fakeUserLookup) GetByID(_ context.Context, id string) (*user.User, error) {
	if userModel, ok := r.byID[id]; ok {
		return userModel, nil
	}
	return nil, user.ErrUserNotFound
}

func (r *fakeUserLookup) GetByPhoneNumber(_ context.Context, phoneNumber string) (*user.User, error) {
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

type fakeLoginRateLimiter struct {
	counters map[string]int64
	locks    map[string]bool
}

func (f *fakeLoginRateLimiter) GetCounter(_ context.Context, key string) (int64, error) {
	if f.counters == nil {
		return 0, nil
	}
	return f.counters[key], nil
}

func (f *fakeLoginRateLimiter) IncrementCounter(_ context.Context, key string, _ time.Duration) (int64, error) {
	if f.counters == nil {
		f.counters = map[string]int64{}
	}
	f.counters[key]++
	return f.counters[key], nil
}

func (f *fakeLoginRateLimiter) DeleteCounter(_ context.Context, key string) error {
	if f.counters != nil {
		delete(f.counters, key)
	}
	return nil
}

func (f *fakeLoginRateLimiter) IsLocked(_ context.Context, key string) (bool, error) {
	if f.locks == nil {
		return false, nil
	}
	return f.locks[key], nil
}

func (f *fakeLoginRateLimiter) Lock(_ context.Context, key string, _ time.Duration) error {
	if f.locks == nil {
		f.locks = map[string]bool{}
	}
	f.locks[key] = true
	return nil
}

func TestLoginCreatesTokenRecord(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("secretpass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	userModel := &user.User{
		ID:           "user-1",
		PhoneNumber:  "+8562012345678",
		PasswordHash: string(passwordHash),
	}
	users := &fakeUserLookup{
		byPhone: map[string]*user.User{"+8562012345678": userModel},
		byID:    map[string]*user.User{"user-1": userModel},
	}
	tokenRecords := &fakeTokenStore{}
	loginSessions := &fakeLoginSessionStore{}
	service := NewService(users, tokenRecords, loginSessions, &fakeAccessTokenIssuer{}, &fakeLoginRateLimiter{}, Settings{
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

	userModel := &user.User{
		ID:           "user-1",
		PhoneNumber:  "+8562012345678",
		PasswordHash: string(passwordHash),
	}
	users := &fakeUserLookup{
		byID: map[string]*user.User{"user-1": userModel},
	}
	service := NewService(users, &fakeTokenStore{
		tokensByHash: map[string]*auth.TokenRecord{
			hashRefreshToken("refresh-token"): {
				ID:          "token-1",
				UserID:      "user-1",
				RootTokenID: "token-1",
				ReplacedAt:  ptrTime(time.Date(2026, 5, 23, 9, 0, 0, 0, time.UTC)),
				ExpiresAt:   time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			},
		},
	}, &fakeLoginSessionStore{}, &fakeAccessTokenIssuer{}, &fakeLoginRateLimiter{}, Settings{
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

	userModel := &user.User{
		ID:           "user-1",
		PhoneNumber:  "+8562012345678",
		PasswordHash: string(passwordHash),
	}
	users := &fakeUserLookup{
		byID: map[string]*user.User{"user-1": userModel},
	}
	tokenRecords := &fakeTokenStore{
		tokensByHash: map[string]*auth.TokenRecord{
			hashRefreshToken("refresh-token"): {
				ID:          "token-1",
				UserID:      "user-1",
				RootTokenID: "root-token",
				TokenHash:   hashRefreshToken("refresh-token"),
				ExpiresAt:   time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			},
		},
	}
	service := NewService(users, tokenRecords, &fakeLoginSessionStore{}, &fakeAccessTokenIssuer{}, &fakeLoginRateLimiter{}, Settings{
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

	userModel := &user.User{
		ID:           "user-1",
		PhoneNumber:  "+8562012345678",
		PasswordHash: string(passwordHash),
	}
	users := &fakeUserLookup{
		byPhone: map[string]*user.User{"+8562012345678": userModel},
		byID:    map[string]*user.User{"user-1": userModel},
	}
	loginSessions := &fakeLoginSessionStore{}
	service := NewService(users, &fakeTokenStore{}, loginSessions, &fakeAccessTokenIssuer{}, &fakeLoginRateLimiter{}, Settings{
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

func TestLoginRateLimitsRepeatedInvalidCredentials(t *testing.T) {
	users := &fakeUserLookup{}
	limiter := &fakeLoginRateLimiter{}
	service := NewService(users, &fakeTokenStore{}, &fakeLoginSessionStore{}, &fakeAccessTokenIssuer{}, limiter, Settings{
		RefreshTokenTTL:     30 * 24 * time.Hour,
		LoginSessionTTL:     30 * 24 * time.Hour,
		FailedAttemptWindow: 5 * time.Minute,
		MaxAttempts:         2,
		LockoutDuration:     15 * time.Minute,
	})

	_, err := service.Login(context.Background(), LoginInput{
		PhoneNumber: "+8562012345678",
		Password:    "wrong-pass",
	})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials on first failure, got %v", err)
	}

	_, err = service.Login(context.Background(), LoginInput{
		PhoneNumber: "+8562012345678",
		Password:    "wrong-pass",
	})
	if !errors.Is(err, ErrLoginRateLimited) {
		t.Fatalf("expected rate limit on second failure, got %v", err)
	}

	_, err = service.Login(context.Background(), LoginInput{
		PhoneNumber: "+8562012345678",
		Password:    "wrong-pass",
	})
	if !errors.Is(err, ErrLoginRateLimited) {
		t.Fatalf("expected rate limit while counter is active, got %v", err)
	}
	if !limiter.locks[loginLockKey("+8562012345678")] {
		t.Fatal("expected login failures to lock the account")
	}
}

func ptrTime(value time.Time) *time.Time {
	return &value
}
