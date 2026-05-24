package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"ddone-server-auth/internal/domain/auth"
	"ddone-server-auth/internal/domain/user"
)

type fakeStore struct {
	byID               map[string]auth.LoginSession
	byUser             map[string][]auth.LoginSession
	revokedSessionID   string
	revokedReason      string
	revokedAt          time.Time
	revokedUserID      string
	revokedExceptID    string
	revokedAllReason   string
	revokedAllAt       time.Time
	revokeByIDErr      error
	revokeOthersErr    error
	revokeByUserErr    error
	updatedSessionID   string
	updatedAccessToken *auth.AccessToken
	updatedExpiresAt   time.Time
}

func (f *fakeStore) GetByID(_ context.Context, sessionID string) (*auth.LoginSession, error) {
	session, ok := f.byID[sessionID]
	if !ok {
		return nil, auth.ErrLoginSessionNotFound
	}

	return cloneSession(session), nil
}

func (f *fakeStore) ListByUserID(_ context.Context, userID string) ([]auth.LoginSession, error) {
	sessions := f.byUser[userID]
	result := make([]auth.LoginSession, 0, len(sessions))
	for _, session := range sessions {
		result = append(result, *cloneSession(session))
	}

	return result, nil
}

func (f *fakeStore) RefreshAccessToken(
	_ context.Context,
	sessionID string,
	accessToken *auth.AccessToken,
	sessionExpiresAt time.Time,
) error {
	f.updatedSessionID = sessionID
	f.updatedAccessToken = accessToken
	f.updatedExpiresAt = sessionExpiresAt
	return nil
}

func (f *fakeStore) RevokeByID(_ context.Context, sessionID string, reason string, revokedAt time.Time) error {
	if f.revokeByIDErr != nil {
		return f.revokeByIDErr
	}

	f.revokedSessionID = sessionID
	f.revokedReason = reason
	f.revokedAt = revokedAt
	return nil
}

func (f *fakeStore) RevokeByUserIDExcept(
	_ context.Context,
	userID string,
	excludedSessionID string,
	reason string,
	revokedAt time.Time,
) error {
	if f.revokeOthersErr != nil {
		return f.revokeOthersErr
	}

	f.revokedUserID = userID
	f.revokedExceptID = excludedSessionID
	f.revokedAllReason = reason
	f.revokedAllAt = revokedAt
	return nil
}

func (f *fakeStore) RevokeByUserID(_ context.Context, userID string, reason string, revokedAt time.Time) error {
	if f.revokeByUserErr != nil {
		return f.revokeByUserErr
	}

	f.revokedUserID = userID
	f.revokedAllReason = reason
	f.revokedAllAt = revokedAt
	return nil
}

type fakeUserLookup struct {
	byID map[string]string
}

func (f *fakeUserLookup) GetByID(_ context.Context, id string) (*user.UserModel, error) {
	phoneNumber, ok := f.byID[id]
	if !ok {
		return nil, user.ErrUserNotFound
	}

	return &user.UserModel{ID: id, PhoneNumber: phoneNumber}, nil
}

type fakeAccessTokenIssuer struct {
	token string
}

func (f *fakeAccessTokenIssuer) IssueAccessToken(_ context.Context, userID string, phoneNumber string) (*auth.AccessToken, error) {
	return &auth.AccessToken{
		Token:     f.token,
		TokenType: "Bearer",
		ExpiresAt: time.Date(2026, 5, 24, 2, 45, 0, 0, time.UTC),
		ExpiresIn: 900,
		KeyID:     userID + ":" + phoneNumber,
	}, nil
}

func TestListReturnsOwnedSessions(t *testing.T) {
	service := NewService(&fakeStore{
		byUser: map[string][]auth.LoginSession{
			"user-1": {
				{
					ID:                   "session-1",
					UserID:               "user-1",
					ClientIP:             "127.0.0.1",
					UserAgent:            "test-agent",
					CurrentAccessExpires: time.Date(2026, 5, 24, 1, 0, 0, 0, time.UTC),
					CreatedAt:            time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
				},
			},
		},
	}, &fakeUserLookup{}, &fakeAccessTokenIssuer{}, Settings{LoginSessionTTL: 30 * 24 * time.Hour})

	result, err := service.List(context.Background(), ListInput{UserID: "user-1"})
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 session, got %d", len(result))
	}
	if result[0].ID != "session-1" {
		t.Fatalf("expected session id %q, got %q", "session-1", result[0].ID)
	}
}

func TestListRequiresAuthenticatedUser(t *testing.T) {
	service := NewService(&fakeStore{}, &fakeUserLookup{}, &fakeAccessTokenIssuer{}, Settings{LoginSessionTTL: 30 * 24 * time.Hour})

	_, err := service.List(context.Background(), ListInput{})
	if !errors.Is(err, ErrAuthenticatedUserRequired) {
		t.Fatalf("expected ErrAuthenticatedUserRequired, got %v", err)
	}
}

func TestRevokeRejectsSessionFromAnotherUser(t *testing.T) {
	service := NewService(&fakeStore{
		byID: map[string]auth.LoginSession{
			"session-1": {
				ID:     "session-1",
				UserID: "user-2",
			},
		},
	}, &fakeUserLookup{}, &fakeAccessTokenIssuer{}, Settings{LoginSessionTTL: 30 * 24 * time.Hour})

	err := service.Revoke(context.Background(), RevokeInput{
		UserID:    "user-1",
		SessionID: "session-1",
	})
	if !errors.Is(err, auth.ErrLoginSessionNotFound) {
		t.Fatalf("expected ErrLoginSessionNotFound, got %v", err)
	}
}

func TestRevokeMarksSessionByID(t *testing.T) {
	store := &fakeStore{
		byID: map[string]auth.LoginSession{
			"session-1": {
				ID:        "session-1",
				UserID:    "user-1",
				ExpiresAt: time.Date(2026, 6, 24, 2, 0, 0, 0, time.UTC),
			},
		},
	}
	service := NewService(store, &fakeUserLookup{}, &fakeAccessTokenIssuer{}, Settings{LoginSessionTTL: 30 * 24 * time.Hour})
	service.now = func() time.Time { return time.Date(2026, 5, 24, 2, 0, 0, 0, time.UTC) }

	err := service.Revoke(context.Background(), RevokeInput{
		UserID:    "user-1",
		SessionID: "session-1",
	})
	if err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}
	if store.revokedSessionID != "session-1" {
		t.Fatalf("expected revoked session id %q, got %q", "session-1", store.revokedSessionID)
	}
	if store.revokedReason != reasonSessionRevoked {
		t.Fatalf("expected revoke reason %q, got %q", reasonSessionRevoked, store.revokedReason)
	}
}

func TestCurrentReturnsSessionMatchedBySessionID(t *testing.T) {
	service := NewService(&fakeStore{
		byID: map[string]auth.LoginSession{
			"session-1": {
				ID:        "session-1",
				UserID:    "user-1",
				ExpiresAt: time.Date(2026, 6, 24, 2, 0, 0, 0, time.UTC),
			},
		},
	}, &fakeUserLookup{}, &fakeAccessTokenIssuer{}, Settings{LoginSessionTTL: 30 * 24 * time.Hour})

	result, err := service.Current(context.Background(), CurrentInput{
		UserID:    "user-1",
		SessionID: "session-1",
	})
	if err != nil {
		t.Fatalf("Current returned error: %v", err)
	}
	if result.ID != "session-1" {
		t.Fatalf("expected session id %q, got %q", "session-1", result.ID)
	}
}

func TestIssueAccessTokenReturnsStoredTokenWhenStillValid(t *testing.T) {
	store := &fakeStore{
		byID: map[string]auth.LoginSession{
			"session-1": {
				ID:                   "session-1",
				UserID:               "user-1",
				CurrentAccessToken:   "stored-access-token",
				CurrentAccessExpires: time.Date(2026, 5, 24, 2, 40, 0, 0, time.UTC),
				ExpiresAt:            time.Date(2026, 6, 24, 2, 0, 0, 0, time.UTC),
			},
		},
	}
	service := NewService(store, &fakeUserLookup{}, &fakeAccessTokenIssuer{token: "fresh-access-token"}, Settings{LoginSessionTTL: 30 * 24 * time.Hour})
	service.now = func() time.Time { return time.Date(2026, 5, 24, 2, 30, 0, 0, time.UTC) }

	result, err := service.IssueAccessToken(context.Background(), IssueAccessTokenInput{
		UserID:    "user-1",
		SessionID: "session-1",
	})
	if err != nil {
		t.Fatalf("IssueAccessToken returned error: %v", err)
	}
	if result.AccessToken.Token != "stored-access-token" {
		t.Fatalf("expected stored access token, got %q", result.AccessToken.Token)
	}
	if result.Refreshed {
		t.Fatal("expected existing access token to avoid refresh")
	}
	if !store.updatedExpiresAt.IsZero() {
		t.Fatalf("expected session expiry to remain unchanged, got %v", store.updatedExpiresAt)
	}
}

func TestIssueAccessTokenRefreshesExpiredAccessToken(t *testing.T) {
	store := &fakeStore{
		byID: map[string]auth.LoginSession{
			"session-1": {
				ID:                   "session-1",
				UserID:               "user-1",
				CurrentAccessToken:   "expired-access-token",
				CurrentAccessExpires: time.Date(2026, 5, 24, 2, 29, 0, 0, time.UTC),
				ExpiresAt:            time.Date(2026, 6, 24, 2, 0, 0, 0, time.UTC),
			},
		},
	}
	service := NewService(store, &fakeUserLookup{
		byID: map[string]string{"user-1": "2012345678"},
	}, &fakeAccessTokenIssuer{token: "fresh-access-token"}, Settings{LoginSessionTTL: 30 * 24 * time.Hour})
	now := time.Date(2026, 5, 24, 2, 30, 0, 0, time.UTC)
	service.now = func() time.Time { return now }

	result, err := service.IssueAccessToken(context.Background(), IssueAccessTokenInput{
		UserID:    "user-1",
		SessionID: "session-1",
	})
	if err != nil {
		t.Fatalf("IssueAccessToken returned error: %v", err)
	}
	if result.AccessToken.Token != "fresh-access-token" {
		t.Fatalf("expected refreshed access token, got %q", result.AccessToken.Token)
	}
	if !result.Refreshed {
		t.Fatal("expected expired access token to trigger refresh")
	}
	if store.updatedSessionID != "session-1" {
		t.Fatalf("expected updated session id %q, got %q", "session-1", store.updatedSessionID)
	}
	if store.updatedAccessToken == nil {
		t.Fatal("expected updated access token to be stored")
	}
	if got, want := store.updatedExpiresAt, now.Add(30*24*time.Hour); !got.Equal(want) {
		t.Fatalf("expected session expiry %v, got %v", want, got)
	}
}

func TestRevokeOthersKeepsCurrentSession(t *testing.T) {
	store := &fakeStore{
		byID: map[string]auth.LoginSession{
			"session-1": {
				ID:        "session-1",
				UserID:    "user-1",
				ExpiresAt: time.Date(2026, 6, 24, 2, 0, 0, 0, time.UTC),
			},
		},
	}
	service := NewService(store, &fakeUserLookup{}, &fakeAccessTokenIssuer{}, Settings{LoginSessionTTL: 30 * 24 * time.Hour})
	service.now = func() time.Time { return time.Date(2026, 5, 24, 2, 30, 0, 0, time.UTC) }

	err := service.RevokeOthers(context.Background(), RevokeOthersInput{
		UserID:    "user-1",
		SessionID: "session-1",
	})
	if err != nil {
		t.Fatalf("RevokeOthers returned error: %v", err)
	}
	if store.revokedUserID != "user-1" {
		t.Fatalf("expected revoked user id %q, got %q", "user-1", store.revokedUserID)
	}
	if store.revokedExceptID != "session-1" {
		t.Fatalf("expected excluded session id %q, got %q", "session-1", store.revokedExceptID)
	}
	if store.revokedAllReason != reasonOtherSessionsRevoked {
		t.Fatalf("expected revoke reason %q, got %q", reasonOtherSessionsRevoked, store.revokedAllReason)
	}
}

func TestRevokeAllRevokesUserSessions(t *testing.T) {
	store := &fakeStore{}
	service := NewService(store, &fakeUserLookup{}, &fakeAccessTokenIssuer{}, Settings{LoginSessionTTL: 30 * 24 * time.Hour})
	service.now = func() time.Time { return time.Date(2026, 5, 24, 3, 0, 0, 0, time.UTC) }

	err := service.RevokeAll(context.Background(), RevokeAllInput{UserID: "user-1"})
	if err != nil {
		t.Fatalf("RevokeAll returned error: %v", err)
	}
	if store.revokedUserID != "user-1" {
		t.Fatalf("expected revoked user id %q, got %q", "user-1", store.revokedUserID)
	}
	if store.revokedAllReason != reasonAllSessionsRevoked {
		t.Fatalf("expected revoke reason %q, got %q", reasonAllSessionsRevoked, store.revokedAllReason)
	}
}

func cloneSession(session auth.LoginSession) *auth.LoginSession {
	copyValue := session
	return &copyValue
}
