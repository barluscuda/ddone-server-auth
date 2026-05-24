package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"ddone-server-auth/internal/domain/auth"
)

type fakeStore struct {
	byID               map[string]auth.LoginSession
	byAccessToken      map[string]auth.LoginSession
	byUser          map[string][]auth.LoginSession
	revokedSessionID   string
	revokedReason      string
	revokedAt          time.Time
	revokedUserID   string
	revokedExceptID    string
	revokedAllReason   string
	revokedAllAt       time.Time
	revokeByIDErr      error
	revokeOthersErr    error
	revokeByUserErr error
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

func (f *fakeStore) GetByCurrentAccessToken(_ context.Context, accessToken string) (*auth.LoginSession, error) {
	session, ok := f.byAccessToken[accessToken]
	if !ok {
		return nil, auth.ErrLoginSessionNotFound
	}

	return cloneSession(session), nil
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

func TestListReturnsOwnedSessions(t *testing.T) {
	service := NewService(&fakeStore{
		byUser: map[string][]auth.LoginSession{
			"user-1": {
				{
					ID:                   "session-1",
					UserID:            "user-1",
					ClientIP:             "127.0.0.1",
					UserAgent:            "test-agent",
					CurrentAccessExpires: time.Date(2026, 5, 24, 1, 0, 0, 0, time.UTC),
					CreatedAt:            time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
				},
			},
		},
	})

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
	service := NewService(&fakeStore{})

	_, err := service.List(context.Background(), ListInput{})
	if !errors.Is(err, ErrAuthenticatedUserRequired) {
		t.Fatalf("expected ErrAuthenticatedUserRequired, got %v", err)
	}
}

func TestRevokeRejectsSessionFromAnotherUser(t *testing.T) {
	service := NewService(&fakeStore{
		byID: map[string]auth.LoginSession{
			"session-1": {
				ID:        "session-1",
				UserID: "user-2",
			},
		},
	})

	err := service.Revoke(context.Background(), RevokeInput{
		UserID: "user-1",
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
				UserID: "user-1",
			},
		},
	}
	service := NewService(store)
	service.now = func() time.Time { return time.Date(2026, 5, 24, 2, 0, 0, 0, time.UTC) }

	err := service.Revoke(context.Background(), RevokeInput{
		UserID: "user-1",
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

func TestCurrentReturnsSessionMatchedByAccessToken(t *testing.T) {
	service := NewService(&fakeStore{
		byAccessToken: map[string]auth.LoginSession{
			"access-token": {
				ID:        "session-1",
				UserID: "user-1",
			},
		},
	})

	result, err := service.Current(context.Background(), CurrentInput{
		UserID:   "user-1",
		AccessToken: "access-token",
	})
	if err != nil {
		t.Fatalf("Current returned error: %v", err)
	}
	if result.ID != "session-1" {
		t.Fatalf("expected session id %q, got %q", "session-1", result.ID)
	}
}

func TestRevokeOthersKeepsCurrentSession(t *testing.T) {
	store := &fakeStore{
		byAccessToken: map[string]auth.LoginSession{
			"access-token": {
				ID:        "session-1",
				UserID: "user-1",
			},
		},
	}
	service := NewService(store)
	service.now = func() time.Time { return time.Date(2026, 5, 24, 2, 30, 0, 0, time.UTC) }

	err := service.RevokeOthers(context.Background(), RevokeOthersInput{
		UserID:   "user-1",
		AccessToken: "access-token",
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
	service := NewService(store)
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
