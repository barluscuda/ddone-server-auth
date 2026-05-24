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
	byAccount          map[string][]auth.LoginSession
	revokedSessionID   string
	revokedReason      string
	revokedAt          time.Time
	revokedAccountID   string
	revokedExceptID    string
	revokedAllReason   string
	revokedAllAt       time.Time
	revokeByIDErr      error
	revokeOthersErr    error
	revokeByAccountErr error
}

func (f *fakeStore) GetByID(_ context.Context, sessionID string) (*auth.LoginSession, error) {
	session, ok := f.byID[sessionID]
	if !ok {
		return nil, auth.ErrLoginSessionNotFound
	}

	return cloneSession(session), nil
}

func (f *fakeStore) ListByAccountID(_ context.Context, accountID string) ([]auth.LoginSession, error) {
	sessions := f.byAccount[accountID]
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

func (f *fakeStore) RevokeByAccountIDExcept(
	_ context.Context,
	accountID string,
	excludedSessionID string,
	reason string,
	revokedAt time.Time,
) error {
	if f.revokeOthersErr != nil {
		return f.revokeOthersErr
	}

	f.revokedAccountID = accountID
	f.revokedExceptID = excludedSessionID
	f.revokedAllReason = reason
	f.revokedAllAt = revokedAt
	return nil
}

func (f *fakeStore) RevokeByAccountID(_ context.Context, accountID string, reason string, revokedAt time.Time) error {
	if f.revokeByAccountErr != nil {
		return f.revokeByAccountErr
	}

	f.revokedAccountID = accountID
	f.revokedAllReason = reason
	f.revokedAllAt = revokedAt
	return nil
}

func TestListReturnsOwnedSessions(t *testing.T) {
	service := NewService(&fakeStore{
		byAccount: map[string][]auth.LoginSession{
			"account-1": {
				{
					ID:                   "session-1",
					AccountID:            "account-1",
					ClientIP:             "127.0.0.1",
					UserAgent:            "test-agent",
					CurrentAccessExpires: time.Date(2026, 5, 24, 1, 0, 0, 0, time.UTC),
					CreatedAt:            time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
				},
			},
		},
	})

	result, err := service.List(context.Background(), ListInput{AccountID: "account-1"})
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

func TestListRequiresAuthenticatedAccount(t *testing.T) {
	service := NewService(&fakeStore{})

	_, err := service.List(context.Background(), ListInput{})
	if !errors.Is(err, ErrAuthenticatedAccountRequired) {
		t.Fatalf("expected ErrAuthenticatedAccountRequired, got %v", err)
	}
}

func TestRevokeRejectsSessionFromAnotherAccount(t *testing.T) {
	service := NewService(&fakeStore{
		byID: map[string]auth.LoginSession{
			"session-1": {
				ID:        "session-1",
				AccountID: "account-2",
			},
		},
	})

	err := service.Revoke(context.Background(), RevokeInput{
		AccountID: "account-1",
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
				AccountID: "account-1",
			},
		},
	}
	service := NewService(store)
	service.now = func() time.Time { return time.Date(2026, 5, 24, 2, 0, 0, 0, time.UTC) }

	err := service.Revoke(context.Background(), RevokeInput{
		AccountID: "account-1",
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
				AccountID: "account-1",
			},
		},
	})

	result, err := service.Current(context.Background(), CurrentInput{
		AccountID:   "account-1",
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
				AccountID: "account-1",
			},
		},
	}
	service := NewService(store)
	service.now = func() time.Time { return time.Date(2026, 5, 24, 2, 30, 0, 0, time.UTC) }

	err := service.RevokeOthers(context.Background(), RevokeOthersInput{
		AccountID:   "account-1",
		AccessToken: "access-token",
	})
	if err != nil {
		t.Fatalf("RevokeOthers returned error: %v", err)
	}
	if store.revokedAccountID != "account-1" {
		t.Fatalf("expected revoked account id %q, got %q", "account-1", store.revokedAccountID)
	}
	if store.revokedExceptID != "session-1" {
		t.Fatalf("expected excluded session id %q, got %q", "session-1", store.revokedExceptID)
	}
	if store.revokedAllReason != reasonOtherSessionsRevoked {
		t.Fatalf("expected revoke reason %q, got %q", reasonOtherSessionsRevoked, store.revokedAllReason)
	}
}

func TestRevokeAllRevokesAccountSessions(t *testing.T) {
	store := &fakeStore{}
	service := NewService(store)
	service.now = func() time.Time { return time.Date(2026, 5, 24, 3, 0, 0, 0, time.UTC) }

	err := service.RevokeAll(context.Background(), RevokeAllInput{AccountID: "account-1"})
	if err != nil {
		t.Fatalf("RevokeAll returned error: %v", err)
	}
	if store.revokedAccountID != "account-1" {
		t.Fatalf("expected revoked account id %q, got %q", "account-1", store.revokedAccountID)
	}
	if store.revokedAllReason != reasonAllSessionsRevoked {
		t.Fatalf("expected revoke reason %q, got %q", reasonAllSessionsRevoked, store.revokedAllReason)
	}
}

func cloneSession(session auth.LoginSession) *auth.LoginSession {
	copyValue := session
	return &copyValue
}
