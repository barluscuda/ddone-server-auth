package accountmanager

import (
	"context"
	"errors"
	"testing"
	"time"

	"ddone-server-auth/internal/domain/account"
	"ddone-server-auth/internal/domain/auth"
)

type fakeAccountReader struct {
	accountByID map[string]*account.AccountModel
}

func (r *fakeAccountReader) GetByID(_ context.Context, id string) (*account.AccountModel, error) {
	if value, ok := r.accountByID[id]; ok {
		return value, nil
	}

	return nil, account.ErrAccountNotFound
}

type fakeSessionReader struct {
	sessionsByAccount map[string][]auth.LoginSession
}

func (r *fakeSessionReader) ListByAccountID(_ context.Context, accountID string) ([]auth.LoginSession, error) {
	return append([]auth.LoginSession(nil), r.sessionsByAccount[accountID]...), nil
}

func TestGetMeReturnsCurrentAccount(t *testing.T) {
	service := NewService(&fakeAccountReader{
		accountByID: map[string]*account.AccountModel{
			"account-1": {
				ID:              "account-1",
				PhoneNumber:     "2012345678",
				PhoneVerifiedAt: time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
				CreatedAt:       time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC),
			},
		},
	}, &fakeSessionReader{})

	result, err := service.GetMe(context.Background(), GetMeInput{AccountID: "account-1"})
	if err != nil {
		t.Fatalf("GetMe returned error: %v", err)
	}
	if result.ID != "account-1" {
		t.Fatalf("expected account id %q, got %q", "account-1", result.ID)
	}
}

func TestGetMeRequiresAuthenticatedAccount(t *testing.T) {
	service := NewService(&fakeAccountReader{}, &fakeSessionReader{})

	_, err := service.GetMe(context.Background(), GetMeInput{})
	if !errors.Is(err, ErrAuthenticatedAccountRequired) {
		t.Fatalf("expected ErrAuthenticatedAccountRequired, got %v", err)
	}
}

func TestListMySessionsReturnsOwnedSessions(t *testing.T) {
	service := NewService(&fakeAccountReader{}, &fakeSessionReader{
		sessionsByAccount: map[string][]auth.LoginSession{
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

	result, err := service.ListMySessions(context.Background(), ListMySessionsInput{AccountID: "account-1"})
	if err != nil {
		t.Fatalf("ListMySessions returned error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 session, got %d", len(result))
	}
	if result[0].ID != "session-1" {
		t.Fatalf("expected session id %q, got %q", "session-1", result[0].ID)
	}
}
