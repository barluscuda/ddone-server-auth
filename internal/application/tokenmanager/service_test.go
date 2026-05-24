package tokenmanager

import (
	"context"
	"errors"
	"testing"
	"time"

	"ddone-server-auth/internal/domain/auth"
)

type fakeStore struct {
	byID               map[string]auth.TokenRecord
	byAccount          map[string][]auth.TokenRecord
	revokedTokenID     string
	revokedReason      string
	revokedAccountID   string
	revokedAllReason   string
	revokeByIDErr      error
	revokeByAccountErr error
}

func (f *fakeStore) GetByID(_ context.Context, tokenID string) (*auth.TokenRecord, error) {
	token, ok := f.byID[tokenID]
	if !ok {
		return nil, auth.ErrTokenNotFound
	}

	copyValue := token
	return &copyValue, nil
}

func (f *fakeStore) ListByAccountID(_ context.Context, accountID string) ([]auth.TokenRecord, error) {
	tokens := f.byAccount[accountID]
	result := make([]auth.TokenRecord, 0, len(tokens))
	for _, token := range tokens {
		result = append(result, token)
	}

	return result, nil
}

func (f *fakeStore) RevokeByID(_ context.Context, tokenID string, reason string, _ time.Time) error {
	if f.revokeByIDErr != nil {
		return f.revokeByIDErr
	}

	f.revokedTokenID = tokenID
	f.revokedReason = reason
	return nil
}

func (f *fakeStore) RevokeByAccountID(_ context.Context, accountID string, reason string, _ time.Time) error {
	if f.revokeByAccountErr != nil {
		return f.revokeByAccountErr
	}

	f.revokedAccountID = accountID
	f.revokedAllReason = reason
	return nil
}

func TestListReturnsAccountTokens(t *testing.T) {
	service := NewService(&fakeStore{
		byAccount: map[string][]auth.TokenRecord{
			"account-1": {
				{
					ID:        "token-1",
					AccountID: "account-1",
					ExpiresAt: time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC),
					CreatedAt: time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
				},
			},
		},
	})

	result, err := service.List(context.Background(), ListInput{AccountID: "account-1"})
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 token, got %d", len(result))
	}
	if result[0].ID != "token-1" {
		t.Fatalf("expected token id %q, got %q", "token-1", result[0].ID)
	}
}

func TestRevokeRejectsTokenFromAnotherAccount(t *testing.T) {
	service := NewService(&fakeStore{
		byID: map[string]auth.TokenRecord{
			"token-1": {
				ID:        "token-1",
				AccountID: "account-2",
			},
		},
	})

	err := service.Revoke(context.Background(), RevokeInput{
		AccountID: "account-1",
		TokenID:   "token-1",
	})
	if !errors.Is(err, auth.ErrTokenNotFound) {
		t.Fatalf("expected ErrTokenNotFound, got %v", err)
	}
}

func TestRevokeMarksTokenByID(t *testing.T) {
	store := &fakeStore{
		byID: map[string]auth.TokenRecord{
			"token-1": {
				ID:        "token-1",
				AccountID: "account-1",
			},
		},
	}
	service := NewService(store)

	err := service.Revoke(context.Background(), RevokeInput{
		AccountID: "account-1",
		TokenID:   "token-1",
	})
	if err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}
	if store.revokedTokenID != "token-1" {
		t.Fatalf("expected revoked token id %q, got %q", "token-1", store.revokedTokenID)
	}
	if store.revokedReason != reasonTokenRevoked {
		t.Fatalf("expected revoke reason %q, got %q", reasonTokenRevoked, store.revokedReason)
	}
}

func TestRevokeAllRevokesAccountTokens(t *testing.T) {
	store := &fakeStore{}
	service := NewService(store)

	err := service.RevokeAll(context.Background(), RevokeAllInput{AccountID: "account-1"})
	if err != nil {
		t.Fatalf("RevokeAll returned error: %v", err)
	}
	if store.revokedAccountID != "account-1" {
		t.Fatalf("expected revoked account id %q, got %q", "account-1", store.revokedAccountID)
	}
	if store.revokedAllReason != reasonAllTokensRevoked {
		t.Fatalf("expected revoke reason %q, got %q", reasonAllTokensRevoked, store.revokedAllReason)
	}
}
