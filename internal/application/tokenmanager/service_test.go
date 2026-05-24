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
	byUser          map[string][]auth.TokenRecord
	revokedTokenID     string
	revokedReason      string
	revokedUserID   string
	revokedAllReason   string
	revokeByIDErr      error
	revokeByUserErr error
}

func (f *fakeStore) GetByID(_ context.Context, tokenID string) (*auth.TokenRecord, error) {
	token, ok := f.byID[tokenID]
	if !ok {
		return nil, auth.ErrTokenNotFound
	}

	copyValue := token
	return &copyValue, nil
}

func (f *fakeStore) ListByUserID(_ context.Context, userID string) ([]auth.TokenRecord, error) {
	tokens := f.byUser[userID]
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

func (f *fakeStore) RevokeByUserID(_ context.Context, userID string, reason string, _ time.Time) error {
	if f.revokeByUserErr != nil {
		return f.revokeByUserErr
	}

	f.revokedUserID = userID
	f.revokedAllReason = reason
	return nil
}

func TestListReturnsUserTokens(t *testing.T) {
	service := NewService(&fakeStore{
		byUser: map[string][]auth.TokenRecord{
			"user-1": {
				{
					ID:        "token-1",
					UserID: "user-1",
					ExpiresAt: time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC),
					CreatedAt: time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
				},
			},
		},
	})

	result, err := service.List(context.Background(), ListInput{UserID: "user-1"})
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

func TestRevokeRejectsTokenFromAnotherUser(t *testing.T) {
	service := NewService(&fakeStore{
		byID: map[string]auth.TokenRecord{
			"token-1": {
				ID:        "token-1",
				UserID: "user-2",
			},
		},
	})

	err := service.Revoke(context.Background(), RevokeInput{
		UserID: "user-1",
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
				UserID: "user-1",
			},
		},
	}
	service := NewService(store)

	err := service.Revoke(context.Background(), RevokeInput{
		UserID: "user-1",
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

func TestRevokeAllRevokesUserTokens(t *testing.T) {
	store := &fakeStore{}
	service := NewService(store)

	err := service.RevokeAll(context.Background(), RevokeAllInput{UserID: "user-1"})
	if err != nil {
		t.Fatalf("RevokeAll returned error: %v", err)
	}
	if store.revokedUserID != "user-1" {
		t.Fatalf("expected revoked user id %q, got %q", "user-1", store.revokedUserID)
	}
	if store.revokedAllReason != reasonAllTokensRevoked {
		t.Fatalf("expected revoke reason %q, got %q", reasonAllTokensRevoked, store.revokedAllReason)
	}
}
