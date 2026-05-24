package settings

import (
	"context"
	"errors"
	"testing"
	"time"

	"ddone-server-auth/internal/domain/account"
)

type fakeAccountReader struct {
	accountByID map[string]*account.AccountModel
	byUsername  map[string]*account.AccountModel
	updated     *account.AccountModel
}

func (r *fakeAccountReader) GetByID(_ context.Context, id string) (*account.AccountModel, error) {
	if value, ok := r.accountByID[id]; ok {
		return value, nil
	}

	return nil, account.ErrAccountNotFound
}

func (r *fakeAccountReader) GetByUsername(_ context.Context, username string) (*account.AccountModel, error) {
	if value, ok := r.byUsername[username]; ok {
		copyValue := *value
		return &copyValue, nil
	}

	return nil, account.ErrAccountNotFound
}

func (r *fakeAccountReader) Update(_ context.Context, accountModel *account.AccountModel) error {
	copyValue := *accountModel
	r.updated = &copyValue
	r.accountByID[accountModel.ID] = &copyValue
	if r.byUsername == nil {
		r.byUsername = map[string]*account.AccountModel{}
	}
	if accountModel.Username != nil {
		r.byUsername[*accountModel.Username] = &copyValue
	}
	return nil
}

func TestGetReturnsCurrentAccount(t *testing.T) {
	service := NewService(&fakeAccountReader{
		accountByID: map[string]*account.AccountModel{
			"account-1": {
				ID:              "account-1",
				PhoneNumber:     "2012345678",
				PhoneVerifiedAt: time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
				CreatedAt:       time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC),
			},
		},
	})

	result, err := service.Get(context.Background(), GetInput{AccountID: "account-1"})
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if result.ID != "account-1" {
		t.Fatalf("expected account id %q, got %q", "account-1", result.ID)
	}
}

func TestGetRequiresAuthenticatedAccount(t *testing.T) {
	service := NewService(&fakeAccountReader{})

	_, err := service.Get(context.Background(), GetInput{})
	if !errors.Is(err, ErrAuthenticatedAccountRequired) {
		t.Fatalf("expected ErrAuthenticatedAccountRequired, got %v", err)
	}
}

func TestUpdateUsernamePersistsNormalizedValue(t *testing.T) {
	accounts := &fakeAccountReader{
		accountByID: map[string]*account.AccountModel{
			"account-1": {
				ID:        "account-1",
				CreatedAt: time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC),
			},
		},
		byUsername: map[string]*account.AccountModel{},
	}
	service := NewService(accounts)
	service.now = func() time.Time { return time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC) }

	result, err := service.UpdateUsername(context.Background(), UpdateUsernameInput{
		AccountID: "account-1",
		Username:  " New_Name ",
	})
	if err != nil {
		t.Fatalf("UpdateUsername returned error: %v", err)
	}
	if result.Username != "new_name" {
		t.Fatalf("expected normalized username %q, got %q", "new_name", result.Username)
	}
	if accounts.updated == nil || accounts.updated.Username == nil || *accounts.updated.Username != "new_name" {
		t.Fatal("expected updated username to be persisted")
	}
	if accounts.updated.UsernameChangedAt == nil {
		t.Fatal("expected username changed at to be recorded")
	}
}

func TestUpdateUsernameRejectsCooldown(t *testing.T) {
	lastChange := time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC)
	accounts := &fakeAccountReader{
		accountByID: map[string]*account.AccountModel{
			"account-1": {
				ID:                "account-1",
				UsernameChangedAt: &lastChange,
			},
		},
		byUsername: map[string]*account.AccountModel{},
	}
	service := NewService(accounts)
	service.now = func() time.Time { return time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC) }

	_, err := service.UpdateUsername(context.Background(), UpdateUsernameInput{
		AccountID: "account-1",
		Username:  "new_name",
	})
	if !errors.Is(err, ErrUsernameCooldownActive) {
		t.Fatalf("expected ErrUsernameCooldownActive, got %v", err)
	}
}
