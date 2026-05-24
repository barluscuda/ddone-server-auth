package settings

import (
	"context"
	"errors"
	"testing"
	"time"

	"ddone-server-auth/internal/domain/user"
)

type fakeUserReader struct {
	userByID map[string]*user.UserModel
	byUsername  map[string]*user.UserModel
	updated     *user.UserModel
}

func (r *fakeUserReader) GetByID(_ context.Context, id string) (*user.UserModel, error) {
	if value, ok := r.userByID[id]; ok {
		return value, nil
	}

	return nil, user.ErrUserNotFound
}

func (r *fakeUserReader) GetByUsername(_ context.Context, username string) (*user.UserModel, error) {
	if value, ok := r.byUsername[username]; ok {
		copyValue := *value
		return &copyValue, nil
	}

	return nil, user.ErrUserNotFound
}

func (r *fakeUserReader) Update(_ context.Context, userModel *user.UserModel) error {
	copyValue := *userModel
	r.updated = &copyValue
	r.userByID[userModel.ID] = &copyValue
	if r.byUsername == nil {
		r.byUsername = map[string]*user.UserModel{}
	}
	if userModel.Username != nil {
		r.byUsername[*userModel.Username] = &copyValue
	}
	return nil
}

func TestGetReturnsCurrentUser(t *testing.T) {
	service := NewService(&fakeUserReader{
		userByID: map[string]*user.UserModel{
			"user-1": {
				ID:              "user-1",
				PhoneNumber:     "2012345678",
				PhoneVerifiedAt: time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
				CreatedAt:       time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC),
			},
		},
	})

	result, err := service.Get(context.Background(), GetInput{UserID: "user-1"})
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if result.ID != "user-1" {
		t.Fatalf("expected user id %q, got %q", "user-1", result.ID)
	}
}

func TestGetRequiresAuthenticatedUser(t *testing.T) {
	service := NewService(&fakeUserReader{})

	_, err := service.Get(context.Background(), GetInput{})
	if !errors.Is(err, ErrAuthenticatedUserRequired) {
		t.Fatalf("expected ErrAuthenticatedUserRequired, got %v", err)
	}
}

func TestUpdateUsernamePersistsNormalizedValue(t *testing.T) {
	users := &fakeUserReader{
		userByID: map[string]*user.UserModel{
			"user-1": {
				ID:        "user-1",
				CreatedAt: time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC),
			},
		},
		byUsername: map[string]*user.UserModel{},
	}
	service := NewService(users)
	service.now = func() time.Time { return time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC) }

	result, err := service.UpdateUsername(context.Background(), UpdateUsernameInput{
		UserID: "user-1",
		Username:  " New_Name ",
	})
	if err != nil {
		t.Fatalf("UpdateUsername returned error: %v", err)
	}
	if result.Username != "new_name" {
		t.Fatalf("expected normalized username %q, got %q", "new_name", result.Username)
	}
	if users.updated == nil || users.updated.Username == nil || *users.updated.Username != "new_name" {
		t.Fatal("expected updated username to be persisted")
	}
	if users.updated.UsernameChangedAt == nil {
		t.Fatal("expected username changed at to be recorded")
	}
}

func TestUpdateUsernameRejectsCooldown(t *testing.T) {
	lastChange := time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC)
	users := &fakeUserReader{
		userByID: map[string]*user.UserModel{
			"user-1": {
				ID:                "user-1",
				UsernameChangedAt: &lastChange,
			},
		},
		byUsername: map[string]*user.UserModel{},
	}
	service := NewService(users)
	service.now = func() time.Time { return time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC) }

	_, err := service.UpdateUsername(context.Background(), UpdateUsernameInput{
		UserID: "user-1",
		Username:  "new_name",
	})
	if !errors.Is(err, ErrUsernameCooldownActive) {
		t.Fatalf("expected ErrUsernameCooldownActive, got %v", err)
	}
}
