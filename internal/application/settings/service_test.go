package settings

import (
	"context"
	"errors"
	"testing"
	"time"

	"ddone-server-auth/internal/domain/user"
)

type fakeUserReader struct {
	userByID   map[string]*user.User
	byUsername map[string]*user.User
	updated    *user.User
}

func (r *fakeUserReader) GetByID(_ context.Context, id string) (*user.User, error) {
	if value, ok := r.userByID[id]; ok {
		return value, nil
	}

	return nil, user.ErrUserNotFound
}

func (r *fakeUserReader) GetByUsername(_ context.Context, username string) (*user.User, error) {
	if value, ok := r.byUsername[username]; ok {
		copyValue := *value
		return &copyValue, nil
	}

	return nil, user.ErrUserNotFound
}

func (r *fakeUserReader) Update(_ context.Context, userModel *user.User) error {
	copyValue := *userModel
	r.updated = &copyValue
	r.userByID[userModel.ID] = &copyValue
	if r.byUsername == nil {
		r.byUsername = map[string]*user.User{}
	}
	if userModel.Username != nil {
		r.byUsername[*userModel.Username] = &copyValue
	}
	return nil
}

func TestGetReturnsCurrentUser(t *testing.T) {
	username := "current_user"
	usernameChangedAt := time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC)
	passwordChangedAt := time.Date(2026, 5, 21, 0, 0, 0, 0, time.UTC)
	service := NewService(&fakeUserReader{
		userByID: map[string]*user.User{
			"user-1": {
				ID:                "user-1",
				Username:          &username,
				PhoneNumber:       "2012345678",
				PhoneVerifiedAt:   time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
				UsernameChangedAt: &usernameChangedAt,
				PasswordChangedAt: &passwordChangedAt,
				CreatedAt:         time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC),
				UpdatedAt:         time.Date(2026, 5, 24, 1, 0, 0, 0, time.UTC),
			},
		},
	})
	service.now = func() time.Time { return time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC) }

	result, err := service.Get(context.Background(), GetInput{UserID: "user-1"})
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if result.ID != "user-1" {
		t.Fatalf("expected user id %q, got %q", "user-1", result.ID)
	}
	if result.Username == nil || *result.Username != username {
		t.Fatalf("expected username %q, got %v", username, result.Username)
	}
	if result.UsernameChangedAt == nil || !result.UsernameChangedAt.Equal(usernameChangedAt) {
		t.Fatalf("expected username changed at %v, got %v", usernameChangedAt, result.UsernameChangedAt)
	}
	if result.UsernameCanChangeAt == nil || !result.UsernameCanChangeAt.Equal(usernameChangedAt.Add(usernameCooldown)) {
		t.Fatalf("expected username cooldown end %v, got %v", usernameChangedAt.Add(usernameCooldown), result.UsernameCanChangeAt)
	}
	if result.CanChangeUsername {
		t.Fatal("expected username cooldown to be active")
	}
	if result.CanChangePassword {
		t.Fatal("expected password cooldown to be active")
	}
	if result.PasswordChangedAt == nil || !result.PasswordChangedAt.Equal(passwordChangedAt) {
		t.Fatalf("expected password changed at %v, got %v", passwordChangedAt, result.PasswordChangedAt)
	}
	if result.UpdatedAt.IsZero() {
		t.Fatal("expected updated at to be returned")
	}
}

func TestGetAllowsPasswordChangeAfterCooldown(t *testing.T) {
	passwordChangedAt := time.Date(2026, 5, 10, 0, 0, 0, 0, time.UTC)
	service := NewService(&fakeUserReader{
		userByID: map[string]*user.User{
			"user-1": {
				ID:                "user-1",
				PhoneNumber:       "2012345678",
				PhoneVerifiedAt:   time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
				PasswordChangedAt: &passwordChangedAt,
				CreatedAt:         time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC),
				UpdatedAt:         time.Date(2026, 5, 24, 1, 0, 0, 0, time.UTC),
			},
		},
	})
	service.now = func() time.Time { return time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC) }

	result, err := service.Get(context.Background(), GetInput{UserID: "user-1"})
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if !result.CanChangePassword {
		t.Fatal("expected password cooldown to have expired")
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
		userByID: map[string]*user.User{
			"user-1": {
				ID:        "user-1",
				CreatedAt: time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC),
			},
		},
		byUsername: map[string]*user.User{},
	}
	service := NewService(users)
	service.now = func() time.Time { return time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC) }

	result, err := service.UpdateUsername(context.Background(), UpdateUsernameInput{
		UserID:   "user-1",
		Username: " New_Name ",
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
		userByID: map[string]*user.User{
			"user-1": {
				ID:                "user-1",
				UsernameChangedAt: &lastChange,
			},
		},
		byUsername: map[string]*user.User{},
	}
	service := NewService(users)
	service.now = func() time.Time { return time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC) }

	_, err := service.UpdateUsername(context.Background(), UpdateUsernameInput{
		UserID:   "user-1",
		Username: "new_name",
	})
	if !errors.Is(err, ErrUsernameCooldownActive) {
		t.Fatalf("expected ErrUsernameCooldownActive, got %v", err)
	}
}
