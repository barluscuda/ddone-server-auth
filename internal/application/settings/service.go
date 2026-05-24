package settings

import (
	"context"
	"errors"
	"strings"
	"time"

	"ddone-server-auth/internal/domain/user"
)

var ErrAuthenticatedUserRequired = errors.New("authenticated user is required")
var ErrUsernameRequired = errors.New("username is required")
var ErrInvalidUsername = errors.New("username is invalid")
var ErrUsernameUnchanged = errors.New("username is unchanged")
var ErrUsernameCooldownActive = errors.New("username change cooldown is active")

const usernameCooldown = 7 * 24 * time.Hour

type UseCase interface {
	Get(ctx context.Context, input GetInput) (*View, error)
	UpdateUsername(ctx context.Context, input UpdateUsernameInput) (*UsernameView, error)
}

type Service struct {
	users UserReader
	now   func() time.Time
}

func NewService(users UserReader) *Service {
	return &Service{
		users: users,
		now:   func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) Get(ctx context.Context, input GetInput) (*View, error) {
	userID := strings.TrimSpace(input.UserID)
	if userID == "" {
		return nil, ErrAuthenticatedUserRequired
	}

	userModel, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	now := s.now()
	var usernameCanChangeAt *time.Time
	canChangeUsername := true
	if userModel.UsernameChangedAt != nil {
		canAt := userModel.UsernameChangedAt.Add(usernameCooldown)
		usernameCanChangeAt = &canAt
		canChangeUsername = !now.Before(canAt)
	}

	return &View{
		ID:                  userModel.ID,
		Username:            userModel.Username,
		PhoneNumber:         userModel.PhoneNumber,
		PhoneVerifiedAt:     userModel.PhoneVerifiedAt,
		UsernameChangedAt:   userModel.UsernameChangedAt,
		UsernameCanChangeAt: usernameCanChangeAt,
		CanChangeUsername:   canChangeUsername,
		PasswordChangedAt:   userModel.PasswordChangedAt,
		CreatedAt:           userModel.CreatedAt,
		UpdatedAt:           userModel.UpdatedAt,
	}, nil
}

func (s *Service) UpdateUsername(ctx context.Context, input UpdateUsernameInput) (*UsernameView, error) {
	userID := strings.TrimSpace(input.UserID)
	if userID == "" {
		return nil, ErrAuthenticatedUserRequired
	}

	username, err := normalizeUsername(input.Username)
	if err != nil {
		return nil, err
	}

	userModel, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if userModel.Username != nil && *userModel.Username == username {
		return nil, ErrUsernameUnchanged
	}

	now := s.now()
	if userModel.UsernameChangedAt != nil && now.Before(userModel.UsernameChangedAt.Add(usernameCooldown)) {
		return nil, ErrUsernameCooldownActive
	}

	existing, err := s.users.GetByUsername(ctx, username)
	switch {
	case err == nil && existing.ID != userID:
		return nil, user.ErrUsernameAlreadyRegistered
	case err == nil && existing.ID == userID:
		return nil, ErrUsernameUnchanged
	case err != nil && !errors.Is(err, user.ErrUserNotFound):
		return nil, err
	}

	userModel.Username = &username
	userModel.UsernameChangedAt = &now
	userModel.UpdatedAt = now
	if err := s.users.Update(ctx, userModel); err != nil {
		return nil, err
	}

	return &UsernameView{
		Username:          username,
		UsernameChangedAt: now,
	}, nil
}

func normalizeUsername(raw string) (string, error) {
	username := strings.ToLower(strings.TrimSpace(raw))
	if username == "" {
		return "", ErrUsernameRequired
	}
	if len(username) < 3 || len(username) > 50 {
		return "", ErrInvalidUsername
	}

	for _, r := range username {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '_':
		default:
			return "", ErrInvalidUsername
		}
	}

	return username, nil
}
