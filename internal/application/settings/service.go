package settings

import (
	"context"
	"errors"
	"strings"
	"time"

	"ddone-server-auth/internal/domain/account"
)

var ErrAuthenticatedAccountRequired = errors.New("authenticated account is required")
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
	accounts AccountReader
	now      func() time.Time
}

func NewService(accounts AccountReader) *Service {
	return &Service{
		accounts: accounts,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) Get(ctx context.Context, input GetInput) (*View, error) {
	accountID := strings.TrimSpace(input.AccountID)
	if accountID == "" {
		return nil, ErrAuthenticatedAccountRequired
	}

	accountModel, err := s.accounts.GetByID(ctx, accountID)
	if err != nil {
		return nil, err
	}

	return &View{
		ID:              accountModel.ID,
		Username:        accountModel.Username,
		PhoneNumber:     accountModel.PhoneNumber,
		PhoneVerifiedAt: accountModel.PhoneVerifiedAt,
		CreatedAt:       accountModel.CreatedAt,
	}, nil
}

func (s *Service) UpdateUsername(ctx context.Context, input UpdateUsernameInput) (*UsernameView, error) {
	accountID := strings.TrimSpace(input.AccountID)
	if accountID == "" {
		return nil, ErrAuthenticatedAccountRequired
	}

	username, err := normalizeUsername(input.Username)
	if err != nil {
		return nil, err
	}

	accountModel, err := s.accounts.GetByID(ctx, accountID)
	if err != nil {
		return nil, err
	}

	if accountModel.Username != nil && *accountModel.Username == username {
		return nil, ErrUsernameUnchanged
	}

	now := s.now()
	if accountModel.UsernameChangedAt != nil && now.Before(accountModel.UsernameChangedAt.Add(usernameCooldown)) {
		return nil, ErrUsernameCooldownActive
	}

	existing, err := s.accounts.GetByUsername(ctx, username)
	switch {
	case err == nil && existing.ID != accountID:
		return nil, account.ErrUsernameAlreadyRegistered
	case err == nil && existing.ID == accountID:
		return nil, ErrUsernameUnchanged
	case err != nil && !errors.Is(err, account.ErrAccountNotFound):
		return nil, err
	}

	accountModel.Username = &username
	accountModel.UsernameChangedAt = &now
	accountModel.UpdatedAt = now
	if err := s.accounts.Update(ctx, accountModel); err != nil {
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
