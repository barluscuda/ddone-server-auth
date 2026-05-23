package accountmanager

import (
	"context"
	"errors"
	"strings"
)

var ErrAuthenticatedAccountRequired = errors.New("authenticated account is required")

type UseCase interface {
	GetMe(ctx context.Context, input GetMeInput) (*AccountView, error)
	ListMySessions(ctx context.Context, input ListMySessionsInput) ([]SessionView, error)
}

type Service struct {
	accounts AccountReader
	sessions SessionReader
}

func NewService(accounts AccountReader, sessions SessionReader) *Service {
	return &Service{
		accounts: accounts,
		sessions: sessions,
	}
}

func (s *Service) GetMe(ctx context.Context, input GetMeInput) (*AccountView, error) {
	accountID := strings.TrimSpace(input.AccountID)
	if accountID == "" {
		return nil, ErrAuthenticatedAccountRequired
	}

	accountModel, err := s.accounts.GetByID(ctx, accountID)
	if err != nil {
		return nil, err
	}

	return &AccountView{
		ID:              accountModel.ID,
		Username:        accountModel.Username,
		PhoneNumber:     accountModel.PhoneNumber,
		PhoneVerifiedAt: accountModel.PhoneVerifiedAt,
		CreatedAt:       accountModel.CreatedAt,
	}, nil
}

func (s *Service) ListMySessions(ctx context.Context, input ListMySessionsInput) ([]SessionView, error) {
	accountID := strings.TrimSpace(input.AccountID)
	if accountID == "" {
		return nil, ErrAuthenticatedAccountRequired
	}

	sessions, err := s.sessions.ListByAccountID(ctx, accountID)
	if err != nil {
		return nil, err
	}

	result := make([]SessionView, 0, len(sessions))
	for _, session := range sessions {
		result = append(result, SessionView{
			ID:                   session.ID,
			ClientIP:             session.ClientIP,
			UserAgent:            session.UserAgent,
			CurrentAccessExpires: session.CurrentAccessExpires,
			CreatedAt:            session.CreatedAt,
			RevokedAt:            session.RevokedAt,
		})
	}

	return result, nil
}
