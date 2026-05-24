package tokenmanager

import (
	"context"
	"errors"
	"strings"
	"time"

	"ddone-server-auth/internal/domain/auth"
)

const (
	reasonTokenRevoked     = "token_revoked"
	reasonAllTokensRevoked = "all_tokens_revoked"
)

var ErrAuthenticatedUserRequired = errors.New("authenticated user is required")
var ErrTokenIDRequired = errors.New("token id is required")

type Service struct {
	store Store
	now   func() time.Time
}

func NewService(store Store) *Service {
	return &Service{
		store: store,
		now:   func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) List(ctx context.Context, input ListInput) ([]View, error) {
	userID := strings.TrimSpace(input.UserID)
	if userID == "" {
		return nil, ErrAuthenticatedUserRequired
	}

	tokens, err := s.store.ListByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	result := make([]View, 0, len(tokens))
	for _, token := range tokens {
		result = append(result, toView(token))
	}

	return result, nil
}

func (s *Service) Revoke(ctx context.Context, input RevokeInput) error {
	userID := strings.TrimSpace(input.UserID)
	if userID == "" {
		return ErrAuthenticatedUserRequired
	}

	tokenID := strings.TrimSpace(input.TokenID)
	if tokenID == "" {
		return ErrTokenIDRequired
	}

	token, err := s.store.GetByID(ctx, tokenID)
	if err != nil {
		return err
	}
	if token.UserID != userID {
		return auth.ErrTokenNotFound
	}
	if token.IsRevoked() {
		return nil
	}

	return s.store.RevokeByID(ctx, tokenID, reasonTokenRevoked, s.now())
}

func (s *Service) RevokeAll(ctx context.Context, input RevokeAllInput) error {
	userID := strings.TrimSpace(input.UserID)
	if userID == "" {
		return ErrAuthenticatedUserRequired
	}

	return s.store.RevokeByUserID(ctx, userID, reasonAllTokensRevoked, s.now())
}

func toView(token auth.TokenRecord) View {
	return View{
		ID:         token.ID,
		ClientIP:   token.ClientIP,
		UserAgent:  token.UserAgent,
		ExpiresAt:  token.ExpiresAt,
		LastUsedAt: token.LastUsedAt,
		ReplacedAt: token.ReplacedAt,
		RevokedAt:  token.RevokedAt,
		CreatedAt:  token.CreatedAt,
	}
}
