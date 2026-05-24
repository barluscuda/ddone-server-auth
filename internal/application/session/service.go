package session

import (
	"context"
	"errors"
	"strings"
	"time"

	"ddone-server-auth/internal/domain/auth"
)

const (
	reasonSessionRevoked       = "session_revoked"
	reasonOtherSessionsRevoked = "other_sessions_revoked"
	reasonAllSessionsRevoked   = "all_sessions_revoked"
)

var ErrAuthenticatedUserRequired = errors.New("authenticated user is required")
var ErrSessionIDRequired = errors.New("session id is required")
var ErrAccessTokenRequired = errors.New("access token is required")

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

	sessions, err := s.store.ListByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	result := make([]View, 0, len(sessions))
	for _, session := range sessions {
		result = append(result, toView(session))
	}

	return result, nil
}

func (s *Service) Current(ctx context.Context, input CurrentInput) (*View, error) {
	session, err := s.currentSession(ctx, input.UserID, input.AccessToken)
	if err != nil {
		return nil, err
	}

	view := toView(*session)
	return &view, nil
}

func (s *Service) Revoke(ctx context.Context, input RevokeInput) error {
	userID := strings.TrimSpace(input.UserID)
	if userID == "" {
		return ErrAuthenticatedUserRequired
	}

	sessionID := strings.TrimSpace(input.SessionID)
	if sessionID == "" {
		return ErrSessionIDRequired
	}

	session, err := s.store.GetByID(ctx, sessionID)
	if err != nil {
		return err
	}
	if session.UserID != userID {
		return auth.ErrLoginSessionNotFound
	}
	if session.IsRevoked() {
		return nil
	}

	return s.store.RevokeByID(ctx, sessionID, reasonSessionRevoked, s.now())
}

func (s *Service) RevokeOthers(ctx context.Context, input RevokeOthersInput) error {
	session, err := s.currentSession(ctx, input.UserID, input.AccessToken)
	if err != nil {
		return err
	}

	return s.store.RevokeByUserIDExcept(
		ctx,
		session.UserID,
		session.ID,
		reasonOtherSessionsRevoked,
		s.now(),
	)
}

func (s *Service) RevokeAll(ctx context.Context, input RevokeAllInput) error {
	userID := strings.TrimSpace(input.UserID)
	if userID == "" {
		return ErrAuthenticatedUserRequired
	}

	return s.store.RevokeByUserID(ctx, userID, reasonAllSessionsRevoked, s.now())
}

func (s *Service) currentSession(ctx context.Context, rawUserID string, rawAccessToken string) (*auth.LoginSession, error) {
	userID := strings.TrimSpace(rawUserID)
	if userID == "" {
		return nil, ErrAuthenticatedUserRequired
	}

	accessToken := strings.TrimSpace(rawAccessToken)
	if accessToken == "" {
		return nil, ErrAccessTokenRequired
	}

	session, err := s.store.GetByCurrentAccessToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	if session.UserID != userID {
		return nil, auth.ErrLoginSessionNotFound
	}

	return session, nil
}

func toView(session auth.LoginSession) View {
	return View{
		ID:                   session.ID,
		ClientIP:             session.ClientIP,
		UserAgent:            session.UserAgent,
		CurrentAccessExpires: session.CurrentAccessExpires,
		CreatedAt:            session.CreatedAt,
		RevokedAt:            session.RevokedAt,
	}
}
