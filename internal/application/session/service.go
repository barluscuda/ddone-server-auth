package session

import (
	"context"
	"ddone-server-auth/internal/domain/user"
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

type Service struct {
	store        Store
	users        UserLookup
	accessTokens AccessTokenIssuer
	settings     Settings
	now          func() time.Time
}

func NewService(store Store, users UserLookup, accessTokens AccessTokenIssuer, settings Settings) *Service {
	return &Service{
		store:        store,
		users:        users,
		accessTokens: accessTokens,
		settings:     settings,
		now:          func() time.Time { return time.Now().UTC() },
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
	session, err := s.currentSession(ctx, input.UserID, input.SessionID)
	if err != nil {
		return nil, err
	}

	view := toView(*session)
	return &view, nil
}

func (s *Service) IssueAccessToken(ctx context.Context, input IssueAccessTokenInput) (*IssueAccessTokenResult, error) {
	session, err := s.currentSession(ctx, input.UserID, input.SessionID)
	if err != nil {
		return nil, err
	}

	now := s.now()
	if session.HasActiveAccessToken(now) {
		return &IssueAccessTokenResult{
			AccessToken: existingAccessToken(session, now),
			Refreshed:   false,
		}, nil
	}

	userModel, err := s.users.GetByID(ctx, session.UserID)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			return nil, auth.ErrInvalidCredentials
		}
		return nil, err
	}

	accessToken, err := s.accessTokens.IssueAccessToken(ctx, userModel.ID, userModel.PhoneNumber)
	if err != nil {
		return nil, err
	}

	sessionExpiresAt := now.Add(s.settings.LoginSessionTTL)
	if err := s.store.RefreshAccessToken(ctx, session.ID, accessToken, sessionExpiresAt); err != nil {
		return nil, err
	}

	return &IssueAccessTokenResult{
		AccessToken: accessToken,
		Refreshed:   true,
	}, nil
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
	session, err := s.currentSession(ctx, input.UserID, input.SessionID)
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

func (s *Service) currentSession(ctx context.Context, rawUserID string, rawSessionID string) (*auth.LoginSession, error) {
	userID := strings.TrimSpace(rawUserID)
	if userID == "" {
		return nil, ErrAuthenticatedUserRequired
	}

	sessionID := strings.TrimSpace(rawSessionID)
	if sessionID == "" {
		return nil, ErrSessionIDRequired
	}

	session, err := s.store.GetByID(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if session.UserID != userID {
		return nil, auth.ErrLoginSessionNotFound
	}
	if session.IsRevoked() {
		return nil, auth.ErrLoginSessionRevoked
	}
	if session.IsExpired(s.now()) {
		return nil, auth.ErrLoginSessionExpired
	}

	return session, nil
}

func existingAccessToken(session *auth.LoginSession, now time.Time) *auth.AccessToken {
	expiresIn := int64(session.CurrentAccessExpires.Sub(now).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}

	return &auth.AccessToken{
		Token:     session.CurrentAccessToken,
		TokenType: "Bearer",
		ExpiresAt: session.CurrentAccessExpires,
		ExpiresIn: expiresIn,
	}
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
