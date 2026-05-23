package login

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"ddone-server-auth/internal/domain/account"
	"ddone-server-auth/internal/domain/auth"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	refreshTokenBytes = 32
	sessionIDBytes    = 16
)

var ErrPhoneNumberRequired = errors.New("phone number is required")
var ErrInvalidPhoneNumber = account.ErrInvalidPhoneNumber
var ErrPasswordRequired = errors.New("password is required")

type UseCase interface {
	Login(ctx context.Context, input LoginInput) (*Result, error)
	Refresh(ctx context.Context, input RefreshInput) (*Result, error)
	RefreshFromCookieToken(ctx context.Context, input RefreshInput) (*Result, error)
}

type Service struct {
	accounts AccountLookup
	sessions RefreshSessionStore
	tokens   AccessTokenIssuer
	settings Settings
	now      func() time.Time
}

func NewService(
	accounts AccountLookup,
	sessions RefreshSessionStore,
	tokens AccessTokenIssuer,
	settings Settings,
) *Service {
	return &Service{
		accounts: accounts,
		sessions: sessions,
		tokens:   tokens,
		settings: settings,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) Login(ctx context.Context, input LoginInput) (*Result, error) {
	phoneNumber, err := account.NormalizePhoneNumber(input.PhoneNumber)
	if err != nil {
		return nil, err
	}
	if phoneNumber == "" {
		return nil, ErrPhoneNumberRequired
	}
	if strings.TrimSpace(input.Password) == "" {
		return nil, ErrPasswordRequired
	}

	accountModel, err := s.accounts.GetByPhoneNumber(ctx, phoneNumber)
	if err != nil {
		if errors.Is(err, account.ErrAccountNotFound) {
			return nil, auth.ErrInvalidCredentials
		}
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(accountModel.PasswordHash), []byte(input.Password)); err != nil {
		return nil, auth.ErrInvalidCredentials
	}

	accessToken, err := s.tokens.IssueAccessToken(ctx, accountModel.ID, accountModel.PhoneNumber)
	if err != nil {
		return nil, err
	}

	refreshToken, session, err := s.newSession(
		accountModel.ID,
		"",
		"",
		input.ClientIP,
		input.UserAgent,
	)
	if err != nil {
		return nil, err
	}
	session.RootSessionID = session.ID

	if err := s.sessions.Create(ctx, session); err != nil {
		return nil, err
	}

	return &Result{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		RefreshExpiresAt: session.ExpiresAt,
	}, nil
}

func (s *Service) Refresh(ctx context.Context, input RefreshInput) (*Result, error) {
	return s.refresh(ctx, input)
}

func (s *Service) RefreshFromCookieToken(ctx context.Context, input RefreshInput) (*Result, error) {
	return s.refresh(ctx, input)
}

func (s *Service) refresh(ctx context.Context, input RefreshInput) (*Result, error) {
	tokenValue := strings.TrimSpace(input.RefreshToken)
	if tokenValue == "" {
		return nil, auth.ErrRefreshTokenRequired
	}

	session, err := s.sessions.GetByTokenHash(ctx, hashRefreshToken(tokenValue))
	if err != nil {
		return nil, err
	}

	now := s.now()
	rootSessionID := session.RootSessionID
	if rootSessionID == "" {
		rootSessionID = session.ID
	}

	if session.IsReplaced() {
		_ = s.sessions.RevokeLineage(ctx, rootSessionID, "refresh_token_replay", now)
		return nil, auth.ErrRefreshTokenReplayDetected
	}
	if session.IsRevoked() {
		return nil, auth.ErrRefreshSessionRevoked
	}
	if session.IsExpired(now) {
		return nil, auth.ErrRefreshSessionExpired
	}

	accountModel, err := s.accounts.GetByID(ctx, session.AccountID)
	if err != nil {
		if errors.Is(err, account.ErrAccountNotFound) {
			return nil, auth.ErrInvalidCredentials
		}
		return nil, err
	}

	accessToken, err := s.tokens.IssueAccessToken(ctx, accountModel.ID, accountModel.PhoneNumber)
	if err != nil {
		return nil, err
	}

	refreshToken, replacement, err := s.newSession(
		accountModel.ID,
		rootSessionID,
		session.ID,
		input.ClientIP,
		input.UserAgent,
	)
	if err != nil {
		return nil, err
	}

	if err := s.sessions.Rotate(ctx, session.ID, replacement, now); err != nil {
		if errors.Is(err, auth.ErrRefreshTokenReplayDetected) || errors.Is(err, auth.ErrRefreshSessionRevoked) {
			_ = s.sessions.RevokeLineage(ctx, rootSessionID, "refresh_token_replay", now)
			return nil, auth.ErrRefreshTokenReplayDetected
		}
		return nil, err
	}

	return &Result{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		RefreshExpiresAt: replacement.ExpiresAt,
	}, nil
}

func (s *Service) newSession(
	accountID string,
	rootSessionID string,
	parentSessionID string,
	clientIP string,
	userAgent string,
) (string, *auth.RefreshSession, error) {
	tokenValue, err := randomRefreshToken()
	if err != nil {
		return "", nil, err
	}
	sessionID, err := randomSessionID()
	if err != nil {
		return "", nil, err
	}

	now := s.now()
	session := &auth.RefreshSession{
		ID:            sessionID,
		AccountID:     accountID,
		RootSessionID: rootSessionID,
		TokenHash:     hashRefreshToken(tokenValue),
		UserAgent:     strings.TrimSpace(userAgent),
		ClientIP:      strings.TrimSpace(clientIP),
		ExpiresAt:     now.Add(s.settings.RefreshTokenTTL),
		CreatedAt:     now,
	}
	if parentSessionID != "" {
		session.ParentSessionID = &parentSessionID
	}

	return tokenValue, session, nil
}

func randomRefreshToken() (string, error) {
	randomBytes := make([]byte, refreshTokenBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

func randomSessionID() (string, error) {
	randomBytes := make([]byte, sessionIDBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	randomBytes[6] = (randomBytes[6] & 0x0f) | 0x40
	randomBytes[8] = (randomBytes[8] & 0x3f) | 0x80

	encoded := hex.EncodeToString(randomBytes)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

func hashRefreshToken(tokenValue string) string {
	sum := sha256.Sum256([]byte(tokenValue))
	return hex.EncodeToString(sum[:])
}
