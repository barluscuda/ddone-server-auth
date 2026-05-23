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
	LoginSession(ctx context.Context, input LoginInput) (*SessionResult, error)
	SessionToken(ctx context.Context, input SessionTokenInput) (*SessionResult, error)
}

type Service struct {
	accounts      AccountLookup
	sessions      RefreshSessionStore
	loginSessions LoginSessionStore
	tokens        AccessTokenIssuer
	settings      Settings
	now           func() time.Time
}

func NewService(
	accounts AccountLookup,
	sessions RefreshSessionStore,
	loginSessions LoginSessionStore,
	tokens AccessTokenIssuer,
	settings Settings,
) *Service {
	return &Service{
		accounts:      accounts,
		sessions:      sessions,
		loginSessions: loginSessions,
		tokens:        tokens,
		settings:      settings,
		now:           func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) Login(ctx context.Context, input LoginInput) (*Result, error) {
	accountModel, err := s.authenticateAccount(ctx, input.PhoneNumber, input.Password)
	if err != nil {
		return nil, err
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

func (s *Service) LoginSession(ctx context.Context, input LoginInput) (*SessionResult, error) {
	accountModel, err := s.authenticateAccount(ctx, input.PhoneNumber, input.Password)
	if err != nil {
		return nil, err
	}

	accessToken, err := s.tokens.IssueAccessToken(ctx, accountModel.ID, accountModel.PhoneNumber)
	if err != nil {
		return nil, err
	}

	sessionToken, session, err := s.newLoginSession(
		accountModel.ID,
		accessToken,
		input.ClientIP,
		input.UserAgent,
	)
	if err != nil {
		return nil, err
	}

	if err := s.loginSessions.Create(ctx, session); err != nil {
		return nil, err
	}

	return &SessionResult{
		SessionToken: sessionToken,
		AccessToken:  accessToken,
	}, nil
}

func (s *Service) Refresh(ctx context.Context, input RefreshInput) (*Result, error) {
	return s.refresh(ctx, input)
}

func (s *Service) SessionToken(ctx context.Context, input SessionTokenInput) (*SessionResult, error) {
	tokenValue := strings.TrimSpace(input.SessionToken)
	if tokenValue == "" {
		return nil, auth.ErrSessionTokenRequired
	}

	session, err := s.loginSessions.GetByTokenHash(ctx, hashSessionToken(tokenValue))
	if err != nil {
		return nil, err
	}

	if session.IsRevoked() {
		return nil, auth.ErrLoginSessionRevoked
	}

	now := s.now()
	if session.IsExpired(now) {
		return nil, auth.ErrLoginSessionExpired
	}
	if session.HasActiveAccessToken(now) {
		return &SessionResult{
			AccessToken: existingAccessToken(session, now),
		}, nil
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

	if err := s.loginSessions.UpdateAccessToken(ctx, session.ID, accessToken); err != nil {
		return nil, err
	}

	return &SessionResult{
		AccessToken: accessToken,
	}, nil
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
	tokenValue, err := randomOpaqueToken()
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

func (s *Service) newLoginSession(
	accountID string,
	accessToken *auth.AccessToken,
	clientIP string,
	userAgent string,
) (string, *auth.LoginSession, error) {
	tokenValue, err := randomOpaqueToken()
	if err != nil {
		return "", nil, err
	}
	sessionID, err := randomSessionID()
	if err != nil {
		return "", nil, err
	}

	now := s.now()
	session := &auth.LoginSession{
		ID:                   sessionID,
		AccountID:            accountID,
		TokenHash:            hashSessionToken(tokenValue),
		UserAgent:            strings.TrimSpace(userAgent),
		ClientIP:             strings.TrimSpace(clientIP),
		CurrentAccessToken:   accessToken.Token,
		CurrentAccessExpires: accessToken.ExpiresAt,
		ExpiresAt:            now.Add(s.settings.LoginSessionTTL),
		CreatedAt:            now,
	}

	return tokenValue, session, nil
}

func (s *Service) authenticateAccount(
	ctx context.Context,
	rawPhoneNumber string,
	password string,
) (*account.AccountModel, error) {
	phoneNumber, err := account.NormalizePhoneNumber(rawPhoneNumber)
	if err != nil {
		return nil, err
	}
	if phoneNumber == "" {
		return nil, ErrPhoneNumberRequired
	}
	if strings.TrimSpace(password) == "" {
		return nil, ErrPasswordRequired
	}

	accountModel, err := s.accounts.GetByPhoneNumber(ctx, phoneNumber)
	if err != nil {
		if errors.Is(err, account.ErrAccountNotFound) {
			return nil, auth.ErrInvalidCredentials
		}
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(accountModel.PasswordHash), []byte(password)); err != nil {
		return nil, auth.ErrInvalidCredentials
	}

	return accountModel, nil
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

func randomOpaqueToken() (string, error) {
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
	return hashOpaqueToken(tokenValue)
}

func hashSessionToken(tokenValue string) string {
	return hashOpaqueToken(tokenValue)
}

func hashOpaqueToken(tokenValue string) string {
	sum := sha256.Sum256([]byte(tokenValue))
	return hex.EncodeToString(sum[:])
}
