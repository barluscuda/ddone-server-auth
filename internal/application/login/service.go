package login

import (
	"context"
	"crypto/rand"
	"ddone-server-auth/internal/domain/auth"
	"ddone-server-auth/internal/domain/user"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	refreshTokenBytes = 32
	uuidBytes         = 16
)

var ErrPhoneNumberRequired = errors.New("phone number is required")
var ErrInvalidPhoneNumber = user.ErrInvalidPhoneNumber
var ErrPasswordRequired = errors.New("password is required")

type UseCase interface {
	Login(ctx context.Context, input LoginInput) (*Result, error)
	Refresh(ctx context.Context, input RefreshInput) (*Result, error)
	LoginSession(ctx context.Context, input LoginInput) (*SessionResult, error)
}

type Service struct {
	users          UserLookup
	tokenRecords   TokenStore
	serverSessions LoginSessionStore
	accessTokens   AccessTokenIssuer
	settings       Settings
	now            func() time.Time
}

func NewService(
	users UserLookup,
	tokenRecords TokenStore,
	loginSessions LoginSessionStore,
	tokens AccessTokenIssuer,
	settings Settings,
) *Service {
	return &Service{
		users:          users,
		tokenRecords:   tokenRecords,
		serverSessions: loginSessions,
		accessTokens:   tokens,
		settings:       settings,
		now:            func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) Login(ctx context.Context, input LoginInput) (*Result, error) {
	userModel, err := s.authenticateUser(ctx, input.PhoneNumber, input.Password)
	if err != nil {
		return nil, err
	}

	accessToken, err := s.accessTokens.IssueAccessToken(ctx, userModel.ID, userModel.PhoneNumber)
	if err != nil {
		return nil, err
	}

	refreshToken, tokenRecord, err := s.newRefreshTokenRecord(
		userModel.ID,
		"",
		"",
		input.ClientIP,
		input.UserAgent,
	)
	if err != nil {
		return nil, err
	}
	tokenRecord.RootTokenID = tokenRecord.ID

	if err := s.tokenRecords.Create(ctx, tokenRecord); err != nil {
		return nil, err
	}

	return &Result{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		RefreshExpiresAt: tokenRecord.ExpiresAt,
	}, nil
}

func (s *Service) LoginSession(ctx context.Context, input LoginInput) (*SessionResult, error) {
	userModel, err := s.authenticateUser(ctx, input.PhoneNumber, input.Password)
	if err != nil {
		return nil, err
	}

	accessToken, err := s.accessTokens.IssueAccessToken(ctx, userModel.ID, userModel.PhoneNumber)
	if err != nil {
		return nil, err
	}

	sessionToken, session, err := s.newServerSession(
		userModel.ID,
		accessToken,
		input.ClientIP,
		input.UserAgent,
	)
	if err != nil {
		return nil, err
	}

	if err := s.serverSessions.Create(ctx, session); err != nil {
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

func (s *Service) refresh(ctx context.Context, input RefreshInput) (*Result, error) {
	tokenValue := strings.TrimSpace(input.RefreshToken)
	if tokenValue == "" {
		return nil, auth.ErrRefreshTokenRequired
	}

	tokenRecord, err := s.tokenRecords.GetByTokenHash(ctx, hashRefreshToken(tokenValue))
	if err != nil {
		return nil, err
	}

	now := s.now()
	rootTokenID := tokenRecord.RootTokenID
	if rootTokenID == "" {
		rootTokenID = tokenRecord.ID
	}

	if tokenRecord.IsReplaced() {
		_ = s.tokenRecords.RevokeLineage(ctx, rootTokenID, "refresh_token_replay", now)
		return nil, auth.ErrRefreshTokenReplayDetected
	}
	if tokenRecord.IsRevoked() {
		return nil, auth.ErrTokenRevoked
	}
	if tokenRecord.IsExpired(now) {
		return nil, auth.ErrTokenExpired
	}

	userModel, err := s.users.GetByID(ctx, tokenRecord.UserID)
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

	refreshToken, replacement, err := s.newRefreshTokenRecord(
		userModel.ID,
		rootTokenID,
		tokenRecord.ID,
		input.ClientIP,
		input.UserAgent,
	)
	if err != nil {
		return nil, err
	}

	if err := s.tokenRecords.Rotate(ctx, tokenRecord.ID, replacement, now); err != nil {
		if errors.Is(err, auth.ErrRefreshTokenReplayDetected) || errors.Is(err, auth.ErrTokenRevoked) {
			_ = s.tokenRecords.RevokeLineage(ctx, rootTokenID, "refresh_token_replay", now)
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

func (s *Service) newRefreshTokenRecord(
	userID string,
	rootTokenID string,
	parentTokenID string,
	clientIP string,
	userAgent string,
) (string, *auth.TokenRecord, error) {
	tokenValue, err := randomOpaqueToken()
	if err != nil {
		return "", nil, err
	}
	tokenID, err := randomUUID()
	if err != nil {
		return "", nil, err
	}

	now := s.now()
	tokenRecord := &auth.TokenRecord{
		ID:          tokenID,
		UserID:      userID,
		RootTokenID: rootTokenID,
		TokenHash:   hashRefreshToken(tokenValue),
		UserAgent:   strings.TrimSpace(userAgent),
		ClientIP:    strings.TrimSpace(clientIP),
		ExpiresAt:   now.Add(s.settings.RefreshTokenTTL),
		CreatedAt:   now,
	}
	if parentTokenID != "" {
		tokenRecord.ParentTokenID = &parentTokenID
	}

	return tokenValue, tokenRecord, nil
}

func (s *Service) newServerSession(
	userID string,
	accessToken *auth.AccessToken,
	clientIP string,
	userAgent string,
) (string, *auth.LoginSession, error) {
	tokenValue, err := randomOpaqueToken()
	if err != nil {
		return "", nil, err
	}
	sessionID, err := randomUUID()
	if err != nil {
		return "", nil, err
	}

	now := s.now()
	session := &auth.LoginSession{
		ID:                   sessionID,
		UserID:               userID,
		TokenHash:            auth.HashSessionToken(tokenValue),
		UserAgent:            strings.TrimSpace(userAgent),
		ClientIP:             strings.TrimSpace(clientIP),
		CurrentAccessToken:   accessToken.Token,
		CurrentAccessExpires: accessToken.ExpiresAt,
		ExpiresAt:            now.Add(s.settings.LoginSessionTTL),
		CreatedAt:            now,
	}

	return tokenValue, session, nil
}

func (s *Service) authenticateUser(
	ctx context.Context,
	rawPhoneNumber string,
	password string,
) (*user.UserModel, error) {
	phoneNumber, err := user.NormalizePhoneNumber(rawPhoneNumber)
	if err != nil {
		return nil, err
	}
	if phoneNumber == "" {
		return nil, ErrPhoneNumberRequired
	}
	if strings.TrimSpace(password) == "" {
		return nil, ErrPasswordRequired
	}

	userModel, err := s.users.GetByPhoneNumber(ctx, phoneNumber)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			return nil, auth.ErrInvalidCredentials
		}
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(userModel.PasswordHash), []byte(password)); err != nil {
		return nil, auth.ErrInvalidCredentials
	}

	return userModel, nil
}

func randomOpaqueToken() (string, error) {
	randomBytes := make([]byte, refreshTokenBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

func randomUUID() (string, error) {
	randomBytes := make([]byte, uuidBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	randomBytes[6] = (randomBytes[6] & 0x0f) | 0x40
	randomBytes[8] = (randomBytes[8] & 0x3f) | 0x80

	encoded := hex.EncodeToString(randomBytes)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

func hashRefreshToken(tokenValue string) string {
	return auth.HashOpaqueToken(tokenValue)
}

func hashSessionToken(tokenValue string) string {
	return auth.HashSessionToken(tokenValue)
}

func hashOpaqueToken(tokenValue string) string {
	return auth.HashOpaqueToken(tokenValue)
}
