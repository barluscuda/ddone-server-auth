package handler

import (
	"context"
	"crypto/sha256"
	"ddone-server-auth/internal/adapters/dto"
	applogin "ddone-server-auth/internal/application/login"
	"ddone-server-auth/internal/domain/auth"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	codeLoginSucceeded       = "login_succeeded"
	codeTokenRefreshed       = "token_refreshed"
	codeInvalidCredentials   = "invalid_credentials"
	codeRefreshTokenRequired = "refresh_token_required"
	codeRefreshTokenExpired  = "refresh_token_expired"
	codeRefreshTokenRevoked  = "refresh_token_revoked"
	codeRefreshTokenReplay   = "refresh_token_replay_detected"
	messageLoginSucceeded    = "login completed successfully"
	messageTokenRefreshed    = "token refreshed successfully"
	loginCookiePath          = "/login/refresh/cookie"
)

type RefreshCookieConfig struct {
	Name     string
	MaxAge   time.Duration
	Secure   bool
	SameSite http.SameSite
}

type LoginHandler struct {
	login         applogin.UseCase
	refreshCookie RefreshCookieConfig
}

func NewLoginHandler(login applogin.UseCase, refreshCookie RefreshCookieConfig) *LoginHandler {
	return &LoginHandler{
		login:         login,
		refreshCookie: refreshCookie,
	}
}

func (h *LoginHandler) Login(c *gin.Context) {
	h.loginWithRefreshResponse(c, true, false)
}

func (h *LoginHandler) LoginCookie(c *gin.Context) {
	h.loginWithRefreshResponse(c, false, true)
}

func (h *LoginHandler) loginWithRefreshResponse(c *gin.Context, includeRefreshToken bool, setCookie bool) {
	var req dto.ReqLogin
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, codeInvalidRequestBody, messageInvalidRequestBody)
		return
	}

	result, err := h.login.Login(c.Request.Context(), applogin.LoginInput{
		PhoneNumber: req.PhoneNumber,
		Password:    req.Password,
		ClientIP:    c.ClientIP(),
		UserAgent:   c.Request.UserAgent(),
	})
	if err != nil {
		handleLoginError(c, err)
		return
	}

	if setCookie {
		h.setRefreshCookie(c, result.RefreshToken)
	}
	response := dto.ResLogin{
		Success: true,
		Code:    codeLoginSucceeded,
		Message: messageLoginSucceeded,
		Data: dto.ResLoginData{
			AccessToken: result.AccessToken.Token,
			TokenType:   result.AccessToken.TokenType,
			ExpiresAt:   result.AccessToken.ExpiresAt,
			ExpiresIn:   result.AccessToken.ExpiresIn,
		},
	}
	if includeRefreshToken {
		response.Data.RefreshToken = result.RefreshToken
		response.Data.RefreshExpiresAt = result.RefreshExpiresAt
	}

	c.JSON(http.StatusOK, response)
}

func (h *LoginHandler) Refresh(c *gin.Context) {
	var req dto.ReqRefreshLogin
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, codeInvalidRequestBody, messageInvalidRequestBody)
		return
	}

	result, err := h.login.Refresh(c.Request.Context(), applogin.RefreshInput{
		RefreshToken: req.RefreshToken,
		ClientIP:     c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
	})
	if err != nil {
		handleLoginError(c, err)
		return
	}

	c.JSON(http.StatusOK, dto.ResLogin{
		Success: true,
		Code:    codeTokenRefreshed,
		Message: messageTokenRefreshed,
		Data: dto.ResLoginData{
			AccessToken:      result.AccessToken.Token,
			TokenType:        result.AccessToken.TokenType,
			ExpiresAt:        result.AccessToken.ExpiresAt,
			ExpiresIn:        result.AccessToken.ExpiresIn,
			RefreshToken:     result.RefreshToken,
			RefreshExpiresAt: result.RefreshExpiresAt,
		},
	})
}

func (h *LoginHandler) RefreshCookie(c *gin.Context) {
	tokenValue, err := c.Cookie(h.refreshCookie.Name)
	if err != nil || strings.TrimSpace(tokenValue) == "" {
		handleLoginError(c, auth.ErrRefreshTokenRequired)
		return
	}

	result, refreshErr := h.login.RefreshFromCookieToken(c.Request.Context(), applogin.RefreshInput{
		RefreshToken: tokenValue,
		ClientIP:     c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
	})
	if refreshErr != nil {
		handleLoginError(c, refreshErr)
		return
	}

	h.setRefreshCookie(c, result.RefreshToken)
	c.JSON(http.StatusOK, dto.ResLogin{
		Success: true,
		Code:    codeTokenRefreshed,
		Message: messageTokenRefreshed,
		Data: dto.ResLoginData{
			AccessToken: result.AccessToken.Token,
			TokenType:   result.AccessToken.TokenType,
			ExpiresAt:   result.AccessToken.ExpiresAt,
			ExpiresIn:   result.AccessToken.ExpiresIn,
		},
	})
}

func (h *LoginHandler) setRefreshCookie(c *gin.Context, tokenValue string) {
	c.SetSameSite(h.refreshCookie.SameSite)
	c.SetCookie(
		h.refreshCookie.Name,
		tokenValue,
		int(h.refreshCookie.MaxAge.Seconds()),
		loginCookiePath,
		"",
		h.refreshCookie.Secure,
		true,
	)
}

func handleLoginError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, applogin.ErrPhoneNumberRequired),
		errors.Is(err, applogin.ErrInvalidPhoneNumber),
		errors.Is(err, applogin.ErrPasswordRequired),
		errors.Is(err, auth.ErrRefreshTokenRequired):
		respondError(c, http.StatusBadRequest, loginErrorCode(err), loginErrorMessage(err))
	case errors.Is(err, auth.ErrInvalidCredentials),
		errors.Is(err, auth.ErrRefreshSessionNotFound),
		errors.Is(err, auth.ErrRefreshSessionExpired),
		errors.Is(err, auth.ErrRefreshSessionRevoked),
		errors.Is(err, auth.ErrRefreshTokenReplayDetected):
		respondError(c, http.StatusUnauthorized, loginErrorCode(err), loginErrorMessage(err))
	default:
		respondError(c, http.StatusInternalServerError, codeInternalServerError, "internal server error")
	}
}

func loginErrorCode(err error) string {
	switch {
	case errors.Is(err, applogin.ErrPhoneNumberRequired):
		return codePhoneNumberRequired
	case errors.Is(err, applogin.ErrInvalidPhoneNumber):
		return codeInvalidPhoneNumber
	case errors.Is(err, applogin.ErrPasswordRequired):
		return codePasswordRequired
	case errors.Is(err, auth.ErrRefreshTokenRequired):
		return codeRefreshTokenRequired
	case errors.Is(err, auth.ErrRefreshSessionExpired):
		return codeRefreshTokenExpired
	case errors.Is(err, auth.ErrRefreshSessionRevoked):
		return codeRefreshTokenRevoked
	case errors.Is(err, auth.ErrRefreshTokenReplayDetected):
		return codeRefreshTokenReplay
	case errors.Is(err, auth.ErrInvalidCredentials),
		errors.Is(err, auth.ErrRefreshSessionNotFound):
		return codeInvalidCredentials
	default:
		return codeInternalServerError
	}
}

func loginErrorMessage(err error) string {
	switch {
	case errors.Is(err, applogin.ErrPhoneNumberRequired):
		return "phone number is required"
	case errors.Is(err, applogin.ErrInvalidPhoneNumber):
		return "phone number format is invalid"
	case errors.Is(err, applogin.ErrPasswordRequired):
		return "password is required"
	case errors.Is(err, auth.ErrRefreshTokenRequired):
		return "refresh token is required"
	case errors.Is(err, auth.ErrRefreshSessionExpired):
		return "refresh token has expired"
	case errors.Is(err, auth.ErrRefreshSessionRevoked):
		return "refresh token is no longer valid"
	case errors.Is(err, auth.ErrRefreshTokenReplayDetected):
		return "refresh token replay detected, please log in again"
	case errors.Is(err, auth.ErrInvalidCredentials),
		errors.Is(err, auth.ErrRefreshSessionNotFound):
		return "invalid credentials"
	default:
		return "internal server error"
	}
}

type JWKSHandler struct {
	jwks JWKSUseCase
}

type JWKSUseCase interface {
	PublicJWKS(cxt context.Context) (*auth.JWKSet, error)
}

func NewJWKSHandler(jwks JWKSUseCase) *JWKSHandler {
	return &JWKSHandler{jwks: jwks}
}

func (h *JWKSHandler) PublicJWKS(c *gin.Context) {
	set, err := h.jwks.PublicJWKS(c.Request.Context())
	if err != nil {
		respondError(c, http.StatusInternalServerError, codeInternalServerError, "internal server error")
		return
	}

	payload := dto.ResJWKS{Keys: make([]dto.JWK, 0, len(set.Keys))}
	for _, key := range set.Keys {
		payload.Keys = append(payload.Keys, dto.JWK{
			KeyType:   key.KeyType,
			Use:       key.Use,
			Curve:     key.Curve,
			Algorithm: key.Algorithm,
			KeyID:     key.KeyID,
			X:         key.X,
			Y:         key.Y,
		})
	}

	etag := hashJWKS(payload)
	if match := c.GetHeader("If-None-Match"); match != "" && match == etag {
		c.Status(http.StatusNotModified)
		return
	}

	c.Header("Cache-Control", "public, max-age=300")
	c.Header("ETag", etag)
	c.JSON(http.StatusOK, payload)
}

func hashJWKS(payload dto.ResJWKS) string {
	sum := sha256.Sum256([]byte(payloadHashSource(payload)))
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func payloadHashSource(payload dto.ResJWKS) string {
	var builder strings.Builder
	for _, key := range payload.Keys {
		builder.WriteString(key.KeyID)
		builder.WriteString("|")
		builder.WriteString(key.X)
		builder.WriteString("|")
		builder.WriteString(key.Y)
		builder.WriteString(";")
	}
	return builder.String()
}
