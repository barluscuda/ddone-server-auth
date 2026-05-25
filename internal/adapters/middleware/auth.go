package middleware

import (
	"context"
	"strings"
	"time"

	"ddone-server-auth/internal/adapters/dto"
	appjwt "ddone-server-auth/internal/application/jwt"
	"ddone-server-auth/internal/domain/auth"

	"github.com/gin-gonic/gin"
)

const authContextKey = "auth_context"

type AccessTokenVerifier = appjwt.Verifier

type AuthContext struct {
	UserID      string
	PhoneNumber string
	TokenID     string
	AccessToken string
}

type SessionLookup interface {
	GetByTokenHash(ctx context.Context, tokenHash string) (*auth.LoginSession, error)
}

type SessionContext struct {
	SessionID string
	UserID    string
}

const sessionContextKey = "session_context"

func RequireAccessToken(verifier AccessTokenVerifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenValue, ok := bearerToken(c.GetHeader("Authorization"))
		if !ok {
			c.AbortWithStatusJSON(401, dto.ResMessage{
				Success: false,
				Code:    "authorization_required",
				Message: "authorization header is required",
			})
			return
		}

		claims, err := verifier.VerifyAccessToken(c.Request.Context(), tokenValue)
		if err != nil {
			c.AbortWithStatusJSON(401, dto.ResMessage{
				Success: false,
				Code:    "invalid_access_token",
				Message: "access token is invalid",
			})
			return
		}

		userID := claims.UserID
		if userID == "" {
			userID = claims.Subject
		}

		c.Set(authContextKey, AuthContext{
			UserID:      userID,
			PhoneNumber: claims.PhoneNumber,
			TokenID:     claims.JWTID,
			AccessToken: tokenValue,
		})
		c.Next()
	}
}

func CurrentAuth(c *gin.Context) (AuthContext, bool) {
	value, ok := c.Get(authContextKey)
	if !ok {
		return AuthContext{}, false
	}

	authContext, ok := value.(AuthContext)
	return authContext, ok
}

func RequireSession(cookieName string, sessions SessionLookup) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenValue, err := c.Cookie(cookieName)
		if err != nil || strings.TrimSpace(tokenValue) == "" {
			c.AbortWithStatusJSON(401, dto.ResMessage{
				Success: false,
				Code:    "session_token_required",
				Message: "session token is required",
			})
			return
		}

		session, err := sessions.GetByTokenHash(c.Request.Context(), auth.HashSessionToken(tokenValue))
		if err != nil || session == nil {
			c.AbortWithStatusJSON(401, dto.ResMessage{
				Success: false,
				Code:    "invalid_session",
				Message: "login session is no longer valid",
			})
			return
		}

		now := time.Now().UTC()
		if session.IsRevoked() || session.IsExpired(now) {
			c.AbortWithStatusJSON(401, dto.ResMessage{
				Success: false,
				Code:    "invalid_session",
				Message: "login session is no longer valid",
			})
			return
		}

		c.Set(sessionContextKey, SessionContext{
			SessionID: session.ID,
			UserID:    session.UserID,
		})
		c.Next()
	}
}

func CurrentSession(c *gin.Context) (SessionContext, bool) {
	value, ok := c.Get(sessionContextKey)
	if !ok {
		return SessionContext{}, false
	}

	sessionContext, ok := value.(SessionContext)
	return sessionContext, ok
}

func bearerToken(headerValue string) (string, bool) {
	trimmed := strings.TrimSpace(headerValue)
	if trimmed == "" {
		return "", false
	}

	parts := strings.SplitN(trimmed, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}

	tokenValue := strings.TrimSpace(parts[1])
	if tokenValue == "" {
		return "", false
	}

	return tokenValue, true
}
