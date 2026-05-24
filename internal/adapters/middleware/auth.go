package middleware

import (
	"context"
	"strings"

	"ddone-server-auth/internal/adapters/dto"
	"ddone-server-auth/internal/domain/auth"

	"github.com/gin-gonic/gin"
)

const authContextKey = "auth_context"

type AccessTokenVerifier interface {
	VerifyAccessToken(ctx context.Context, tokenValue string) (*auth.AccessTokenClaims, error)
}

type AuthContext struct {
	AccountID   string
	PhoneNumber string
	TokenID     string
	AccessToken string
}

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

		accountID := claims.AccountID
		if accountID == "" {
			accountID = claims.Subject
		}

		c.Set(authContextKey, AuthContext{
			AccountID:   accountID,
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
