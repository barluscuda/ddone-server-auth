package middleware

import (
	"net/http"
	"strings"

	"ddone-server-auth/internal/adapters/dto"

	"github.com/gin-gonic/gin"
)

func RequireUserAgent() gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.TrimSpace(c.Request.UserAgent()) == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, dto.ResMessage{
				Success: false,
				Code:    "user_agent_required",
				Message: "user agent is required",
			})
			return
		}

		c.Next()
	}
}
