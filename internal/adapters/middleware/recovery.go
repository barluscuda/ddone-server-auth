package middleware

import (
	"ddone-server-auth/internal/adapters/dto"
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func Recovery(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error(
					"panic recovered",
					zap.Any("panic", rec),
					zap.ByteString("stack", debug.Stack()),
					zap.String("method", c.Request.Method),
					zap.String("path", c.Request.URL.Path),
				)

				c.AbortWithStatusJSON(http.StatusInternalServerError, dto.ResMessage{
					Success: false,
					Code:    "internal_server_error",
					Message: "internal server error",
				})
			}
		}()

		c.Next()
	}
}
