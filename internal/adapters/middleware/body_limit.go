package middleware

import (
	"net/http"

	"ddone-server-auth/internal/adapters/dto"

	"github.com/gin-gonic/gin"
)

type BodyLimitConfig struct {
	MaxBytes int64
}

func RequestBodyLimit(cfg BodyLimitConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if cfg.MaxBytes <= 0 || c.Request.Body == nil {
			c.Next()
			return
		}

		if c.Request.ContentLength > cfg.MaxBytes {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, dto.ResMessage{
				Success: false,
				Code:    "request_body_too_large",
				Message: "request body is too large",
			})
			return
		}

		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, cfg.MaxBytes)
		c.Next()
	}
}
