package middleware

import (
	"ddone-server-auth/internal/adapters/dto"
	"net/http"

	"github.com/gin-gonic/gin"
)

func NoRoute() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusNotFound, dto.ResMessage{
			Message: "route not found",
		})
	}
}

func NoMethod() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusMethodNotAllowed, dto.ResMessage{
			Message: "method not allowed",
		})
	}
}
