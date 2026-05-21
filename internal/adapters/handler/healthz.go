package handler

import (
	"ddone-server-auth/internal/adapters/dto"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func Healthz(c *gin.Context) {
	c.JSON(http.StatusOK, dto.ResHealthz{
		Message:    "server is healthy",
		Active:     true,
		ServerTime: time.Now(),
	})
}
