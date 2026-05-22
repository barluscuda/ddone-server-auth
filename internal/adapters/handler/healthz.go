package handler

import (
	"ddone-server-auth/internal/adapters/dto"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const codeHealthzOK = "healthz_ok"

func Healthz(c *gin.Context) {
	c.JSON(http.StatusOK, dto.ResHealthz{
		Success:    true,
		Code:       codeHealthzOK,
		Message:    "server is healthy",
		Active:     true,
		ServerTime: time.Now(),
	})
}
