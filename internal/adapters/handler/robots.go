package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const robotsTXT = "User-agent: *\nDisallow: /\n"

func RobotsTXT(c *gin.Context) {
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(robotsTXT))
}
