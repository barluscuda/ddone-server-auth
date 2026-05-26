package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const robotsTXT = `User-agent: GPTBot
Disallow: /

User-agent: Google-Extended
Disallow: /

User-agent: CCBot
Disallow: /

User-agent: ClaudeBot
Disallow: /

User-agent: anthropic-ai
Disallow: /

User-agent: PerplexityBot
Disallow: /

User-agent: FacebookBot
Disallow: /

User-agent: *
Disallow: /
Noindex: /
Crawl-delay: 10
`

func RobotsTXT(c *gin.Context) {
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(robotsTXT))
}
