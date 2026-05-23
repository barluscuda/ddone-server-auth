package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge           time.Duration
}

func CORS(cfg CORSConfig) gin.HandlerFunc {
	allowedOrigins := trimAndCopy(cfg.AllowedOrigins)
	allowedMethods := trimAndCopy(cfg.AllowedMethods)
	allowedHeaders := trimAndCopy(cfg.AllowedHeaders)
	exposedHeaders := trimAndCopy(cfg.ExposedHeaders)
	allowAnyOrigin := containsString(allowedOrigins, "*")

	allowMethodsValue := strings.Join(allowedMethods, ", ")
	allowHeadersValue := strings.Join(allowedHeaders, ", ")
	exposeHeadersValue := strings.Join(exposedHeaders, ", ")
	maxAgeValue := strconv.FormatInt(int64(cfg.MaxAge/time.Second), 10)

	return func(c *gin.Context) {
		origin := strings.TrimSpace(c.GetHeader("Origin"))
		if origin == "" {
			c.Next()
			return
		}

		if !allowAnyOrigin && !containsString(allowedOrigins, origin) {
			if isPreflightRequest(c.Request) {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

			c.Next()
			return
		}

		addVaryHeader(c.Writer.Header(), "Origin")
		if allowAnyOrigin && !cfg.AllowCredentials {
			c.Header("Access-Control-Allow-Origin", "*")
		} else {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		if cfg.AllowCredentials {
			c.Header("Access-Control-Allow-Credentials", "true")
		}
		if exposeHeadersValue != "" {
			c.Header("Access-Control-Expose-Headers", exposeHeadersValue)
		}

		if isPreflightRequest(c.Request) {
			addVaryHeader(c.Writer.Header(), "Access-Control-Request-Method")
			addVaryHeader(c.Writer.Header(), "Access-Control-Request-Headers")
			c.Header("Access-Control-Allow-Methods", allowMethodsValue)
			c.Header("Access-Control-Allow-Headers", allowHeadersValue)
			if cfg.MaxAge > 0 {
				c.Header("Access-Control-Max-Age", maxAgeValue)
			}
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func isPreflightRequest(req *http.Request) bool {
	return req.Method == http.MethodOptions && strings.TrimSpace(req.Header.Get("Access-Control-Request-Method")) != ""
}

func addVaryHeader(header http.Header, value string) {
	current := header.Values("Vary")
	for _, entry := range current {
		for _, part := range strings.Split(entry, ",") {
			if strings.EqualFold(strings.TrimSpace(part), value) {
				return
			}
		}
	}

	header.Add("Vary", value)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}

	return false
}

func trimAndCopy(values []string) []string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		cleaned = append(cleaned, trimmed)
	}

	return cleaned
}
