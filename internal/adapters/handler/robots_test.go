package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRobotsTXTReturnsDisallowAllPolicy(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.GET("/robots.txt", RobotsTXT)
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("expected content type %q, got %q", "text/plain; charset=utf-8", got)
	}
	if got := recorder.Body.String(); got != robotsTXT {
		t.Fatalf("expected robots.txt body %q, got %q", robotsTXT, got)
	}
}
