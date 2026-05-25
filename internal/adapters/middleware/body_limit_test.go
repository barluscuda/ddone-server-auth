package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRequestBodyLimitRejectsOversizedContentLength(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RequestBodyLimit(BodyLimitConfig{MaxBytes: 4}))
	router.POST("/tokens", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/tokens", strings.NewReader("12345"))
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected status %d, got %d", http.StatusRequestEntityTooLarge, recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "request_body_too_large") {
		t.Fatalf("expected body limit error code, got %q", recorder.Body.String())
	}
}

func TestRequestBodyLimitAllowsBodyWithinLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RequestBodyLimit(BodyLimitConfig{MaxBytes: 5}))
	router.POST("/tokens", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/tokens", strings.NewReader("12345"))
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}
