package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestBotProtectionBlocksRequestsAboveLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	now := time.Date(2026, 5, 25, 10, 0, 0, 0, time.UTC)
	router := gin.New()
	router.Use(BotProtection(BotProtectionConfig{
		Enabled:       true,
		Window:        time.Minute,
		MaxRequests:   2,
		BlockDuration: 5 * time.Minute,
		Now:           func() time.Time { return now },
	}))
	router.POST("/tokens", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/tokens", nil)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected request %d status %d, got %d", i+1, http.StatusOK, recorder.Code)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/tokens", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("expected status %d, got %d", http.StatusTooManyRequests, recorder.Code)
	}
	if recorder.Header().Get("Retry-After") != "300" {
		t.Fatalf("expected retry-after %q, got %q", "300", recorder.Header().Get("Retry-After"))
	}
	if !strings.Contains(recorder.Body.String(), "bot_protection_rate_limited") {
		t.Fatalf("expected bot protection error code, got %q", recorder.Body.String())
	}
}

func TestBotProtectionResetsAfterBlockDuration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	now := time.Date(2026, 5, 25, 10, 0, 0, 0, time.UTC)
	router := gin.New()
	router.Use(BotProtection(BotProtectionConfig{
		Enabled:       true,
		Window:        time.Minute,
		MaxRequests:   1,
		BlockDuration: time.Minute,
		Now:           func() time.Time { return now },
	}))
	router.POST("/tokens", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	first := httptest.NewRequest(http.MethodPost, "/tokens", nil)
	firstRecorder := httptest.NewRecorder()
	router.ServeHTTP(firstRecorder, first)
	if firstRecorder.Code != http.StatusOK {
		t.Fatalf("expected first status %d, got %d", http.StatusOK, firstRecorder.Code)
	}

	blocked := httptest.NewRequest(http.MethodPost, "/tokens", nil)
	blockedRecorder := httptest.NewRecorder()
	router.ServeHTTP(blockedRecorder, blocked)
	if blockedRecorder.Code != http.StatusTooManyRequests {
		t.Fatalf("expected blocked status %d, got %d", http.StatusTooManyRequests, blockedRecorder.Code)
	}

	now = now.Add(time.Minute + time.Second)
	allowed := httptest.NewRequest(http.MethodPost, "/tokens", nil)
	allowedRecorder := httptest.NewRecorder()
	router.ServeHTTP(allowedRecorder, allowed)
	if allowedRecorder.Code != http.StatusOK {
		t.Fatalf("expected status %d after block duration, got %d", http.StatusOK, allowedRecorder.Code)
	}
}

func TestBotProtectionCanBeDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(BotProtection(BotProtectionConfig{
		Enabled:       false,
		Window:        time.Minute,
		MaxRequests:   1,
		BlockDuration: time.Minute,
	}))
	router.POST("/tokens", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/tokens", nil)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected request %d status %d, got %d", i+1, http.StatusOK, recorder.Code)
		}
	}
}
