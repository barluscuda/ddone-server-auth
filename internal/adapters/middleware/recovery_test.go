package middleware

import (
	"ddone-server-auth/internal/adapters/dto"
	"net/http"
	"net/http/httptest"
	"testing"

	json "github.com/bytedance/sonic"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestRecoveryReturnsResponseCode(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.Use(Recovery(zap.NewNop()))
	router.GET("/panic", func(c *gin.Context) {
		panic("boom")
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, recorder.Code)
	}

	var res dto.ResMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal response body: %v", err)
	}

	if res.Success {
		t.Fatal("expected error response")
	}
	if res.Code != "internal_server_error" {
		t.Fatalf("expected code %q, got %q", "internal_server_error", res.Code)
	}
}
