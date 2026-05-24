package handler

import (
	"ddone-server-auth/internal/adapters/dto"
	"net/http"
	"net/http/httptest"
	"testing"

	json "github.com/bytedance/sonic"
	"github.com/gin-gonic/gin"
)

func TestHealthzReturnsResponseCode(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.GET("/healthz", Healthz)
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	var res dto.ResHealthz
	if err := json.Unmarshal(recorder.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal response body: %v", err)
	}

	if !res.Success {
		t.Fatal("expected success response")
	}
	if res.Code != "healthz_ok" {
		t.Fatalf("expected code %q, got %q", "healthz_ok", res.Code)
	}
}
