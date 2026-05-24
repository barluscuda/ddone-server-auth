package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ddone-server-auth/internal/adapters/middleware"
	apptokenmanager "ddone-server-auth/internal/application/tokenmanager"

	"github.com/gin-gonic/gin"
)

type fakeTokenManagerUseCase struct {
	tokens       []apptokenmanager.View
	listErr      error
	revokeErr    error
	revokeAllErr error
}

func (f *fakeTokenManagerUseCase) List(
	_ context.Context,
	_ apptokenmanager.ListInput,
) ([]apptokenmanager.View, error) {
	return f.tokens, f.listErr
}

func (f *fakeTokenManagerUseCase) Revoke(
	_ context.Context,
	_ apptokenmanager.RevokeInput,
) error {
	return f.revokeErr
}

func (f *fakeTokenManagerUseCase) RevokeAll(
	_ context.Context,
	_ apptokenmanager.RevokeAllInput,
) error {
	return f.revokeAllErr
}

func TestTokenManagerHandlerReturnsTokens(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewTokenManagerHandler(&fakeTokenManagerUseCase{
		tokens: []apptokenmanager.View{
			{
				ID:        "token-1",
				ExpiresAt: time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC),
				CreatedAt: time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/tokens", nil)
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.GET("/tokens", func(c *gin.Context) {
		c.Set("auth_context", middleware.AuthContext{AccountID: "account-1"})
		handler.List(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestTokenManagerHandlerRevokesToken(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewTokenManagerHandler(&fakeTokenManagerUseCase{})

	req := httptest.NewRequest(http.MethodDelete, "/tokens/token-1", nil)
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.DELETE("/tokens/:tokenId", func(c *gin.Context) {
		c.Set("auth_context", middleware.AuthContext{AccountID: "account-1"})
		handler.Revoke(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestTokenManagerHandlerRevokesAllTokens(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewTokenManagerHandler(&fakeTokenManagerUseCase{})

	req := httptest.NewRequest(http.MethodPost, "/tokens/revoke-all", nil)
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.POST("/tokens/revoke-all", func(c *gin.Context) {
		c.Set("auth_context", middleware.AuthContext{AccountID: "account-1"})
		handler.RevokeAll(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}
