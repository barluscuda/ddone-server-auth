package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ddone-server-auth/internal/adapters/middleware"
	appsession "ddone-server-auth/internal/application/session"

	"github.com/gin-gonic/gin"
)

type fakeSessionUseCase struct {
	sessions        []appsession.View
	current         *appsession.View
	listErr         error
	currentErr      error
	revokeErr       error
	revokeOthersErr error
	revokeAllErr    error
}

func (f *fakeSessionUseCase) List(_ context.Context, _ appsession.ListInput) ([]appsession.View, error) {
	return f.sessions, f.listErr
}

func (f *fakeSessionUseCase) Current(_ context.Context, _ appsession.CurrentInput) (*appsession.View, error) {
	return f.current, f.currentErr
}

func (f *fakeSessionUseCase) Revoke(_ context.Context, _ appsession.RevokeInput) error {
	return f.revokeErr
}

func (f *fakeSessionUseCase) RevokeOthers(_ context.Context, _ appsession.RevokeOthersInput) error {
	return f.revokeOthersErr
}

func (f *fakeSessionUseCase) RevokeAll(_ context.Context, _ appsession.RevokeAllInput) error {
	return f.revokeAllErr
}

func TestSessionHandlerReturnsSessions(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewSessionHandler(&fakeSessionUseCase{
		sessions: []appsession.View{
			{
				ID:                   "session-1",
				ClientIP:             "127.0.0.1",
				UserAgent:            "test-agent",
				CurrentAccessExpires: time.Date(2026, 5, 24, 1, 0, 0, 0, time.UTC),
				CreatedAt:            time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/settings/sessions", nil)
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.GET("/settings/sessions", func(c *gin.Context) {
		c.Set("auth_context", middleware.AuthContext{AccountID: "account-1"})
		handler.List(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestSessionHandlerReturnsCurrentSession(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewSessionHandler(&fakeSessionUseCase{
		current: &appsession.View{
			ID:                   "session-1",
			CurrentAccessExpires: time.Date(2026, 5, 24, 1, 0, 0, 0, time.UTC),
			CreatedAt:            time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/settings/session/current", nil)
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.GET("/settings/session/current", func(c *gin.Context) {
		c.Set("auth_context", middleware.AuthContext{AccountID: "account-1", AccessToken: "access-token"})
		handler.Current(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestSessionHandlerRevokesSession(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewSessionHandler(&fakeSessionUseCase{})

	req := httptest.NewRequest(http.MethodDelete, "/settings/sessions/session-1", nil)
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.DELETE("/settings/sessions/:sessionId", func(c *gin.Context) {
		c.Set("auth_context", middleware.AuthContext{AccountID: "account-1"})
		handler.Revoke(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestSessionHandlerRevokesAllSessions(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewSessionHandler(&fakeSessionUseCase{})

	req := httptest.NewRequest(http.MethodPost, "/settings/sessions/revoke-all", nil)
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.POST("/settings/sessions/revoke-all", func(c *gin.Context) {
		c.Set("auth_context", middleware.AuthContext{AccountID: "account-1"})
		handler.RevokeAll(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestSessionHandlerRevokesOtherSessions(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewSessionHandler(&fakeSessionUseCase{})

	req := httptest.NewRequest(http.MethodPost, "/settings/sessions/revoke-others", nil)
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.POST("/settings/sessions/revoke-others", func(c *gin.Context) {
		c.Set("auth_context", middleware.AuthContext{AccountID: "account-1", AccessToken: "access-token"})
		handler.RevokeOthers(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}
