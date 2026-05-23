package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ddone-server-auth/internal/adapters/middleware"
	appsettings "ddone-server-auth/internal/application/settings"

	"github.com/gin-gonic/gin"
)

type fakeSettingsUseCase struct {
	me       *appsettings.View
	meErr    error
	sessions []appsettings.SessionView
	sessErr  error
}

func (f *fakeSettingsUseCase) Get(_ context.Context, _ appsettings.GetInput) (*appsettings.View, error) {
	return f.me, f.meErr
}

func (f *fakeSettingsUseCase) ListSessions(_ context.Context, _ appsettings.ListSessionsInput) ([]appsettings.SessionView, error) {
	return f.sessions, f.sessErr
}

func TestSettingsHandlerReturnsMe(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewSettingsHandler(&fakeSettingsUseCase{
		me: &appsettings.View{
			ID:              "account-1",
			PhoneNumber:     "2012345678",
			PhoneVerifiedAt: time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
			CreatedAt:       time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC),
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/settings/me", nil)
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.GET("/settings/me", func(c *gin.Context) {
		c.Set("auth_context", middleware.AuthContext{AccountID: "account-1"})
		handler.GetMe(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestSettingsHandlerReturnsSessions(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewSettingsHandler(&fakeSettingsUseCase{
		sessions: []appsettings.SessionView{
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
		handler.ListSessions(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}
