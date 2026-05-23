package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ddone-server-auth/internal/adapters/middleware"
	appaccountmanager "ddone-server-auth/internal/application/accountmanager"

	"github.com/gin-gonic/gin"
)

type fakeAccountManagerUseCase struct {
	me       *appaccountmanager.AccountView
	meErr    error
	sessions []appaccountmanager.SessionView
	sessErr  error
}

func (f *fakeAccountManagerUseCase) GetMe(_ context.Context, _ appaccountmanager.GetMeInput) (*appaccountmanager.AccountView, error) {
	return f.me, f.meErr
}

func (f *fakeAccountManagerUseCase) ListMySessions(_ context.Context, _ appaccountmanager.ListMySessionsInput) ([]appaccountmanager.SessionView, error) {
	return f.sessions, f.sessErr
}

func TestAccountManagerHandlerReturnsMe(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewAccountManagerHandler(&fakeAccountManagerUseCase{
		me: &appaccountmanager.AccountView{
			ID:              "account-1",
			PhoneNumber:     "2012345678",
			PhoneVerifiedAt: time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
			CreatedAt:       time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC),
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/account/me", nil)
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.GET("/account/me", func(c *gin.Context) {
		c.Set("auth_context", middleware.AuthContext{AccountID: "account-1"})
		handler.GetMe(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestAccountManagerHandlerReturnsSessions(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewAccountManagerHandler(&fakeAccountManagerUseCase{
		sessions: []appaccountmanager.SessionView{
			{
				ID:                   "session-1",
				ClientIP:             "127.0.0.1",
				UserAgent:            "test-agent",
				CurrentAccessExpires: time.Date(2026, 5, 24, 1, 0, 0, 0, time.UTC),
				CreatedAt:            time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/account/sessions", nil)
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.GET("/account/sessions", func(c *gin.Context) {
		c.Set("auth_context", middleware.AuthContext{AccountID: "account-1"})
		handler.ListSessions(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}
