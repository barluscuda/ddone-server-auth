package handler

import (
	"bytes"
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
	me          *appsettings.View
	meErr       error
	username    *appsettings.UsernameView
	usernameErr error
}

func (f *fakeSettingsUseCase) Get(_ context.Context, _ appsettings.GetInput) (*appsettings.View, error) {
	return f.me, f.meErr
}

func (f *fakeSettingsUseCase) UpdateUsername(
	_ context.Context,
	_ appsettings.UpdateUsernameInput,
) (*appsettings.UsernameView, error) {
	return f.username, f.usernameErr
}

func TestSettingsHandlerReturnsMe(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewSettingsHandler(&fakeSettingsUseCase{
		me: &appsettings.View{
			ID:              "user-1",
			PhoneNumber:     "2012345678",
			PhoneVerifiedAt: time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
			CreatedAt:       time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC),
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/settings/me", nil)
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.GET("/settings/me", func(c *gin.Context) {
		c.Set("auth_context", middleware.AuthContext{UserID: "user-1"})
		handler.GetMe(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestSettingsHandlerUpdatesUsername(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewSettingsHandler(&fakeSettingsUseCase{
		username: &appsettings.UsernameView{
			Username:          "new_name",
			UsernameChangedAt: time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
		},
	})

	req := httptest.NewRequest(http.MethodPatch, "/settings/username", bytes.NewBufferString(`{"username":"new_name"}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.PATCH("/settings/username", func(c *gin.Context) {
		c.Set("auth_context", middleware.AuthContext{UserID: "user-1"})
		handler.PatchUsername(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}
