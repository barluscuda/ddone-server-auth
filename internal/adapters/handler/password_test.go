package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ddone-server-auth/internal/adapters/middleware"
	apppassword "ddone-server-auth/internal/application/password"

	"github.com/gin-gonic/gin"
)

type fakePasswordUseCase struct {
	forgotResult *apppassword.ResetTicketResult
	forgotErr    error
	resendResult *apppassword.ResetTicketResult
	resendErr    error
	verifyErr    error
	changeErr    error
}

func (f *fakePasswordUseCase) ForgotPassword(_ context.Context, _ apppassword.ForgotPasswordInput) (*apppassword.ResetTicketResult, error) {
	return f.forgotResult, f.forgotErr
}

func (f *fakePasswordUseCase) ResendForgotPasswordOTP(_ context.Context, _ apppassword.ResendForgotPasswordInput) (*apppassword.ResetTicketResult, error) {
	return f.resendResult, f.resendErr
}

func (f *fakePasswordUseCase) VerifyForgotPassword(_ context.Context, _ apppassword.VerifyForgotPasswordInput) error {
	return f.verifyErr
}

func (f *fakePasswordUseCase) ChangePassword(_ context.Context, _ apppassword.ChangePasswordInput) error {
	return f.changeErr
}

func TestPasswordHandlerForgotPasswordReturnsAccepted(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewPasswordHandler(&fakePasswordUseCase{
		forgotResult: &apppassword.ResetTicketResult{
			TicketID:             "pwd_abc123",
			ExpiresAt:            time.Date(2026, 5, 24, 0, 5, 0, 0, time.UTC),
			RemainingResendCount: 3,
		},
	})

	body, err := json.Marshal(map[string]string{"phoneNumber": "+8562012345678"})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/password-resets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.POST("/password-resets", handler.ForgotPassword)
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, recorder.Code)
	}
}

func TestPasswordHandlerChangePasswordRequiresAuthContext(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewPasswordHandler(&fakePasswordUseCase{})

	body, err := json.Marshal(map[string]string{
		"currentPassword": "old-password",
		"newPassword":     "new-password",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/settings/password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.POST("/settings/password", handler.ChangePassword)
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, recorder.Code)
	}
}

func TestPasswordHandlerChangePasswordReturnsSuccess(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewPasswordHandler(&fakePasswordUseCase{})

	body, err := json.Marshal(map[string]string{
		"currentPassword": "old-password",
		"newPassword":     "new-password",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/settings/password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.POST("/settings/password", func(c *gin.Context) {
		c.Set("auth_context", middleware.AuthContext{UserID: "user-1"})
		handler.ChangePassword(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}
