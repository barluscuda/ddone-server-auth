package handler

import (
	"bytes"
	"context"
	"ddone-server-auth/internal/domain/account"
	"ddone-server-auth/internal/services"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

type fakeAccountRepository struct{}

func (r *fakeAccountRepository) Create(_ context.Context, _ *account.AccountModel) error {
	return nil
}

func (r *fakeAccountRepository) GetByID(_ context.Context, _ string) (*account.AccountModel, error) {
	return nil, account.ErrAccountNotFound
}

func (r *fakeAccountRepository) GetByPhoneNumber(_ context.Context, _ string) (*account.AccountModel, error) {
	return nil, account.ErrAccountNotFound
}

func (r *fakeAccountRepository) GetByUsername(_ context.Context, _ string) (*account.AccountModel, error) {
	return nil, account.ErrAccountNotFound
}

func (r *fakeAccountRepository) GetByProvider(_ context.Context, _ account.AuthProvider, _ string) (*account.AccountModel, error) {
	return nil, account.ErrAccountNotFound
}

func (r *fakeAccountRepository) Update(_ context.Context, _ *account.AccountModel) error {
	return nil
}

func (r *fakeAccountRepository) Delete(_ context.Context, _ string) error {
	return nil
}

type fakeRegistrationStore struct{}

func (s *fakeRegistrationStore) Save(_ context.Context, _ *account.RegisterModel, _ time.Duration) error {
	return nil
}

func (s *fakeRegistrationStore) Get(_ context.Context, _ string) (*account.RegisterModel, error) {
	return nil, account.ErrPendingRegistrationNotFound
}

func (s *fakeRegistrationStore) Delete(_ context.Context, _ string) error {
	return nil
}

type fakeOTPSender struct{}

func (s *fakeOTPSender) SendOTP(_ context.Context, _ string, _ string) error {
	return nil
}

func TestRegisterRejectsWhitespacePhoneNumber(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	service := services.NewRegisterService(&fakeAccountRepository{}, &fakeRegistrationStore{}, &fakeOTPSender{})
	handler := NewAuthHandler(service)

	body, err := json.Marshal(map[string]string{
		"phone_number": "        ",
		"password":     "secretpass",
	})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.POST("/register", handler.Register)
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}
}

func TestRegisterRejectsWhitespacePassword(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	service := services.NewRegisterService(&fakeAccountRepository{}, &fakeRegistrationStore{}, &fakeOTPSender{})
	handler := NewAuthHandler(service)

	body, err := json.Marshal(map[string]string{
		"phone_number": "+8562012345678",
		"password":     "        ",
	})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.POST("/register", handler.Register)
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}
}

func TestVerifyRegisterRejectsWhitespacePhoneNumber(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	service := services.NewRegisterService(&fakeAccountRepository{}, &fakeRegistrationStore{}, &fakeOTPSender{})
	handler := NewAuthHandler(service)

	body, err := json.Marshal(map[string]string{
		"phone_number": "        ",
		"otp_code":     "123456",
	})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/register/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.POST("/register/verify", handler.VerifyRegister)
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}
}
