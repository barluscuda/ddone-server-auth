package handler

import (
	"bytes"
	"context"
	"ddone-server-auth/internal/adapters/dto"
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

func TestRegisterReturnsTicketID(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	service := services.NewRegisterService(&fakeAccountRepository{}, &fakeRegistrationStore{}, &fakeOTPSender{})
	handler := NewAuthHandler(service)

	body, err := json.Marshal(map[string]string{
		"phone_number": "+8562012345678",
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

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, recorder.Code)
	}

	var res dto.ResRegister
	if err := json.Unmarshal(recorder.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal response body: %v", err)
	}

	if res.TicketID == "" {
		t.Fatal("expected ticket id in register response")
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

func TestVerifyRegisterRejectsWhitespaceTicketID(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	service := services.NewRegisterService(&fakeAccountRepository{}, &fakeRegistrationStore{}, &fakeOTPSender{})
	handler := NewAuthHandler(service)

	body, err := json.Marshal(map[string]string{
		"ticket_id": "        ",
		"otp_code":  "123456",
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
