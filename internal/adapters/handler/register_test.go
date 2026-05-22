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

type fakeRegistrationStore struct {
	values map[string]*account.RegisterModel
}

func (s *fakeRegistrationStore) Save(_ context.Context, registration *account.RegisterModel, _ time.Duration) error {
	if s.values == nil {
		s.values = map[string]*account.RegisterModel{}
	}
	s.values[registration.TicketID] = registration
	return nil
}

func (s *fakeRegistrationStore) Get(_ context.Context, ticketID string) (*account.RegisterModel, error) {
	if registration, ok := s.values[ticketID]; ok {
		return registration, nil
	}

	return nil, account.ErrPendingRegistrationNotFound
}

func (s *fakeRegistrationStore) Delete(_ context.Context, _ string) error {
	return nil
}

func (s *fakeRegistrationStore) IncrementCounter(_ context.Context, _ string, _ time.Duration) (int64, error) {
	return 1, nil
}

func (s *fakeRegistrationStore) DeleteCounter(_ context.Context, _ string) error {
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
	handler := NewRegisterHandler(service)

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

func TestRegisterRejectsInvalidPhoneNumber(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	service := services.NewRegisterService(&fakeAccountRepository{}, &fakeRegistrationStore{}, &fakeOTPSender{})
	handler := NewRegisterHandler(service)

	body, err := json.Marshal(map[string]string{
		"phone_number": "+85620ABC5678",
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
	handler := NewRegisterHandler(service)

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
	handler := NewRegisterHandler(service)

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
	handler := NewRegisterHandler(service)

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

func TestResendOTPReturnsTicketID(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	store := &fakeRegistrationStore{
		values: map[string]*account.RegisterModel{
			"reg_fixed123": {
				TicketID:      "reg_fixed123",
				Username:      stringPtr("user_fixed123"),
				PasswordHash:  "hashed-password",
				PhoneNumber:   "2012345678",
				OTPCodeHash:   "existing-hash",
				OTPExpiresAt:  time.Now().UTC().Add(time.Minute),
				LastOTPSentAt: time.Now().UTC().Add(-2 * time.Minute),
				CreatedAt:     time.Now().UTC().Add(-3 * time.Minute),
			},
		},
	}
	service := services.NewRegisterService(&fakeAccountRepository{}, store, &fakeOTPSender{})
	handler := NewRegisterHandler(service)

	body, err := json.Marshal(map[string]string{
		"ticket_id": "reg_fixed123",
	})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/register/resend", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.POST("/register/resend", handler.ResendOTP)
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, recorder.Code)
	}

	var res dto.ResRegister
	if err := json.Unmarshal(recorder.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal response body: %v", err)
	}

	if res.TicketID != "reg_fixed123" {
		t.Fatalf("expected ticket id %q, got %q", "reg_fixed123", res.TicketID)
	}
}

func TestResendOTPReturnsTooManyRequestsDuringCooldown(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	store := &fakeRegistrationStore{
		values: map[string]*account.RegisterModel{
			"reg_fixed123": {
				TicketID:      "reg_fixed123",
				Username:      stringPtr("user_fixed123"),
				PasswordHash:  "hashed-password",
				PhoneNumber:   "2012345678",
				OTPCodeHash:   "existing-hash",
				OTPExpiresAt:  time.Now().UTC().Add(time.Minute),
				LastOTPSentAt: time.Now().UTC().Add(-30 * time.Second),
				CreatedAt:     time.Now().UTC().Add(-2 * time.Minute),
			},
		},
	}
	service := services.NewRegisterService(&fakeAccountRepository{}, store, &fakeOTPSender{})
	handler := NewRegisterHandler(service)

	body, err := json.Marshal(map[string]string{
		"ticket_id": "reg_fixed123",
	})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/register/resend", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.POST("/register/resend", handler.ResendOTP)
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("expected status %d, got %d", http.StatusTooManyRequests, recorder.Code)
	}
}

func stringPtr(value string) *string {
	return &value
}
