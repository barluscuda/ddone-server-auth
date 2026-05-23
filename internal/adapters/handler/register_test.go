package handler

import (
	"bytes"
	"context"
	"ddone-server-auth/internal/adapters/dto"
	appregister "ddone-server-auth/internal/application/register"
	"ddone-server-auth/internal/domain/account"
	"encoding/json"
	"errors"
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

	service := appregister.NewService(&fakeAccountRepository{}, &fakeRegistrationStore{}, &fakeOTPSender{})
	handler := NewRegisterHandler(service)

	body, err := json.Marshal(map[string]string{
		"phoneNumber": "        ",
		"password":    "secretpass",
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

	var res dto.ResMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal response body: %v", err)
	}
	if res.Message != "phone number is required" {
		t.Fatalf("expected safe message %q, got %q", "phone number is required", res.Message)
	}
}

func TestRegisterRejectsInvalidPhoneNumber(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	service := appregister.NewService(&fakeAccountRepository{}, &fakeRegistrationStore{}, &fakeOTPSender{})
	handler := NewRegisterHandler(service)

	body, err := json.Marshal(map[string]string{
		"phoneNumber": "+85620ABC5678",
		"password":    "secretpass",
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

func TestRegisterRejectsInvalidRequestBodyWithSafeMessage(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	service := appregister.NewService(&fakeAccountRepository{}, &fakeRegistrationStore{}, &fakeOTPSender{})
	handler := NewRegisterHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader([]byte(`{`)))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.POST("/register", handler.Register)
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}

	var res dto.ResMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal response body: %v", err)
	}
	if res.Code != "invalid_request_body" {
		t.Fatalf("expected code %q, got %q", "invalid_request_body", res.Code)
	}
	if res.Message != "invalid request body" {
		t.Fatalf("expected safe message %q, got %q", "invalid request body", res.Message)
	}
}

func TestRegisterReturnsTicketID(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	service := appregister.NewService(&fakeAccountRepository{}, &fakeRegistrationStore{}, &fakeOTPSender{})
	handler := NewRegisterHandler(service)

	body, err := json.Marshal(map[string]string{
		"phoneNumber": "+8562012345678",
		"password":    "secretpass",
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

	if !res.Success {
		t.Fatal("expected success response")
	}
	if res.Code != "register_otp_sent" {
		t.Fatalf("expected code %q, got %q", "register_otp_sent", res.Code)
	}
	if res.Data.TicketID == "" {
		t.Fatal("expected ticket id in register response")
	}
	if res.Data.RemainingResendCount != 3 {
		t.Fatalf("expected remaining resend count %d, got %d", 3, res.Data.RemainingResendCount)
	}
}

func TestRegisterRejectsWhitespacePassword(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	service := appregister.NewService(&fakeAccountRepository{}, &fakeRegistrationStore{}, &fakeOTPSender{})
	handler := NewRegisterHandler(service)

	body, err := json.Marshal(map[string]string{
		"phoneNumber": "+8562012345678",
		"password":    "        ",
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

	service := appregister.NewService(&fakeAccountRepository{}, &fakeRegistrationStore{}, &fakeOTPSender{})
	handler := NewRegisterHandler(service)

	body, err := json.Marshal(map[string]string{
		"ticketId": "        ",
		"otpCode":  "123456",
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
	service := appregister.NewService(&fakeAccountRepository{}, store, &fakeOTPSender{})
	handler := NewRegisterHandler(service)

	body, err := json.Marshal(map[string]string{
		"ticketId": "reg_fixed123",
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

	if !res.Success {
		t.Fatal("expected success response")
	}
	if res.Code != "register_otp_resent" {
		t.Fatalf("expected code %q, got %q", "register_otp_resent", res.Code)
	}
	if res.Data.TicketID != "reg_fixed123" {
		t.Fatalf("expected ticket id %q, got %q", "reg_fixed123", res.Data.TicketID)
	}
	if res.Data.RemainingResendCount != 2 {
		t.Fatalf("expected remaining resend count %d, got %d", 2, res.Data.RemainingResendCount)
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
	service := appregister.NewService(&fakeAccountRepository{}, store, &fakeOTPSender{})
	handler := NewRegisterHandler(service)

	body, err := json.Marshal(map[string]string{
		"ticketId": "reg_fixed123",
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

	var res dto.ResMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal response body: %v", err)
	}

	if res.Success {
		t.Fatal("expected error response")
	}
	if res.Code != "resend_cooldown_active" {
		t.Fatalf("expected code %q, got %q", "resend_cooldown_active", res.Code)
	}
	if res.Message != "please wait before requesting another otp" {
		t.Fatalf("expected safe message %q, got %q", "please wait before requesting another otp", res.Message)
	}
}

func TestHandleRegisterErrorDoesNotLeakUnexpectedError(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)

	handleRegisterError(c, errors.New("database connection failed: secret details"))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, recorder.Code)
	}

	var res dto.ResMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal response body: %v", err)
	}

	if res.Success {
		t.Fatal("expected error response")
	}
	if res.Code != "internal_server_error" {
		t.Fatalf("expected code %q, got %q", "internal_server_error", res.Code)
	}
	if res.Message != "internal server error" {
		t.Fatalf("expected safe message %q, got %q", "internal server error", res.Message)
	}
}

func stringPtr(value string) *string {
	return &value
}
