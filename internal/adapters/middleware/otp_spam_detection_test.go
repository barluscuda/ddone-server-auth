package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ddone-server-auth/internal/adapters/dto"

	"github.com/gin-gonic/gin"
)

type fakeOTPSpamStore struct {
	counters map[string]int64
	scores   map[string]float64
}

func (s *fakeOTPSpamStore) IncrementCounter(_ context.Context, key string, _ time.Duration) (int64, error) {
	if s.counters == nil {
		s.counters = map[string]int64{}
	}

	s.counters[key]++
	return s.counters[key], nil
}

func (s *fakeOTPSpamStore) AdjustScore(_ context.Context, key string, delta float64, _ time.Duration) (float64, error) {
	if s.scores == nil {
		s.scores = map[string]float64{}
	}

	nextScore := s.scores[key] + delta
	if nextScore <= 0 {
		delete(s.scores, key)
		return 0, nil
	}

	s.scores[key] = nextScore
	return nextScore, nil
}

func TestOTPSpamDetectionAllowsLikelyUserAndPreservesBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := &fakeOTPSpamStore{}
	router := gin.New()
	router.Use(OTPSpamDetection(store, testOTPSpamConfig()))
	router.POST("/registrations", func(c *gin.Context) {
		var req struct {
			PhoneNumber string `json:"phoneNumber"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			t.Fatalf("expected handler to receive JSON body: %v", err)
		}
		if req.PhoneNumber != "+8562012345678" {
			t.Fatalf("expected phone body to survive middleware, got %q", req.PhoneNumber)
		}

		c.JSON(http.StatusAccepted, dto.ResMessage{Success: true, Code: "register_otp_sent"})
	})

	res := performOTPSpamRequest(router, http.MethodPost, "/registrations", `{"phoneNumber":"+8562012345678"}`, browserUserAgent)

	if res.Code != http.StatusAccepted {
		t.Fatalf("expected accepted response, got %d", res.Code)
	}
}

func TestOTPSpamDetectionBlocksBotLikeRegistrationRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := &fakeOTPSpamStore{}
	cfg := testOTPSpamConfig()
	cfg.Register.MaxIPScore = 2
	router := gin.New()
	router.Use(OTPSpamDetection(store, cfg))
	router.POST("/registrations", func(c *gin.Context) {
		c.JSON(http.StatusAccepted, dto.ResMessage{Success: true})
	})

	res := performOTPSpamRequest(router, http.MethodPost, "/registrations", `{"phoneNumber":"+8562012345678"}`, "curl/8.5.0")

	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("expected bot-like request to be rate limited, got %d", res.Code)
	}
}

func TestOTPSpamDetectionIncreasesScoreAfterInvalidOTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := &fakeOTPSpamStore{}
	cfg := testOTPSpamConfig()
	cfg.Register.MaxIPScore = 2
	cfg.Register.InvalidVerifyIPScore = 3
	router := gin.New()
	router.Use(OTPSpamDetection(store, cfg))
	router.POST("/registrations/verify", func(c *gin.Context) {
		c.JSON(http.StatusBadRequest, dto.ResMessage{
			Success: false,
			Code:    otpSpamCodeInvalidOTPCode,
			Message: "invalid otp code",
		})
	})
	router.POST("/registrations", func(c *gin.Context) {
		c.JSON(http.StatusAccepted, dto.ResMessage{Success: true})
	})

	invalid := performOTPSpamRequest(router, http.MethodPost, "/registrations/verify", `{"ticketId":"reg_fixed","otpCode":"000000"}`, browserUserAgent)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid otp response, got %d", invalid.Code)
	}

	blocked := performOTPSpamRequest(router, http.MethodPost, "/registrations", `{"phoneNumber":"+8562012345678"}`, browserUserAgent)
	if blocked.Code != http.StatusTooManyRequests {
		t.Fatalf("expected score from invalid otp to block next request, got %d", blocked.Code)
	}
}

func TestOTPSpamDetectionReducesScoreAfterSuccessfulVerify(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := &fakeOTPSpamStore{
		scores: map[string]float64{
			"register:score:ip:192.0.2.1": 2,
		},
	}
	cfg := testOTPSpamConfig()
	cfg.Register.SuccessVerifyIPScore = -1.5
	router := gin.New()
	router.Use(OTPSpamDetection(store, cfg))
	router.POST("/registrations/verify", func(c *gin.Context) {
		c.JSON(http.StatusCreated, dto.ResMessage{
			Success: true,
			Code:    otpSpamCodeRegisterVerified,
		})
	})

	res := performOTPSpamRequest(router, http.MethodPost, "/registrations/verify", `{"ticketId":"reg_fixed","otpCode":"123456"}`, browserUserAgent)
	if res.Code != http.StatusCreated {
		t.Fatalf("expected successful verify response, got %d", res.Code)
	}
	if got, want := store.scores["register:score:ip:192.0.2.1"], 0.5; got != want {
		t.Fatalf("expected score %v after success, got %v", want, got)
	}
}

func testOTPSpamConfig() OTPSpamDetectionConfig {
	flow := OTPSpamFlowConfig{
		IPWindow:             10 * time.Minute,
		PhoneWindow:          5 * time.Minute,
		MaxIPScore:           20,
		MaxPhoneRequests:     20,
		PendingIPScore:       1,
		ResendIPScore:        1,
		InvalidVerifyIPScore: 1,
		SuccessVerifyIPScore: -1.5,
	}

	return OTPSpamDetectionConfig{
		Enabled:       true,
		Register:      flow,
		PasswordReset: flow,
	}
}

const browserUserAgent = "Mozilla/5.0 AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"

func performOTPSpamRequest(router *gin.Engine, method string, target string, body string, userAgent string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("User-Agent", userAgent)

	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	return res
}
