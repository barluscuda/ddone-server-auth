package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode"

	"ddone-server-auth/internal/adapters/dto"

	json "github.com/bytedance/sonic"
	"github.com/gin-gonic/gin"
)

const (
	otpSpamCodeRegisterRateLimited            = "register_rate_limited"
	otpSpamCodeRegisterVerified               = "register_verified"
	otpSpamCodeResendRateLimited              = "resend_rate_limited"
	otpSpamCodeVerifyRateLimited              = "verify_rate_limited"
	otpSpamCodeInvalidOTPCode                 = "invalid_otp_code"
	otpSpamCodePasswordResetRateLimited       = "password_reset_rate_limited"
	otpSpamCodePasswordResetResendRateLimited = "password_reset_resend_rate_limited"
	otpSpamCodePasswordResetVerifyRateLimited = "password_reset_verify_rate_limited"
	otpSpamCodePasswordResetVerified          = "password_reset_completed"
)

type OTPSpamStore interface {
	IncrementCounter(ctx context.Context, key string, ttl time.Duration) (int64, error)
	AdjustScore(ctx context.Context, key string, delta float64, ttl time.Duration) (float64, error)
}

type OTPSpamDetectionConfig struct {
	Enabled       bool
	Register      OTPSpamFlowConfig
	PasswordReset OTPSpamFlowConfig
}

type OTPSpamFlowConfig struct {
	IPWindow             time.Duration
	PhoneWindow          time.Duration
	MaxIPScore           int
	MaxPhoneRequests     int
	PendingIPScore       float64
	ResendIPScore        float64
	InvalidVerifyIPScore float64
	SuccessVerifyIPScore float64
}

type otpSpamFlow string

const (
	otpSpamFlowRegister      otpSpamFlow = "register"
	otpSpamFlowPasswordReset otpSpamFlow = "password_reset"
)

type otpSpamAction string

const (
	otpSpamActionStart  otpSpamAction = "start"
	otpSpamActionResend otpSpamAction = "resend"
	otpSpamActionVerify otpSpamAction = "verify"
)

type otpSpamEndpoint struct {
	Flow             otpSpamFlow
	Action           otpSpamAction
	RateLimitedCode  string
	RateLimitedMsg   string
	SuccessStatus    int
	SuccessCode      string
	InvalidOTPCode   string
	RequiresPhone    bool
	RequiresTicketID bool
	RequiresOTPCode  bool
}

type otpSpamPayload struct {
	PhoneNumber string `json:"phoneNumber"`
	TicketID    string `json:"ticketId"`
	OTPCode     string `json:"otpCode"`
}

type otpClientClassification struct {
	Label string
	Risk  float64
}

func OTPSpamDetection(store OTPSpamStore, cfg OTPSpamDetectionConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		endpoint, ok := otpSpamEndpointForPath(c.FullPath())
		if !ok {
			c.Next()
			return
		}
		if !cfg.Enabled || store == nil {
			c.Next()
			return
		}

		flowCfg, ok := otpSpamFlowConfig(cfg, endpoint.Flow)
		if !ok || flowCfg.IPWindow <= 0 || flowCfg.MaxIPScore <= 0 {
			c.Next()
			return
		}

		body, payload, err := readOTPSpamPayload(c)
		if err != nil {
			abortOTPSpamError(c, http.StatusBadRequest, "invalid_request_body", "invalid request body")
			return
		}

		classification := classifyOTPClient(c, endpoint, body, payload)
		c.Set("otpSpamClientClass", classification.Label)

		if err := enforceOTPSpamPreRequest(c, store, flowCfg, endpoint, payload, classification); err != nil {
			return
		}

		writer := &otpSpamResponseWriter{ResponseWriter: c.Writer}
		c.Writer = writer
		c.Next()

		adjustOTPSpamAfterResponse(c.Request.Context(), store, flowCfg, endpoint, c.ClientIP(), writer)
	}
}

func otpSpamEndpointForPath(path string) (otpSpamEndpoint, bool) {
	switch path {
	case "/registrations":
		return otpSpamEndpoint{
			Flow:            otpSpamFlowRegister,
			Action:          otpSpamActionStart,
			RateLimitedCode: otpSpamCodeRegisterRateLimited,
			RateLimitedMsg:  "too many registration requests, please try again later",
			RequiresPhone:   true,
		}, true
	case "/registrations/resend":
		return otpSpamEndpoint{
			Flow:             otpSpamFlowRegister,
			Action:           otpSpamActionResend,
			RateLimitedCode:  otpSpamCodeResendRateLimited,
			RateLimitedMsg:   "resend limit reached, please start a new registration",
			RequiresTicketID: true,
		}, true
	case "/registrations/verify":
		return otpSpamEndpoint{
			Flow:             otpSpamFlowRegister,
			Action:           otpSpamActionVerify,
			RateLimitedCode:  otpSpamCodeVerifyRateLimited,
			RateLimitedMsg:   "too many invalid otp attempts, please request a new code",
			SuccessStatus:    http.StatusCreated,
			SuccessCode:      otpSpamCodeRegisterVerified,
			InvalidOTPCode:   otpSpamCodeInvalidOTPCode,
			RequiresTicketID: true,
			RequiresOTPCode:  true,
		}, true
	case "/password-resets":
		return otpSpamEndpoint{
			Flow:            otpSpamFlowPasswordReset,
			Action:          otpSpamActionStart,
			RateLimitedCode: otpSpamCodePasswordResetRateLimited,
			RateLimitedMsg:  "too many password reset requests, please try again later",
			RequiresPhone:   true,
		}, true
	case "/password-resets/resend":
		return otpSpamEndpoint{
			Flow:             otpSpamFlowPasswordReset,
			Action:           otpSpamActionResend,
			RateLimitedCode:  otpSpamCodePasswordResetResendRateLimited,
			RateLimitedMsg:   "resend limit reached, please start a new password reset",
			RequiresTicketID: true,
		}, true
	case "/password-resets/verify":
		return otpSpamEndpoint{
			Flow:             otpSpamFlowPasswordReset,
			Action:           otpSpamActionVerify,
			RateLimitedCode:  otpSpamCodePasswordResetVerifyRateLimited,
			RateLimitedMsg:   "too many invalid otp attempts, please request a new code",
			SuccessStatus:    http.StatusOK,
			SuccessCode:      otpSpamCodePasswordResetVerified,
			InvalidOTPCode:   otpSpamCodeInvalidOTPCode,
			RequiresTicketID: true,
			RequiresOTPCode:  true,
		}, true
	default:
		return otpSpamEndpoint{}, false
	}
}

func otpSpamFlowConfig(cfg OTPSpamDetectionConfig, flow otpSpamFlow) (OTPSpamFlowConfig, bool) {
	switch flow {
	case otpSpamFlowRegister:
		return cfg.Register, true
	case otpSpamFlowPasswordReset:
		return cfg.PasswordReset, true
	default:
		return OTPSpamFlowConfig{}, false
	}
}

func readOTPSpamPayload(c *gin.Context) ([]byte, otpSpamPayload, error) {
	if c.Request.Body == nil {
		return nil, otpSpamPayload{}, nil
	}

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return nil, otpSpamPayload{}, err
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))

	var payload otpSpamPayload
	if len(bytes.TrimSpace(body)) == 0 {
		return body, payload, nil
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return body, otpSpamPayload{}, nil
	}

	return body, payload, nil
}

func enforceOTPSpamPreRequest(
	c *gin.Context,
	store OTPSpamStore,
	cfg OTPSpamFlowConfig,
	endpoint otpSpamEndpoint,
	payload otpSpamPayload,
	classification otpClientClassification,
) error {
	if err := enforceOTPPhoneCounter(c, store, cfg, endpoint, payload); err != nil {
		return err
	}

	scoreDelta := otpActionScoreDelta(cfg, endpoint.Action) + classification.Risk
	if scoreDelta <= 0 {
		return nil
	}

	score, err := store.AdjustScore(
		c.Request.Context(),
		otpIPScoreKey(endpoint.Flow, c.ClientIP()),
		scoreDelta,
		cfg.IPWindow,
	)
	if err != nil {
		abortOTPSpamError(c, http.StatusInternalServerError, "internal_server_error", "internal server error")
		return err
	}
	if score > float64(cfg.MaxIPScore) {
		abortOTPSpamRateLimited(c, endpoint)
		return fmt.Errorf("otp spam score exceeded")
	}

	return nil
}

func enforceOTPPhoneCounter(
	c *gin.Context,
	store OTPSpamStore,
	cfg OTPSpamFlowConfig,
	endpoint otpSpamEndpoint,
	payload otpSpamPayload,
) error {
	if endpoint.Action != otpSpamActionStart || !endpoint.RequiresPhone {
		return nil
	}
	phoneNumber := strings.TrimSpace(payload.PhoneNumber)
	if phoneNumber == "" || cfg.PhoneWindow <= 0 || cfg.MaxPhoneRequests <= 0 {
		return nil
	}

	count, err := store.IncrementCounter(
		c.Request.Context(),
		otpPhoneRateKey(endpoint.Flow, phoneNumber),
		cfg.PhoneWindow,
	)
	if err != nil {
		abortOTPSpamError(c, http.StatusInternalServerError, "internal_server_error", "internal server error")
		return err
	}
	if count > int64(cfg.MaxPhoneRequests) {
		abortOTPSpamRateLimited(c, endpoint)
		return fmt.Errorf("otp phone counter exceeded")
	}

	return nil
}

func otpActionScoreDelta(cfg OTPSpamFlowConfig, action otpSpamAction) float64 {
	switch action {
	case otpSpamActionStart:
		return cfg.PendingIPScore
	case otpSpamActionResend:
		return cfg.ResendIPScore
	default:
		return 0
	}
}

func classifyOTPClient(c *gin.Context, endpoint otpSpamEndpoint, body []byte, payload otpSpamPayload) otpClientClassification {
	risk := 0.0
	userAgent := strings.TrimSpace(c.GetHeader("User-Agent"))
	userAgentLower := strings.ToLower(userAgent)

	if userAgent == "" {
		risk += 2
	} else if containsSuspiciousUserAgentToken(userAgentLower) {
		risk += 2
	} else if looksLikeBrowser(userAgentLower) && c.GetHeader("Accept-Language") != "" {
		risk -= 0.25
	}

	if contentType := strings.TrimSpace(c.GetHeader("Content-Type")); contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil || mediaType != "application/json" {
			risk += 0.5
		}
	}

	if len(bytes.TrimSpace(body)) == 0 {
		risk += 0.75
	}
	if endpoint.RequiresPhone && strings.TrimSpace(payload.PhoneNumber) == "" {
		risk += 0.5
	}
	if endpoint.RequiresTicketID && strings.TrimSpace(payload.TicketID) == "" {
		risk += 0.5
	}
	if endpoint.RequiresOTPCode && !isSixDigitOTP(payload.OTPCode) {
		risk += 0.75
	}

	if risk <= 0 {
		return otpClientClassification{Label: "likely_user"}
	}
	if risk >= 2 {
		return otpClientClassification{Label: "likely_bot", Risk: risk}
	}

	return otpClientClassification{Label: "suspicious", Risk: risk}
}

func containsSuspiciousUserAgentToken(userAgent string) bool {
	suspiciousTokens := []string{
		"bot",
		"crawler",
		"curl",
		"headless",
		"httpclient",
		"masscan",
		"nikto",
		"phantomjs",
		"python-requests",
		"scrapy",
		"selenium",
		"sqlmap",
		"wget",
	}
	for _, token := range suspiciousTokens {
		if strings.Contains(userAgent, token) {
			return true
		}
	}

	return false
}

func looksLikeBrowser(userAgent string) bool {
	return strings.Contains(userAgent, "mozilla/") &&
		(strings.Contains(userAgent, "chrome/") ||
			strings.Contains(userAgent, "safari/") ||
			strings.Contains(userAgent, "firefox/") ||
			strings.Contains(userAgent, "edg/"))
}

func isSixDigitOTP(value string) bool {
	if len(value) != 6 {
		return false
	}
	for _, r := range value {
		if !unicode.IsDigit(r) {
			return false
		}
	}

	return true
}

func adjustOTPSpamAfterResponse(
	ctx context.Context,
	store OTPSpamStore,
	cfg OTPSpamFlowConfig,
	endpoint otpSpamEndpoint,
	clientIP string,
	writer *otpSpamResponseWriter,
) {
	if endpoint.Action != otpSpamActionVerify {
		return
	}

	responseCode := writer.responseCode()
	switch {
	case writer.Status() == endpoint.SuccessStatus && responseCode == endpoint.SuccessCode:
		_, _ = store.AdjustScore(ctx, otpIPScoreKey(endpoint.Flow, clientIP), cfg.SuccessVerifyIPScore, cfg.IPWindow)
	case responseCode == endpoint.InvalidOTPCode:
		_, _ = store.AdjustScore(ctx, otpIPScoreKey(endpoint.Flow, clientIP), cfg.InvalidVerifyIPScore, cfg.IPWindow)
	}
}

func abortOTPSpamRateLimited(c *gin.Context, endpoint otpSpamEndpoint) {
	abortOTPSpamError(c, http.StatusTooManyRequests, endpoint.RateLimitedCode, endpoint.RateLimitedMsg)
}

func abortOTPSpamError(c *gin.Context, statusCode int, code string, message string) {
	c.AbortWithStatusJSON(statusCode, dto.ResMessage{
		Success: false,
		Code:    code,
		Message: message,
	})
}

func otpIPScoreKey(flow otpSpamFlow, clientIP string) string {
	clientIP = strings.TrimSpace(clientIP)
	if clientIP == "" {
		clientIP = "unknown"
	}

	switch flow {
	case otpSpamFlowRegister:
		return fmt.Sprintf("register:score:ip:%s", clientIP)
	case otpSpamFlowPasswordReset:
		return fmt.Sprintf("password_reset:ip:%s", clientIP)
	default:
		return fmt.Sprintf("otp:score:ip:%s:%s", flow, clientIP)
	}
}

func otpPhoneRateKey(flow otpSpamFlow, phoneNumber string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(phoneNumber)))
	digest := hex.EncodeToString(sum[:])
	switch flow {
	case otpSpamFlowRegister:
		return fmt.Sprintf("otp_spam:register:phone:%s", digest)
	case otpSpamFlowPasswordReset:
		return fmt.Sprintf("otp_spam:password_reset:phone:%s", digest)
	default:
		return fmt.Sprintf("otp_spam:%s:phone:%s", flow, digest)
	}
}

type otpSpamResponseWriter struct {
	gin.ResponseWriter
	body bytes.Buffer
}

func (w *otpSpamResponseWriter) Write(data []byte) (int, error) {
	w.capture(data)
	return w.ResponseWriter.Write(data)
}

func (w *otpSpamResponseWriter) WriteString(data string) (int, error) {
	w.capture([]byte(data))
	return w.ResponseWriter.WriteString(data)
}

func (w *otpSpamResponseWriter) capture(data []byte) {
	const maxCapturedBodyBytes = 4096
	if w.body.Len() >= maxCapturedBodyBytes {
		return
	}

	remaining := maxCapturedBodyBytes - w.body.Len()
	if len(data) > remaining {
		data = data[:remaining]
	}
	_, _ = w.body.Write(data)
}

func (w *otpSpamResponseWriter) responseCode() string {
	var response struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(w.body.Bytes(), &response); err != nil {
		return ""
	}

	return response.Code
}
