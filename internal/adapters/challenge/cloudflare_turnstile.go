package challenge

import (
	"bytes"
	"context"
	"ddone-server-auth/internal/application/dexbotkiller"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const DefaultCloudflareTurnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

var ErrCloudflareTurnstileVerificationFailed = errors.New("cloudflare turnstile verification failed")

type CloudflareTurnstileVerifier struct {
	secretKey string
	verifyURL string
	client    *http.Client
}

type CloudflareTurnstileConfig struct {
	SecretKey string
	VerifyURL string
	Timeout   time.Duration
}

type siteVerifyRequest struct {
	Secret         string `json:"secret"`
	Response       string `json:"response"`
	RemoteIP       string `json:"remoteip,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

type siteVerifyResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
}

var _ dexbotkiller.ChallengeVerifier = (*CloudflareTurnstileVerifier)(nil)

func NewCloudflareTurnstileVerifier(config CloudflareTurnstileConfig) *CloudflareTurnstileVerifier {
	verifyURL := strings.TrimSpace(config.VerifyURL)
	if verifyURL == "" {
		verifyURL = DefaultCloudflareTurnstileVerifyURL
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	return &CloudflareTurnstileVerifier{
		secretKey: strings.TrimSpace(config.SecretKey),
		verifyURL: verifyURL,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (v *CloudflareTurnstileVerifier) Verify(ctx context.Context, verification dexbotkiller.ChallengeVerification) error {
	token := strings.TrimSpace(verification.Token)
	if token == "" || v.secretKey == "" {
		return ErrCloudflareTurnstileVerificationFailed
	}

	payload, err := json.Marshal(siteVerifyRequest{
		Secret:         v.secretKey,
		Response:       token,
		RemoteIP:       strings.TrimSpace(verification.RemoteIP),
		IdempotencyKey: strings.TrimSpace(verification.IdempotencyKey),
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.verifyURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	res, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	var verifyResponse siteVerifyResponse
	if err := json.NewDecoder(res.Body).Decode(&verifyResponse); err != nil {
		return err
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: status %d", ErrCloudflareTurnstileVerificationFailed, res.StatusCode)
	}
	if !verifyResponse.Success {
		return ErrCloudflareTurnstileVerificationFailed
	}

	return nil
}
