package challenge

import (
	"context"
	"ddone-server-auth/internal/application/dexbotkiller"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCloudflareTurnstileVerifierAcceptsSuccessfulVerification(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}

		var req siteVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Secret != "secret-key" {
			t.Fatalf("expected secret key, got %q", req.Secret)
		}
		if req.Response != "token" {
			t.Fatalf("expected token, got %q", req.Response)
		}
		if req.RemoteIP != "192.0.2.10" {
			t.Fatalf("expected remote ip, got %q", req.RemoteIP)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer server.Close()

	verifier := NewCloudflareTurnstileVerifier(CloudflareTurnstileConfig{
		SecretKey: "secret-key",
		VerifyURL: server.URL,
		Timeout:   time.Second,
	})

	if err := verifier.Verify(context.Background(), dexbotkiller.ChallengeVerification{
		Provider: dexbotkiller.ChallengeProviderCloudflareTurnstile,
		Token:    "token",
		RemoteIP: "192.0.2.10",
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestCloudflareTurnstileVerifierRejectsFailedVerification(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":false,"error-codes":["timeout-or-duplicate"]}`))
	}))
	defer server.Close()

	verifier := NewCloudflareTurnstileVerifier(CloudflareTurnstileConfig{
		SecretKey: "secret-key",
		VerifyURL: server.URL,
		Timeout:   time.Second,
	})

	if err := verifier.Verify(context.Background(), dexbotkiller.ChallengeVerification{
		Provider: dexbotkiller.ChallengeProviderCloudflareTurnstile,
		Token:    "token",
	}); err == nil {
		t.Fatal("expected failed verification error")
	}
}
