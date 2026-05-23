package handler

import (
	"bytes"
	"context"
	applogin "ddone-server-auth/internal/application/login"
	"ddone-server-auth/internal/domain/auth"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func testSessionCookieConfig() SessionCookieConfig {
	return SessionCookieConfig{
		Name:     "ddone_session",
		MaxAge:   30 * 24 * time.Hour,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}
}

type fakeLoginUseCase struct {
	loginResult   *applogin.Result
	loginErr      error
	refreshResult *applogin.Result
	refreshErr    error
	sessionResult *applogin.SessionResult
	sessionErr    error
}

func (f *fakeLoginUseCase) Login(_ context.Context, _ applogin.LoginInput) (*applogin.Result, error) {
	return f.loginResult, f.loginErr
}

func (f *fakeLoginUseCase) Refresh(_ context.Context, _ applogin.RefreshInput) (*applogin.Result, error) {
	return f.refreshResult, f.refreshErr
}

func (f *fakeLoginUseCase) LoginSession(_ context.Context, _ applogin.LoginInput) (*applogin.SessionResult, error) {
	return f.sessionResult, f.sessionErr
}

func (f *fakeLoginUseCase) SessionToken(_ context.Context, _ applogin.SessionTokenInput) (*applogin.SessionResult, error) {
	return f.sessionResult, f.sessionErr
}

type fakeJWKSUseCase struct {
	set *auth.JWKSet
	err error
}

func (f *fakeJWKSUseCase) PublicJWKS(_ context.Context) (*auth.JWKSet, error) {
	return f.set, f.err
}

func TestLoginHandlerReturnsRefreshTokenWithoutSettingCookie(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewLoginHandler(&fakeLoginUseCase{
		loginResult: &applogin.Result{
			AccessToken: &auth.AccessToken{
				Token:     "access-token",
				TokenType: "Bearer",
				ExpiresAt: time.Date(2026, 5, 23, 10, 15, 0, 0, time.UTC),
				ExpiresIn: 900,
			},
			RefreshToken:     "refresh-token",
			RefreshExpiresAt: time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC),
		},
	}, testSessionCookieConfig())

	body, err := json.Marshal(map[string]string{
		"phoneNumber": "+8562012345678",
		"password":    "secretpass",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.POST("/tokens", handler.Login)
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if cookie := recorder.Header().Get("Set-Cookie"); cookie != "" {
		t.Fatalf("expected body login flow to avoid Set-Cookie, got %q", cookie)
	}
	if !strings.Contains(recorder.Body.String(), "refresh-token") {
		t.Fatal("expected refresh token in response body")
	}
}

func TestRefreshHandlerReturnsRefreshTokenWithoutSettingCookie(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewLoginHandler(&fakeLoginUseCase{
		refreshResult: &applogin.Result{
			AccessToken: &auth.AccessToken{
				Token:     "access-token",
				TokenType: "Bearer",
				ExpiresAt: time.Date(2026, 5, 23, 10, 15, 0, 0, time.UTC),
				ExpiresIn: 900,
			},
			RefreshToken:     "rotated-refresh-token",
			RefreshExpiresAt: time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC),
		},
	}, testSessionCookieConfig())

	body, err := json.Marshal(map[string]string{
		"refreshToken": "refresh-token",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/tokens/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.POST("/tokens/refresh", handler.Refresh)
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if cookie := recorder.Header().Get("Set-Cookie"); cookie != "" {
		t.Fatalf("expected body refresh flow to avoid Set-Cookie, got %q", cookie)
	}
	if !strings.Contains(recorder.Body.String(), "rotated-refresh-token") {
		t.Fatal("expected rotated refresh token in response body")
	}
}

func TestLoginSessionHandlerSetsSessionCookie(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewLoginHandler(&fakeLoginUseCase{
		sessionResult: &applogin.SessionResult{
			SessionToken: "session-token",
			AccessToken: &auth.AccessToken{
				Token:     "access-token",
				TokenType: "Bearer",
				ExpiresAt: time.Date(2026, 5, 23, 10, 15, 0, 0, time.UTC),
				ExpiresIn: 900,
			},
		},
	}, testSessionCookieConfig())

	body, err := json.Marshal(map[string]string{
		"phoneNumber": "+8562012345678",
		"password":    "secretpass",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.POST("/sessions", handler.LoginSession)
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if cookie := recorder.Header().Get("Set-Cookie"); cookie == "" {
		t.Fatal("expected session cookie to be set")
	} else if !strings.Contains(cookie, "Max-Age=2592000") {
		t.Fatalf("expected session cookie max-age to match configured ttl, got %q", cookie)
	}
	if strings.Contains(recorder.Body.String(), "access-token") {
		t.Fatal("expected access token to be omitted from session login response body")
	}
	if strings.Contains(recorder.Body.String(), "session-token") {
		t.Fatal("expected session token to be omitted from session login response body")
	}
}

func TestSessionTokenHandlerReturnsAccessTokenFromSessionCookie(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewLoginHandler(&fakeLoginUseCase{
		sessionResult: &applogin.SessionResult{
			AccessToken: &auth.AccessToken{
				Token:     "access-token",
				TokenType: "Bearer",
				ExpiresAt: time.Date(2026, 5, 23, 10, 15, 0, 0, time.UTC),
				ExpiresIn: 900,
			},
		},
	}, testSessionCookieConfig())

	req := httptest.NewRequest(http.MethodPost, "/sessions/token", nil)
	req.AddCookie(&http.Cookie{Name: "ddone_session", Value: "session-token"})
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.POST("/sessions/token", handler.SessionToken)
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "access-token") {
		t.Fatal("expected access token in response body")
	}
	if strings.Contains(recorder.Body.String(), "session-token") {
		t.Fatal("expected session token to be omitted from token response body")
	}
}

func TestJWKSHandlerReturnsKeys(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewJWKSHandler(&fakeJWKSUseCase{
		set: &auth.JWKSet{
			Keys: []auth.JWK{
				{
					KeyType:   "EC",
					Use:       "sig",
					Curve:     "P-256",
					Algorithm: "ES256",
					KeyID:     "kid-1",
					X:         "x",
					Y:         "y",
				},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.GET("/.well-known/jwks.json", handler.PublicJWKS)
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if recorder.Header().Get("ETag") == "" {
		t.Fatal("expected etag header")
	}
}
