package handler

import (
	"bytes"
	"context"
	applogin "ddone-server-auth/internal/application/login"
	"ddone-server-auth/internal/domain/auth"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

type fakeLoginUseCase struct {
	loginResult   *applogin.Result
	loginErr      error
	refreshResult *applogin.Result
	refreshErr    error
}

func (f *fakeLoginUseCase) Login(_ context.Context, _ applogin.LoginInput) (*applogin.Result, error) {
	return f.loginResult, f.loginErr
}

func (f *fakeLoginUseCase) Refresh(_ context.Context, _ applogin.RefreshInput) (*applogin.Result, error) {
	return f.refreshResult, f.refreshErr
}

func (f *fakeLoginUseCase) RefreshFromCookieToken(_ context.Context, _ applogin.RefreshInput) (*applogin.Result, error) {
	return f.refreshResult, f.refreshErr
}

type fakeJWKSUseCase struct {
	set *auth.JWKSet
	err error
}

func (f *fakeJWKSUseCase) PublicJWKS(_ context.Context) (*auth.JWKSet, error) {
	return f.set, f.err
}

func TestLoginHandlerSetsRefreshCookie(t *testing.T) {
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
	}, RefreshCookieConfig{
		Name:     "ddone_refresh_token",
		MaxAge:   30 * 24 * time.Hour,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})

	body, err := json.Marshal(map[string]string{
		"phone_number": "+8562012345678",
		"password":     "secretpass",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.POST("/login", handler.Login)
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if cookie := recorder.Header().Get("Set-Cookie"); cookie == "" {
		t.Fatal("expected refresh cookie to be set")
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
