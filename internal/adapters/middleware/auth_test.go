package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ddone-server-auth/internal/domain/auth"

	"github.com/gin-gonic/gin"
)

type fakeAccessTokenVerifier struct {
	claims *auth.AccessTokenClaims
	err    error
}

func (v *fakeAccessTokenVerifier) VerifyAccessToken(_ context.Context, _ string) (*auth.AccessTokenClaims, error) {
	return v.claims, v.err
}

func TestRequireAccessTokenRejectsMissingHeader(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RequireAccessToken(&fakeAccessTokenVerifier{}))
	router.GET("/account/me", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/account/me", nil)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, recorder.Code)
	}
}

func TestRequireAccessTokenSetsAuthContext(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RequireAccessToken(&fakeAccessTokenVerifier{
		claims: &auth.AccessTokenClaims{
			Subject:     "account-1",
			PhoneNumber: "2012345678",
			JWTID:       "token-1",
			ExpiresAt:   time.Now().UTC().Add(time.Minute),
		},
	}))
	router.GET("/account/me", func(c *gin.Context) {
		authContext, ok := CurrentAuth(c)
		if !ok {
			t.Fatal("expected auth context")
		}
		if authContext.AccountID != "account-1" {
			t.Fatalf("expected account id %q, got %q", "account-1", authContext.AccountID)
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/account/me", nil)
	req.Header.Set("Authorization", "Bearer access-token")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}
