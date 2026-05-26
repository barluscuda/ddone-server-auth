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
	router.GET("/settings/me", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/settings/me", nil)
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
			Subject:     "user-1",
			PhoneNumber: "+8562012345678",
			JWTID:       "token-1",
			ExpiresAt:   time.Now().UTC().Add(time.Minute),
		},
	}))
	router.GET("/settings/me", func(c *gin.Context) {
		authContext, ok := CurrentAuth(c)
		if !ok {
			t.Fatal("expected auth context")
		}
		if authContext.UserID != "user-1" {
			t.Fatalf("expected user id %q, got %q", "user-1", authContext.UserID)
		}
		if authContext.AccessToken != "access-token" {
			t.Fatalf("expected access token %q, got %q", "access-token", authContext.AccessToken)
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/settings/me", nil)
	req.Header.Set("Authorization", "Bearer access-token")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

type fakeSessionLookup struct {
	session *auth.LoginSession
	err     error
}

func (f *fakeSessionLookup) GetByTokenHash(_ context.Context, _ string) (*auth.LoginSession, error) {
	return f.session, f.err
}

func TestRequireSessionRejectsMissingCookie(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RequireSession("ddone_session", &fakeSessionLookup{}))
	router.GET("/sessions/current", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/sessions/current", nil)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, recorder.Code)
	}
}

func TestRequireSessionSetsSessionContext(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RequireSession("ddone_session", &fakeSessionLookup{
		session: &auth.LoginSession{
			ID:        "session-1",
			UserID:    "user-1",
			ExpiresAt: time.Now().UTC().Add(time.Minute),
		},
	}))
	router.GET("/sessions/current", func(c *gin.Context) {
		sessionContext, ok := CurrentSession(c)
		if !ok {
			t.Fatal("expected session context")
		}
		if sessionContext.SessionID != "session-1" {
			t.Fatalf("expected session id %q, got %q", "session-1", sessionContext.SessionID)
		}
		if sessionContext.UserID != "user-1" {
			t.Fatalf("expected user id %q, got %q", "user-1", sessionContext.UserID)
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/sessions/current", nil)
	req.AddCookie(&http.Cookie{Name: "ddone_session", Value: "session-token"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestRequireSessionRejectsUnsafeCrossOriginRequest(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RequireSession("ddone_session", &fakeSessionLookup{
		session: &auth.LoginSession{
			ID:        "session-1",
			UserID:    "user-1",
			ExpiresAt: time.Now().UTC().Add(time.Minute),
		},
	}, []string{"https://app.example.com"}))
	router.POST("/sessions/revoke-all", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/sessions/revoke-all", nil)
	req.Host = "api.example.com"
	req.Header.Set("Origin", "https://evil.example.net")
	req.AddCookie(&http.Cookie{Name: "ddone_session", Value: "session-token"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}
}

func TestRequireSessionAllowsConfiguredOriginForUnsafeRequest(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RequireSession("ddone_session", &fakeSessionLookup{
		session: &auth.LoginSession{
			ID:        "session-1",
			UserID:    "user-1",
			ExpiresAt: time.Now().UTC().Add(time.Minute),
		},
	}, []string{"https://app.example.com"}))
	router.POST("/sessions/revoke-all", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/sessions/revoke-all", nil)
	req.Host = "api.example.com"
	req.Header.Set("Origin", "https://app.example.com")
	req.AddCookie(&http.Cookie{Name: "ddone_session", Value: "session-token"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestRequireSessionRejectsUnsafeRequestWithoutOriginOrReferer(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RequireSession("ddone_session", &fakeSessionLookup{
		session: &auth.LoginSession{
			ID:        "session-1",
			UserID:    "user-1",
			ExpiresAt: time.Now().UTC().Add(time.Minute),
		},
	}, []string{"https://app.example.com"}))
	router.POST("/sessions/token", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/sessions/token", nil)
	req.Host = "api.example.com"
	req.AddCookie(&http.Cookie{Name: "ddone_session", Value: "session-token"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}
}

func TestRequireSessionDoesNotTrustWildcardOriginForUnsafeRequest(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RequireSession("ddone_session", &fakeSessionLookup{
		session: &auth.LoginSession{
			ID:        "session-1",
			UserID:    "user-1",
			ExpiresAt: time.Now().UTC().Add(time.Minute),
		},
	}, []string{"*"}))
	router.POST("/sessions/revoke-all", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/sessions/revoke-all", nil)
	req.Host = "api.example.com"
	req.Header.Set("Origin", "https://evil.example.net")
	req.AddCookie(&http.Cookie{Name: "ddone_session", Value: "session-token"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, recorder.Code)
	}
}
