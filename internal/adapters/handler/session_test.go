package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ddone-server-auth/internal/adapters/middleware"
	appsession "ddone-server-auth/internal/application/session"
	"ddone-server-auth/internal/domain/auth"

	"github.com/gin-gonic/gin"
)

func testSessionHandlerCookieConfig() SessionCookieConfig {
	return SessionCookieConfig{
		Name:     "ddone_session",
		MaxAge:   30 * 24 * time.Hour,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}
}

type fakeSessionUseCase struct {
	sessions        []appsession.View
	current         *appsession.View
	accessToken     *appsession.IssueAccessTokenResult
	listErr         error
	currentErr      error
	tokenErr        error
	revokeErr       error
	revokeOthersErr error
	revokeAllErr    error
}

func (f *fakeSessionUseCase) List(_ context.Context, _ appsession.ListInput) ([]appsession.View, error) {
	return f.sessions, f.listErr
}

func (f *fakeSessionUseCase) Current(_ context.Context, _ appsession.CurrentInput) (*appsession.View, error) {
	return f.current, f.currentErr
}

func (f *fakeSessionUseCase) IssueAccessToken(_ context.Context, _ appsession.IssueAccessTokenInput) (*appsession.IssueAccessTokenResult, error) {
	return f.accessToken, f.tokenErr
}

func (f *fakeSessionUseCase) Revoke(_ context.Context, _ appsession.RevokeInput) error {
	return f.revokeErr
}

func (f *fakeSessionUseCase) RevokeOthers(_ context.Context, _ appsession.RevokeOthersInput) error {
	return f.revokeOthersErr
}

func (f *fakeSessionUseCase) RevokeAll(_ context.Context, _ appsession.RevokeAllInput) error {
	return f.revokeAllErr
}

func TestSessionHandlerReturnsSessions(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewSessionHandler(&fakeSessionUseCase{
		sessions: []appsession.View{
			{
				ID:                   "session-1",
				ClientIP:             "127.0.0.1",
				UserAgent:            "test-agent",
				CurrentAccessExpires: time.Date(2026, 5, 24, 1, 0, 0, 0, time.UTC),
				CreatedAt:            time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
			},
		},
	}, testSessionHandlerCookieConfig())

	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.GET("/sessions", func(c *gin.Context) {
		c.Set("session_context", middleware.SessionContext{UserID: "user-1", SessionID: "session-1"})
		handler.List(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestSessionHandlerReturnsCurrentSession(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewSessionHandler(&fakeSessionUseCase{
		current: &appsession.View{
			ID:                   "session-1",
			CurrentAccessExpires: time.Date(2026, 5, 24, 1, 0, 0, 0, time.UTC),
			CreatedAt:            time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC),
		},
	}, testSessionHandlerCookieConfig())

	req := httptest.NewRequest(http.MethodGet, "/sessions/current", nil)
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.GET("/sessions/current", func(c *gin.Context) {
		c.Set("session_context", middleware.SessionContext{UserID: "user-1", SessionID: "session-1"})
		handler.Current(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestSessionHandlerIssuesAccessToken(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewSessionHandler(&fakeSessionUseCase{
		accessToken: &appsession.IssueAccessTokenResult{
			AccessToken: &auth.AccessToken{
				Token:     "access-token",
				TokenType: "Bearer",
				ExpiresAt: time.Date(2026, 5, 24, 1, 0, 0, 0, time.UTC),
				ExpiresIn: 900,
			},
			Refreshed: true,
		},
	}, testSessionHandlerCookieConfig())

	req := httptest.NewRequest(http.MethodPost, "/sessions/token", nil)
	req.AddCookie(&http.Cookie{Name: "ddone_session", Value: "session-token"})
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.POST("/sessions/token", func(c *gin.Context) {
		c.Set("session_context", middleware.SessionContext{UserID: "user-1", SessionID: "session-1"})
		handler.Token(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if cookie := recorder.Header().Get("Set-Cookie"); cookie == "" {
		t.Fatal("expected session cookie to be refreshed")
	} else if !containsAll(cookie, []string{"ddone_session=session-token", "Max-Age=2592000"}) {
		t.Fatalf("expected refreshed session cookie with same token and max-age, got %q", cookie)
	}
}

func TestSessionHandlerDoesNotRefreshCookieForExistingAccessToken(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewSessionHandler(&fakeSessionUseCase{
		accessToken: &appsession.IssueAccessTokenResult{
			AccessToken: &auth.AccessToken{
				Token:     "access-token",
				TokenType: "Bearer",
				ExpiresAt: time.Date(2026, 5, 24, 1, 0, 0, 0, time.UTC),
				ExpiresIn: 900,
			},
			Refreshed: false,
		},
	}, testSessionHandlerCookieConfig())

	req := httptest.NewRequest(http.MethodPost, "/sessions/token", nil)
	req.AddCookie(&http.Cookie{Name: "ddone_session", Value: "session-token"})
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.POST("/sessions/token", func(c *gin.Context) {
		c.Set("session_context", middleware.SessionContext{UserID: "user-1", SessionID: "session-1"})
		handler.Token(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if cookie := recorder.Header().Get("Set-Cookie"); cookie != "" {
		t.Fatalf("expected no cookie refresh for existing access token, got %q", cookie)
	}
}

func TestSessionHandlerRevokesSession(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewSessionHandler(&fakeSessionUseCase{}, testSessionHandlerCookieConfig())

	req := httptest.NewRequest(http.MethodDelete, "/sessions/session-1", nil)
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.DELETE("/sessions/:sessionId", func(c *gin.Context) {
		c.Set("session_context", middleware.SessionContext{UserID: "user-1", SessionID: "session-1"})
		handler.Revoke(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestSessionHandlerRevokesAllSessions(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewSessionHandler(&fakeSessionUseCase{}, testSessionHandlerCookieConfig())

	req := httptest.NewRequest(http.MethodPost, "/sessions/revoke-all", nil)
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.POST("/sessions/revoke-all", func(c *gin.Context) {
		c.Set("session_context", middleware.SessionContext{UserID: "user-1", SessionID: "session-1"})
		handler.RevokeAll(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestSessionHandlerRevokesOtherSessions(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	gin.SetMode(gin.TestMode)

	handler := NewSessionHandler(&fakeSessionUseCase{}, testSessionHandlerCookieConfig())

	req := httptest.NewRequest(http.MethodPost, "/sessions/revoke-others", nil)
	recorder := httptest.NewRecorder()

	router := gin.New()
	router.POST("/sessions/revoke-others", func(c *gin.Context) {
		c.Set("session_context", middleware.SessionContext{UserID: "user-1", SessionID: "session-1"})
		handler.RevokeOthers(c)
	})
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func containsAll(value string, parts []string) bool {
	for _, part := range parts {
		if !strings.Contains(value, part) {
			return false
		}
	}

	return true
}
