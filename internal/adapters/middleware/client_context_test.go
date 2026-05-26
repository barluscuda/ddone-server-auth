package middleware

import (
	"ddone-server-auth/internal/application/dexbotkiller"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestClientContextIssuesSignedDeviceCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	hasher, err := dexbotkiller.NewHasher("test-pepper")
	if err != nil {
		t.Fatalf("new hasher: %v", err)
	}

	router := gin.New()
	router.Use(ClientContext(ClientContextConfig{
		DeviceCookieName:   "ddone_device",
		DeviceCookieMaxAge: time.Hour,
	}, hasher))
	router.GET("/", func(c *gin.Context) {
		clientContext, ok := dexbotkiller.ClientContextFromContext(c.Request.Context())
		if !ok {
			t.Fatal("expected client context")
		}
		if clientContext.DeviceID == "" {
			t.Fatal("expected generated device id")
		}
		if clientContext.HasDeviceCookie {
			t.Fatal("expected first request to be marked as missing device cookie")
		}
		c.Status(http.StatusNoContent)
	})

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", recorder.Code)
	}
	if len(recorder.Result().Cookies()) == 0 {
		t.Fatal("expected device cookie")
	}
}

func TestClientContextReadsValidDeviceCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	hasher, err := dexbotkiller.NewHasher("test-pepper")
	if err != nil {
		t.Fatalf("new hasher: %v", err)
	}

	router := gin.New()
	router.Use(ClientContext(ClientContextConfig{DeviceCookieName: "ddone_device"}, hasher))
	router.GET("/", func(c *gin.Context) {
		clientContext, ok := dexbotkiller.ClientContextFromContext(c.Request.Context())
		if !ok {
			t.Fatal("expected client context")
		}
		if clientContext.DeviceID != "known-device" {
			t.Fatalf("expected known device id, got %q", clientContext.DeviceID)
		}
		if !clientContext.HasDeviceCookie {
			t.Fatal("expected valid device cookie flag")
		}
		c.Status(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{
		Name:  "ddone_device",
		Value: "known-device." + hasher.Sign("known-device"),
	})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", recorder.Code)
	}
}
