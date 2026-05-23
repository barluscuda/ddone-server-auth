package config

import "testing"

func TestValidateRejectsSameSiteNoneWithoutSecure(t *testing.T) {
	cfg := validConfig()
	cfg.Auth.RefreshCookieSameSite = "none"
	cfg.Auth.RefreshCookieSecure = false

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected validate to reject SameSite=None without Secure")
	}
}

func TestValidateAllowsSameSiteNoneWithSecure(t *testing.T) {
	cfg := validConfig()
	cfg.Auth.RefreshCookieSameSite = "none"
	cfg.Auth.RefreshCookieSecure = true

	if err := cfg.validate(); err != nil {
		t.Fatalf("expected validate to allow SameSite=None with Secure, got %v", err)
	}
}

func validConfig() Config {
	var cfg Config
	cfg.App.Port = 3000
	cfg.Database.URL = "postgres://localhost/ddone_auth"
	cfg.Redis.URL = "redis://localhost:6379/0"
	cfg.CORS.AllowedOrigins = []string{"http://localhost:5173"}
	cfg.CORS.AllowedMethods = []string{"GET", "POST"}
	cfg.CORS.AllowedHeaders = []string{"Origin", "Content-Type"}
	cfg.Auth.Issuer = "issuer"
	cfg.Auth.Audience = "audience"
	cfg.Auth.AccessTokenTTL = 1
	cfg.Auth.RefreshTokenTTL = 1
	cfg.Auth.SigningKeyRotation = 1
	cfg.Auth.SigningKeyRetention = 1
	cfg.Auth.RefreshCookieName = "ddone_refresh_token"
	cfg.Auth.RefreshCookieSecure = true
	cfg.Auth.RefreshCookieSameSite = "lax"
	return cfg
}
