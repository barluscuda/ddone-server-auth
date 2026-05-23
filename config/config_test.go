package config

import "testing"

func TestValidateRejectsCredentialsWithWildcardOrigin(t *testing.T) {
	cfg := validConfig()
	cfg.CORS.AllowedOrigins = []string{"*"}
	cfg.CORS.AllowCredentials = true

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected validate to reject wildcard origin when credentials are allowed")
	}
}

func TestValidateAllowsCredentialsWithExplicitOrigin(t *testing.T) {
	cfg := validConfig()
	cfg.CORS.AllowedOrigins = []string{"http://localhost:5173"}
	cfg.CORS.AllowCredentials = true

	if err := cfg.validate(); err != nil {
		t.Fatalf("expected validate to allow explicit origin with credentials, got %v", err)
	}
}

func TestValidateRejectsSessionCookieSameSiteNoneWithoutSecure(t *testing.T) {
	cfg := validConfig()
	cfg.Auth.SessionCookieSameSite = "none"
	cfg.Auth.SessionCookieSecure = false

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected validate to reject SameSite=None without Secure")
	}
}

func TestValidateRejectsNegativeCacheTTL(t *testing.T) {
	cfg := validConfig()
	cfg.Cache.AccountTTL = -1

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected validate to reject negative cache ttl")
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
	cfg.Auth.SessionCookieName = "ddone_session"
	cfg.Auth.SessionCookieSecure = true
	cfg.Auth.SessionCookieSameSite = "lax"
	cfg.Auth.SessionCookieMaxAge = 1
	return cfg
}
