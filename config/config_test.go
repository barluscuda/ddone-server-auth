package config

import (
	"testing"
	"time"
)

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

func TestValidateRejectsNonPositiveLoginSessionTTL(t *testing.T) {
	cfg := validConfig()
	cfg.Auth.LoginSessionTTL = 0

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected validate to reject non-positive login session ttl")
	}
}

func TestValidateRejectsSessionCookieMaxAgeLongerThanLoginSessionTTL(t *testing.T) {
	cfg := validConfig()
	cfg.Auth.LoginSessionTTL = time.Hour
	cfg.Auth.SessionCookieMaxAge = 2 * time.Hour

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected validate to reject session cookie max age longer than login session ttl")
	}
}

func TestEffectiveSessionCookieMaxAgeDefaultsToLoginSessionTTL(t *testing.T) {
	cfg := validConfig()
	cfg.Auth.LoginSessionTTL = 24 * time.Hour
	cfg.Auth.SessionCookieMaxAge = 0

	if got, want := cfg.Auth.EffectiveSessionCookieMaxAge(), 24*time.Hour; got != want {
		t.Fatalf("expected effective session cookie max age %v, got %v", want, got)
	}
}

func TestValidateRejectsNegativeCacheTTL(t *testing.T) {
	cfg := validConfig()
	cfg.Cache.UserTTL = -1

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected validate to reject negative cache ttl")
	}
}

func TestValidateRejectsNonPositiveOTPRegisterTTL(t *testing.T) {
	cfg := validConfig()
	cfg.OTP.Register.TTL = 0

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected validate to reject non-positive register otp ttl")
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
	cfg.OTP.Register.TTL = time.Minute
	cfg.OTP.Register.PhoneWindow = time.Minute
	cfg.OTP.Register.ResendCooldown = time.Second
	cfg.OTP.Register.VerifyAttemptWindow = time.Minute
	cfg.OTP.Register.MaxPhoneRequests = 1
	cfg.OTP.Register.MaxResends = 1
	cfg.OTP.Register.MaxVerifyAttempts = 1
	cfg.OTP.PasswordReset.TTL = time.Minute
	cfg.OTP.PasswordReset.PhoneWindow = time.Minute
	cfg.OTP.PasswordReset.ResendCooldown = time.Second
	cfg.OTP.PasswordReset.VerifyAttemptWindow = time.Minute
	cfg.OTP.PasswordReset.MaxPhoneRequests = 1
	cfg.OTP.PasswordReset.MaxResends = 1
	cfg.OTP.PasswordReset.MaxVerifyAttempts = 1
	cfg.Auth.Issuer = "issuer"
	cfg.Auth.Audience = "audience"
	cfg.Auth.AccessTokenTTL = 1
	cfg.Auth.RefreshTokenTTL = 1
	cfg.Auth.LoginSessionTTL = 1
	cfg.Auth.SigningKeyRotation = 1
	cfg.Auth.SigningKeyRetention = 1
	cfg.Auth.SessionCookieName = "ddone_session"
	cfg.Auth.SessionCookieSecure = true
	cfg.Auth.SessionCookieSameSite = "lax"
	cfg.Auth.SessionCookieMaxAge = 0
	return cfg
}
