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
	cfg.Security.Auth.SessionCookieSameSite = "none"
	cfg.Security.Auth.SessionCookieSecure = false

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected validate to reject SameSite=None without Secure")
	}
}

func TestValidateRejectsNonPositiveLoginSessionTTL(t *testing.T) {
	cfg := validConfig()
	cfg.Security.Auth.LoginSessionTTL = 0

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected validate to reject non-positive login session ttl")
	}
}

func TestValidateRejectsSessionCookieMaxAgeLongerThanLoginSessionTTL(t *testing.T) {
	cfg := validConfig()
	cfg.Security.Auth.LoginSessionTTL = time.Hour
	cfg.Security.Auth.SessionCookieMaxAge = 2 * time.Hour

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected validate to reject session cookie max age longer than login session ttl")
	}
}

func TestEffectiveSessionCookieMaxAgeDefaultsToLoginSessionTTL(t *testing.T) {
	cfg := validConfig()
	cfg.Security.Auth.LoginSessionTTL = 24 * time.Hour
	cfg.Security.Auth.SessionCookieMaxAge = 0

	if got, want := cfg.Security.Auth.EffectiveSessionCookieMaxAge(), 24*time.Hour; got != want {
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

func TestValidateRejectsNegativeMaxRequestBodyBytes(t *testing.T) {
	cfg := validConfig()
	cfg.App.MaxRequestBodyBytes = -1

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected validate to reject negative max request body bytes")
	}
}

func TestValidateRejectsEnabledDexBotKillerWithoutPepper(t *testing.T) {
	cfg := validConfig()
	cfg.DexBotKiller.Enabled = true
	cfg.DexBotKiller.Pepper = ""

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected validate to reject enabled dexbotkiller without pepper")
	}
}

func TestValidateAllowsEnabledDexBotKillerWithPepper(t *testing.T) {
	cfg := validConfig()
	cfg.DexBotKiller.Enabled = true
	cfg.DexBotKiller.Pepper = "test-pepper"

	if err := cfg.validate(); err != nil {
		t.Fatalf("expected validate to allow enabled dexbotkiller with pepper, got %v", err)
	}
}

func TestValidateRejectsDexBotKillerChallengeModeWithoutTurnstileKeys(t *testing.T) {
	cfg := validConfig()
	cfg.DexBotKiller.Enabled = true
	cfg.DexBotKiller.Mode = "challenge"
	cfg.DexBotKiller.Pepper = "test-pepper"
	cfg.DexBotKiller.CloudflareTurnstile.SiteKey = ""
	cfg.DexBotKiller.CloudflareTurnstile.SecretKey = ""

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected validate to reject challenge mode without turnstile keys")
	}
}

func TestValidateAllowsDexBotKillerChallengeModeWithTurnstileKeys(t *testing.T) {
	cfg := validConfig()
	cfg.DexBotKiller.Enabled = true
	cfg.DexBotKiller.Mode = "challenge"
	cfg.DexBotKiller.Pepper = "test-pepper"
	cfg.DexBotKiller.CloudflareTurnstile.SiteKey = "site-key"
	cfg.DexBotKiller.CloudflareTurnstile.SecretKey = "secret-key"

	if err := cfg.validate(); err != nil {
		t.Fatalf("expected validate to allow challenge mode with turnstile keys, got %v", err)
	}
}

func TestValidateRejectsTrustAllProxyCIDR(t *testing.T) {
	cfg := validConfig()
	cfg.App.TrustedProxies = []string{"0.0.0.0/0"}

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected validate to reject trust-all proxy CIDR")
	}
}

func TestValidateRejectsNonPositiveLoginRateLimitWindow(t *testing.T) {
	cfg := validConfig()
	cfg.Security.Login.FailedAttemptWindow = 0

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected validate to reject non-positive login rate limit window")
	}
}

func TestValidateRejectsNonPositiveOTPRegisterTTL(t *testing.T) {
	cfg := validConfig()
	cfg.Security.OTP.Register.TTL = 0

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected validate to reject non-positive register otp ttl")
	}
}

func TestValidateRejectsNonPositiveOTPRegisterSystemWindow(t *testing.T) {
	cfg := validConfig()
	cfg.Security.OTP.Register.SystemWindow = 0

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected validate to reject non-positive register otp system window")
	}
}

func TestValidateRejectsNonPositiveOTPRegisterSystemLimit(t *testing.T) {
	cfg := validConfig()
	cfg.Security.OTP.Register.MaxSystemRequests = 0

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected validate to reject non-positive register otp system request limit")
	}
}

func validConfig() Config {
	var cfg Config
	cfg.App.Port = 3000
	cfg.App.MaxRequestBodyBytes = 1 << 20
	cfg.Database.Host = "localhost"
	cfg.Database.Port = 5432
	cfg.Database.Name = "ddone_auth"
	cfg.Database.Username = "postgres"
	cfg.Database.SSLMode = "disable"
	cfg.Database.TimeZone = "UTC"
	cfg.Redis.Host = "localhost"
	cfg.Redis.Port = 6379
	cfg.DexBotKiller.Mode = "passive"
	cfg.DexBotKiller.RedisPrefix = "dbk:v1"
	cfg.DexBotKiller.CounterWindow = time.Minute
	cfg.DexBotKiller.UniqueWindow = 15 * time.Minute
	cfg.DexBotKiller.ScoreTTL = 24 * time.Hour
	cfg.DexBotKiller.Delay = 500 * time.Millisecond
	cfg.DexBotKiller.Thresholds.DelayScore = 3
	cfg.DexBotKiller.Thresholds.ChallengeScore = 6
	cfg.DexBotKiller.Thresholds.BlockScore = 10
	cfg.DexBotKiller.CloudflareTurnstile.VerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	cfg.DexBotKiller.CloudflareTurnstile.Timeout = 3 * time.Second
	cfg.DexBotKiller.DeviceCookieName = "ddone_device"
	cfg.DexBotKiller.DeviceCookieMaxAge = 24 * time.Hour
	cfg.DexBotKiller.DeviceCookieSecure = true
	cfg.DexBotKiller.DeviceCookieSameSite = "lax"
	cfg.CORS.AllowedOrigins = []string{"http://localhost:5173"}
	cfg.CORS.AllowedMethods = []string{"GET", "POST"}
	cfg.CORS.AllowedHeaders = []string{"Origin", "Content-Type"}
	cfg.Security.Login.FailedAttemptWindow = time.Minute
	cfg.Security.Login.MaxAttempts = 1
	cfg.Security.Login.LockoutDuration = time.Minute
	cfg.Security.OTP.Register.TTL = time.Minute
	cfg.Security.OTP.Register.PhoneWindow = time.Minute
	cfg.Security.OTP.Register.SystemWindow = time.Minute
	cfg.Security.OTP.Register.ResendCooldown = time.Second
	cfg.Security.OTP.Register.VerifyAttemptWindow = time.Minute
	cfg.Security.OTP.Register.MaxPhoneRequests = 1
	cfg.Security.OTP.Register.MaxSystemRequests = 1
	cfg.Security.OTP.Register.MaxResends = 1
	cfg.Security.OTP.Register.MaxVerifyAttempts = 1
	cfg.Security.OTP.PasswordReset.TTL = time.Minute
	cfg.Security.OTP.PasswordReset.PhoneWindow = time.Minute
	cfg.Security.OTP.PasswordReset.ResendCooldown = time.Second
	cfg.Security.OTP.PasswordReset.VerifyAttemptWindow = time.Minute
	cfg.Security.OTP.PasswordReset.MaxPhoneRequests = 1
	cfg.Security.OTP.PasswordReset.MaxResends = 1
	cfg.Security.OTP.PasswordReset.MaxVerifyAttempts = 1
	cfg.Security.Auth.Issuer = "issuer"
	cfg.Security.Auth.Audience = "audience"
	cfg.Security.Auth.AccessTokenTTL = 1
	cfg.Security.Auth.RefreshTokenTTL = 1
	cfg.Security.Auth.LoginSessionTTL = 1
	cfg.Security.Auth.SigningKeyRotation = 1
	cfg.Security.Auth.SigningKeyRetention = 1
	cfg.Security.Auth.SessionCookieName = "ddone_session"
	cfg.Security.Auth.SessionCookieSecure = true
	cfg.Security.Auth.SessionCookieSameSite = "lax"
	cfg.Security.Auth.SessionCookieMaxAge = 0
	return cfg
}
