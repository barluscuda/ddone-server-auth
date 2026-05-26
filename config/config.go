package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

type Config struct {
	App struct {
		Debug               bool
		Port                int
		TrustedProxies      []string `mapstructure:"trusted_proxies"`
		MaxRequestBodyBytes int64    `mapstructure:"max_request_body_bytes"`
	}
	Database     DatabaseConfig
	Redis        RedisConfig
	Cache        CacheConfig
	DexBotKiller DexBotKillerConfig `mapstructure:"dexbotkiller"`
	Security     SecurityConfig
	CORS         CORSConfig
	WenovaAPI    WenovaAPIConfig
}

type DatabaseConfig struct {
	Host            string
	Port            int
	Name            string
	Username        string
	Password        string
	SSLMode         string
	TimeZone        string
	ConnectTimeout  int
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
	LogSQL          bool `mapstructure:"log_sql"`
}

type RedisConfig struct {
	Host         string
	Port         int
	Username     string
	Password     string
	DB           int
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	PoolSize     int
	MinIdleConns int
}

type CacheConfig struct {
	UserTTL            time.Duration `mapstructure:"user_ttl"`
	UserSessionListTTL time.Duration `mapstructure:"user_session_list_ttl"`
	SigningKeysTTL     time.Duration `mapstructure:"signing_keys_ttl"`
}

type WenovaAPIConfig struct {
	Token string
}

type DexBotKillerConfig struct {
	Enabled              bool
	Mode                 string
	RedisPrefix          string `mapstructure:"redis_prefix"`
	Pepper               string
	CounterWindow        time.Duration `mapstructure:"counter_window"`
	UniqueWindow         time.Duration `mapstructure:"unique_window"`
	ScoreTTL             time.Duration `mapstructure:"score_ttl"`
	Delay                time.Duration
	Thresholds           DexBotKillerThresholdsConfig
	CloudflareTurnstile  CloudflareTurnstileConfig `mapstructure:"cloudflare_turnstile"`
	DeviceCookieName     string                    `mapstructure:"device_cookie_name"`
	DeviceCookieMaxAge   time.Duration             `mapstructure:"device_cookie_max_age"`
	DeviceCookieSecure   bool                      `mapstructure:"device_cookie_secure"`
	DeviceCookieSameSite string                    `mapstructure:"device_cookie_same_site"`
}

type DexBotKillerThresholdsConfig struct {
	DelayScore     float64 `mapstructure:"delay_score"`
	ChallengeScore float64 `mapstructure:"challenge_score"`
	BlockScore     float64 `mapstructure:"block_score"`
}

type CloudflareTurnstileConfig struct {
	SiteKey   string        `mapstructure:"site_key"`
	SecretKey string        `mapstructure:"secret_key"`
	VerifyURL string        `mapstructure:"verify_url"`
	Timeout   time.Duration `mapstructure:"timeout"`
}

type SecurityConfig struct {
	Login LoginConfig `mapstructure:"login"`
	OTP   OTPConfig   `mapstructure:"otp"`
	Auth  AuthConfig  `mapstructure:"auth"`
}

type OTPConfig struct {
	Register      RegisterOTPPolicyConfig `mapstructure:"register"`
	PasswordReset OTPPolicyConfig         `mapstructure:"password_reset"`
}

type OTPPolicyConfig struct {
	TTL                 time.Duration `mapstructure:"ttl"`
	PhoneWindow         time.Duration `mapstructure:"phone_window"`
	ResendCooldown      time.Duration `mapstructure:"resend_cooldown"`
	VerifyAttemptWindow time.Duration `mapstructure:"verify_attempt_window"`
	MaxPhoneRequests    int           `mapstructure:"max_phone_requests"`
	MaxResends          int           `mapstructure:"max_resends"`
	MaxVerifyAttempts   int           `mapstructure:"max_verify_attempts"`
}

type RegisterOTPPolicyConfig struct {
	OTPPolicyConfig   `mapstructure:",squash"`
	SystemWindow      time.Duration `mapstructure:"system_window"`
	MaxSystemRequests int           `mapstructure:"max_system_requests"`
}

type LoginConfig struct {
	FailedAttemptWindow time.Duration `mapstructure:"failed_attempt_window"`
	MaxAttempts         int           `mapstructure:"max_attempts"`
	LockoutDuration     time.Duration `mapstructure:"lockout_duration"`
}

type CORSConfig struct {
	AllowedOrigins   []string      `mapstructure:"allowed_origins"`
	AllowedMethods   []string      `mapstructure:"allowed_methods"`
	AllowedHeaders   []string      `mapstructure:"allowed_headers"`
	ExposedHeaders   []string      `mapstructure:"exposed_headers"`
	AllowCredentials bool          `mapstructure:"allow_credentials"`
	MaxAge           time.Duration `mapstructure:"max_age"`
}

type AuthConfig struct {
	Issuer                string        `mapstructure:"issuer"`
	Audience              string        `mapstructure:"audience"`
	AccessTokenTTL        time.Duration `mapstructure:"access_token_ttl"`
	RefreshTokenTTL       time.Duration `mapstructure:"refresh_token_ttl"`
	LoginSessionTTL       time.Duration `mapstructure:"login_session_ttl"`
	SigningKeyRotation    time.Duration `mapstructure:"signing_key_rotation"`
	SigningKeyRetention   time.Duration `mapstructure:"signing_key_retention"`
	SessionCookieName     string        `mapstructure:"session_cookie_name"`
	SessionCookieSecure   bool          `mapstructure:"session_cookie_secure"`
	SessionCookieSameSite string        `mapstructure:"session_cookie_same_site"`
	SessionCookieMaxAge   time.Duration `mapstructure:"session_cookie_max_age"`
}

func Load() (*Config, error) {
	var cfg Config

	godotenv.Load()

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")

	viper.SetDefault("app.debug", false)
	viper.SetDefault("app.port", 3000)
	viper.SetDefault("app.trusted_proxies", []string{})
	viper.SetDefault("app.max_request_body_bytes", int64(1<<20))
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.sslmode", "require")
	viper.SetDefault("database.timezone", "UTC")
	viper.SetDefault("database.connect_timeout", 10)
	viper.SetDefault("database.max_open_conns", 25)
	viper.SetDefault("database.max_idle_conns", 5)
	viper.SetDefault("database.conn_max_lifetime", "30m")
	viper.SetDefault("database.conn_max_idle_time", "15m")
	viper.SetDefault("database.log_sql", false)
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("redis.dial_timeout", "5s")
	viper.SetDefault("redis.read_timeout", "3s")
	viper.SetDefault("redis.write_timeout", "3s")
	viper.SetDefault("redis.pool_size", 10)
	viper.SetDefault("redis.min_idle_conns", 2)
	viper.SetDefault("cache.user_ttl", "5m")
	viper.SetDefault("cache.user_session_list_ttl", "1m")
	viper.SetDefault("cache.signing_keys_ttl", "1m")
	viper.SetDefault("dexbotkiller.enabled", false)
	viper.SetDefault("dexbotkiller.mode", "passive")
	viper.SetDefault("dexbotkiller.redis_prefix", "dbk:v1")
	viper.SetDefault("dexbotkiller.counter_window", "1m")
	viper.SetDefault("dexbotkiller.unique_window", "15m")
	viper.SetDefault("dexbotkiller.score_ttl", "24h")
	viper.SetDefault("dexbotkiller.delay", "500ms")
	viper.SetDefault("dexbotkiller.thresholds.delay_score", 3)
	viper.SetDefault("dexbotkiller.thresholds.challenge_score", 6)
	viper.SetDefault("dexbotkiller.thresholds.block_score", 10)
	viper.SetDefault("dexbotkiller.cloudflare_turnstile.verify_url", "https://challenges.cloudflare.com/turnstile/v0/siteverify")
	viper.SetDefault("dexbotkiller.cloudflare_turnstile.timeout", "3s")
	viper.SetDefault("dexbotkiller.device_cookie_name", "ddone_device")
	viper.SetDefault("dexbotkiller.device_cookie_max_age", "720h")
	viper.SetDefault("dexbotkiller.device_cookie_secure", true)
	viper.SetDefault("dexbotkiller.device_cookie_same_site", "lax")
	viper.SetDefault("security.login.failed_attempt_window", "5m")
	viper.SetDefault("security.login.max_attempts", 5)
	viper.SetDefault("security.login.lockout_duration", "15m")
	viper.SetDefault("security.otp.register.ttl", "5m")
	viper.SetDefault("security.otp.register.phone_window", "5m")
	viper.SetDefault("security.otp.register.system_window", "10m")
	viper.SetDefault("security.otp.register.resend_cooldown", "60s")
	viper.SetDefault("security.otp.register.verify_attempt_window", "5m")
	viper.SetDefault("security.otp.register.max_phone_requests", 1)
	viper.SetDefault("security.otp.register.max_system_requests", 30)
	viper.SetDefault("security.otp.register.max_resends", 3)
	viper.SetDefault("security.otp.register.max_verify_attempts", 5)
	viper.SetDefault("security.otp.password_reset.ttl", "5m")
	viper.SetDefault("security.otp.password_reset.phone_window", "5m")
	viper.SetDefault("security.otp.password_reset.resend_cooldown", "60s")
	viper.SetDefault("security.otp.password_reset.verify_attempt_window", "5m")
	viper.SetDefault("security.otp.password_reset.max_phone_requests", 1)
	viper.SetDefault("security.otp.password_reset.max_resends", 3)
	viper.SetDefault("security.otp.password_reset.max_verify_attempts", 5)
	viper.SetDefault("cors.allowed_origins", []string{"*"})
	viper.SetDefault("cors.allowed_methods", []string{"GET", "POST", "OPTIONS"})
	viper.SetDefault("cors.allowed_headers", []string{"Origin", "Content-Type", "Accept", "Authorization"})
	viper.SetDefault("cors.exposed_headers", []string{})
	viper.SetDefault("cors.allow_credentials", false)
	viper.SetDefault("cors.max_age", "12h")
	viper.SetDefault("security.auth.issuer", "ddone-server-auth")
	viper.SetDefault("security.auth.audience", "ddone-clients")
	viper.SetDefault("security.auth.access_token_ttl", "5m")
	viper.SetDefault("security.auth.refresh_token_ttl", "720h")
	viper.SetDefault("security.auth.login_session_ttl", "720h")
	viper.SetDefault("security.auth.signing_key_rotation", "2160h")
	viper.SetDefault("security.auth.signing_key_retention", "4320h")
	viper.SetDefault("security.auth.session_cookie_name", "ddone_session")
	viper.SetDefault("security.auth.session_cookie_secure", true)
	viper.SetDefault("security.auth.session_cookie_same_site", "lax")
	viper.SetDefault("security.auth.session_cookie_max_age", "0s")

	viper.SetEnvPrefix("DDONE")
	viper.SetEnvKeyReplacer(
		strings.NewReplacer(".", "_"),
	)
	viper.AutomaticEnv()

	viper.BindEnv("app.port", "DDONE_APP_PORT")
	viper.BindEnv("app.debug", "DDONE_APP_DEBUG")
	viper.BindEnv("app.trusted_proxies", "DDONE_APP_TRUSTED_PROXIES")
	viper.BindEnv("app.max_request_body_bytes", "DDONE_APP_MAX_REQUEST_BODY_BYTES")
	viper.BindEnv("database.host", "DDONE_DATABASE_HOST")
	viper.BindEnv("database.port", "DDONE_DATABASE_PORT")
	viper.BindEnv("database.name", "DDONE_DATABASE_NAME")
	viper.BindEnv("database.username", "DDONE_DATABASE_USERNAME")
	viper.BindEnv("database.password", "DDONE_DATABASE_PASSWORD")
	viper.BindEnv("database.sslmode", "DDONE_DATABASE_SSLMODE")
	viper.BindEnv("database.timezone", "DDONE_DATABASE_TIMEZONE")
	viper.BindEnv("database.connect_timeout", "DDONE_DATABASE_CONNECT_TIMEOUT")
	viper.BindEnv("database.max_open_conns", "DDONE_DATABASE_MAX_OPEN_CONNS")
	viper.BindEnv("database.max_idle_conns", "DDONE_DATABASE_MAX_IDLE_CONNS")
	viper.BindEnv("database.conn_max_lifetime", "DDONE_DATABASE_CONN_MAX_LIFETIME")
	viper.BindEnv("database.conn_max_idle_time", "DDONE_DATABASE_CONN_MAX_IDLE_TIME")
	viper.BindEnv("database.log_sql", "DDONE_DATABASE_LOG_SQL")
	viper.BindEnv("redis.host", "DDONE_REDIS_HOST")
	viper.BindEnv("redis.port", "DDONE_REDIS_PORT")
	viper.BindEnv("redis.username", "DDONE_REDIS_USERNAME")
	viper.BindEnv("redis.password", "DDONE_REDIS_PASSWORD")
	viper.BindEnv("redis.db", "DDONE_REDIS_DB")
	viper.BindEnv("redis.dial_timeout", "DDONE_REDIS_DIAL_TIMEOUT")
	viper.BindEnv("redis.read_timeout", "DDONE_REDIS_READ_TIMEOUT")
	viper.BindEnv("redis.write_timeout", "DDONE_REDIS_WRITE_TIMEOUT")
	viper.BindEnv("redis.pool_size", "DDONE_REDIS_POOL_SIZE")
	viper.BindEnv("redis.min_idle_conns", "DDONE_REDIS_MIN_IDLE_CONNS")
	viper.BindEnv("cache.user_ttl", "DDONE_CACHE_USER_TTL", "DDONE_CACHE_ACCOUNT_TTL")
	viper.BindEnv(
		"cache.user_session_list_ttl",
		"DDONE_CACHE_USER_SESSION_LIST_TTL",
		"DDONE_CACHE_ACCOUNT_SESSION_LIST_TTL",
	)
	viper.BindEnv("cache.signing_keys_ttl", "DDONE_CACHE_SIGNING_KEYS_TTL")
	viper.BindEnv("dexbotkiller.enabled", "DDONE_DEXBOTKILLER_ENABLED")
	viper.BindEnv("dexbotkiller.mode", "DDONE_DEXBOTKILLER_MODE")
	viper.BindEnv("dexbotkiller.redis_prefix", "DDONE_DEXBOTKILLER_REDIS_PREFIX")
	viper.BindEnv("dexbotkiller.pepper", "DDONE_DEXBOTKILLER_PEPPER")
	viper.BindEnv("dexbotkiller.counter_window", "DDONE_DEXBOTKILLER_COUNTER_WINDOW")
	viper.BindEnv("dexbotkiller.unique_window", "DDONE_DEXBOTKILLER_UNIQUE_WINDOW")
	viper.BindEnv("dexbotkiller.score_ttl", "DDONE_DEXBOTKILLER_SCORE_TTL")
	viper.BindEnv("dexbotkiller.delay", "DDONE_DEXBOTKILLER_DELAY")
	viper.BindEnv("dexbotkiller.thresholds.delay_score", "DDONE_DEXBOTKILLER_THRESHOLDS_DELAY_SCORE")
	viper.BindEnv("dexbotkiller.thresholds.challenge_score", "DDONE_DEXBOTKILLER_THRESHOLDS_CHALLENGE_SCORE")
	viper.BindEnv("dexbotkiller.thresholds.block_score", "DDONE_DEXBOTKILLER_THRESHOLDS_BLOCK_SCORE")
	viper.BindEnv("dexbotkiller.cloudflare_turnstile.site_key", "DDONE_DEXBOTKILLER_CLOUDFLARE_TURNSTILE_SITE_KEY")
	viper.BindEnv("dexbotkiller.cloudflare_turnstile.secret_key", "DDONE_DEXBOTKILLER_CLOUDFLARE_TURNSTILE_SECRET_KEY")
	viper.BindEnv("dexbotkiller.cloudflare_turnstile.verify_url", "DDONE_DEXBOTKILLER_CLOUDFLARE_TURNSTILE_VERIFY_URL")
	viper.BindEnv("dexbotkiller.cloudflare_turnstile.timeout", "DDONE_DEXBOTKILLER_CLOUDFLARE_TURNSTILE_TIMEOUT")
	viper.BindEnv("dexbotkiller.device_cookie_name", "DDONE_DEXBOTKILLER_DEVICE_COOKIE_NAME")
	viper.BindEnv("dexbotkiller.device_cookie_max_age", "DDONE_DEXBOTKILLER_DEVICE_COOKIE_MAX_AGE")
	viper.BindEnv("dexbotkiller.device_cookie_secure", "DDONE_DEXBOTKILLER_DEVICE_COOKIE_SECURE")
	viper.BindEnv("dexbotkiller.device_cookie_same_site", "DDONE_DEXBOTKILLER_DEVICE_COOKIE_SAME_SITE")
	viper.BindEnv("security.login.failed_attempt_window", "DDONE_SECURITY_LOGIN_FAILED_ATTEMPT_WINDOW", "DDONE_LOGIN_FAILED_ATTEMPT_WINDOW", "DDONE_LOGIN_RATE_LIMIT_WINDOW")
	viper.BindEnv("security.login.max_attempts", "DDONE_SECURITY_LOGIN_MAX_ATTEMPTS", "DDONE_LOGIN_MAX_ATTEMPTS")
	viper.BindEnv("security.login.lockout_duration", "DDONE_SECURITY_LOGIN_LOCKOUT_DURATION", "DDONE_LOGIN_LOCKOUT_DURATION")
	viper.BindEnv("security.otp.register.ttl", "DDONE_SECURITY_OTP_REGISTER_TTL", "DDONE_OTP_REGISTER_TTL")
	viper.BindEnv("security.otp.register.phone_window", "DDONE_SECURITY_OTP_REGISTER_PHONE_WINDOW", "DDONE_OTP_REGISTER_PHONE_WINDOW")
	viper.BindEnv("security.otp.register.system_window", "DDONE_SECURITY_OTP_REGISTER_SYSTEM_WINDOW", "DDONE_OTP_REGISTER_SYSTEM_WINDOW")
	viper.BindEnv("security.otp.register.resend_cooldown", "DDONE_SECURITY_OTP_REGISTER_RESEND_COOLDOWN", "DDONE_OTP_REGISTER_RESEND_COOLDOWN")
	viper.BindEnv("security.otp.register.verify_attempt_window", "DDONE_SECURITY_OTP_REGISTER_VERIFY_ATTEMPT_WINDOW", "DDONE_OTP_REGISTER_VERIFY_ATTEMPT_WINDOW")
	viper.BindEnv("security.otp.register.max_phone_requests", "DDONE_SECURITY_OTP_REGISTER_MAX_PHONE_REQUESTS", "DDONE_OTP_REGISTER_MAX_PHONE_REQUESTS")
	viper.BindEnv("security.otp.register.max_system_requests", "DDONE_SECURITY_OTP_REGISTER_MAX_SYSTEM_REQUESTS", "DDONE_OTP_REGISTER_MAX_SYSTEM_REQUESTS")
	viper.BindEnv("security.otp.register.max_resends", "DDONE_SECURITY_OTP_REGISTER_MAX_RESENDS", "DDONE_OTP_REGISTER_MAX_RESENDS")
	viper.BindEnv("security.otp.register.max_verify_attempts", "DDONE_SECURITY_OTP_REGISTER_MAX_VERIFY_ATTEMPTS", "DDONE_OTP_REGISTER_MAX_VERIFY_ATTEMPTS")
	viper.BindEnv("security.otp.password_reset.ttl", "DDONE_SECURITY_OTP_PASSWORD_RESET_TTL", "DDONE_OTP_PASSWORD_RESET_TTL")
	viper.BindEnv("security.otp.password_reset.phone_window", "DDONE_SECURITY_OTP_PASSWORD_RESET_PHONE_WINDOW", "DDONE_OTP_PASSWORD_RESET_PHONE_WINDOW")
	viper.BindEnv("security.otp.password_reset.resend_cooldown", "DDONE_SECURITY_OTP_PASSWORD_RESET_RESEND_COOLDOWN", "DDONE_OTP_PASSWORD_RESET_RESEND_COOLDOWN")
	viper.BindEnv("security.otp.password_reset.verify_attempt_window", "DDONE_SECURITY_OTP_PASSWORD_RESET_VERIFY_ATTEMPT_WINDOW", "DDONE_OTP_PASSWORD_RESET_VERIFY_ATTEMPT_WINDOW")
	viper.BindEnv("security.otp.password_reset.max_phone_requests", "DDONE_SECURITY_OTP_PASSWORD_RESET_MAX_PHONE_REQUESTS", "DDONE_OTP_PASSWORD_RESET_MAX_PHONE_REQUESTS")
	viper.BindEnv("security.otp.password_reset.max_resends", "DDONE_SECURITY_OTP_PASSWORD_RESET_MAX_RESENDS", "DDONE_OTP_PASSWORD_RESET_MAX_RESENDS")
	viper.BindEnv("security.otp.password_reset.max_verify_attempts", "DDONE_SECURITY_OTP_PASSWORD_RESET_MAX_VERIFY_ATTEMPTS", "DDONE_OTP_PASSWORD_RESET_MAX_VERIFY_ATTEMPTS")
	viper.BindEnv("cors.allowed_origins", "DDONE_CORS_ALLOWED_ORIGINS")
	viper.BindEnv("cors.allowed_methods", "DDONE_CORS_ALLOWED_METHODS")
	viper.BindEnv("cors.allowed_headers", "DDONE_CORS_ALLOWED_HEADERS")
	viper.BindEnv("cors.exposed_headers", "DDONE_CORS_EXPOSED_HEADERS")
	viper.BindEnv("cors.allow_credentials", "DDONE_CORS_ALLOW_CREDENTIALS")
	viper.BindEnv("cors.max_age", "DDONE_CORS_MAX_AGE")
	viper.BindEnv("security.auth.issuer", "DDONE_SECURITY_AUTH_ISSUER", "DDONE_AUTH_ISSUER")
	viper.BindEnv("security.auth.audience", "DDONE_SECURITY_AUTH_AUDIENCE", "DDONE_AUTH_AUDIENCE")
	viper.BindEnv("security.auth.access_token_ttl", "DDONE_SECURITY_AUTH_ACCESS_TOKEN_TTL", "DDONE_AUTH_ACCESS_TOKEN_TTL")
	viper.BindEnv("security.auth.refresh_token_ttl", "DDONE_SECURITY_AUTH_REFRESH_TOKEN_TTL", "DDONE_AUTH_REFRESH_TOKEN_TTL")
	viper.BindEnv("security.auth.login_session_ttl", "DDONE_SECURITY_AUTH_LOGIN_SESSION_TTL", "DDONE_AUTH_LOGIN_SESSION_TTL")
	viper.BindEnv("security.auth.signing_key_rotation", "DDONE_SECURITY_AUTH_SIGNING_KEY_ROTATION", "DDONE_AUTH_SIGNING_KEY_ROTATION")
	viper.BindEnv("security.auth.signing_key_retention", "DDONE_SECURITY_AUTH_SIGNING_KEY_RETENTION", "DDONE_AUTH_SIGNING_KEY_RETENTION")
	viper.BindEnv("security.auth.session_cookie_name", "DDONE_SECURITY_AUTH_SESSION_COOKIE_NAME", "DDONE_AUTH_SESSION_COOKIE_NAME")
	viper.BindEnv("security.auth.session_cookie_secure", "DDONE_SECURITY_AUTH_SESSION_COOKIE_SECURE", "DDONE_AUTH_SESSION_COOKIE_SECURE")
	viper.BindEnv("security.auth.session_cookie_same_site", "DDONE_SECURITY_AUTH_SESSION_COOKIE_SAME_SITE", "DDONE_AUTH_SESSION_COOKIE_SAME_SITE")
	viper.BindEnv("security.auth.session_cookie_max_age", "DDONE_SECURITY_AUTH_SESSION_COOKIE_MAX_AGE", "DDONE_AUTH_SESSION_COOKIE_MAX_AGE")
	viper.BindEnv("wenovaapi.token", "DDONE_WENOVAAPI_TOKEN", "DDONE_WENOVA_TOKEN")

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	err := viper.Unmarshal(&cfg)
	if err != nil {
		return nil, err
	}

	cfg.App.TrustedProxies = viper.GetStringSlice("app.trusted_proxies")
	cfg.App.MaxRequestBodyBytes = viper.GetInt64("app.max_request_body_bytes")
	cfg.CORS.AllowedOrigins = viper.GetStringSlice("cors.allowed_origins")
	cfg.CORS.AllowedMethods = viper.GetStringSlice("cors.allowed_methods")
	cfg.CORS.AllowedHeaders = viper.GetStringSlice("cors.allowed_headers")
	cfg.CORS.ExposedHeaders = viper.GetStringSlice("cors.exposed_headers")
	cfg.CORS.AllowCredentials = viper.GetBool("cors.allow_credentials")
	cfg.CORS.MaxAge = viper.GetDuration("cors.max_age")

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	if c.App.Port <= 0 {
		return fmt.Errorf("app.port must be greater than 0")
	}
	c.App.TrustedProxies = cleanStringSlice(c.App.TrustedProxies)
	for _, proxy := range c.App.TrustedProxies {
		if proxy == "0.0.0.0/0" || proxy == "::/0" {
			return fmt.Errorf("app.trusted_proxies must not trust all network origins")
		}
	}
	if c.App.MaxRequestBodyBytes < 0 {
		return fmt.Errorf("app.max_request_body_bytes must be greater than or equal to 0")
	}

	if c.Database.Host == "" {
		return fmt.Errorf("database.host is required")
	}
	if c.Database.Port <= 0 {
		return fmt.Errorf("database.port must be greater than 0")
	}
	if c.Database.Name == "" {
		return fmt.Errorf("database.name is required")
	}
	if c.Database.Username == "" {
		return fmt.Errorf("database.username is required")
	}
	if c.Database.SSLMode == "" {
		return fmt.Errorf("database.sslmode is required")
	}

	if c.Redis.Host == "" {
		return fmt.Errorf("redis.host is required")
	}
	if c.Redis.Port <= 0 {
		return fmt.Errorf("redis.port must be greater than 0")
	}
	if c.Redis.DB < 0 {
		return fmt.Errorf("redis.db must be greater than or equal to 0")
	}

	if c.Cache.UserTTL < 0 {
		return fmt.Errorf("cache.user_ttl must be greater than or equal to 0")
	}
	if c.Cache.UserSessionListTTL < 0 {
		return fmt.Errorf("cache.user_session_list_ttl must be greater than or equal to 0")
	}
	if c.Cache.SigningKeysTTL < 0 {
		return fmt.Errorf("cache.signing_keys_ttl must be greater than or equal to 0")
	}
	if err := validateDexBotKiller(c.DexBotKiller); err != nil {
		return err
	}
	if c.Security.Login.FailedAttemptWindow <= 0 {
		return fmt.Errorf("security.login.failed_attempt_window must be greater than 0")
	}
	if c.Security.Login.MaxAttempts <= 0 {
		return fmt.Errorf("security.login.max_attempts must be greater than 0")
	}
	if c.Security.Login.LockoutDuration <= 0 {
		return fmt.Errorf("security.login.lockout_duration must be greater than 0")
	}
	if err := validateOTPPolicy("security.otp.register", c.Security.OTP.Register.OTPPolicyConfig); err != nil {
		return err
	}
	if err := validateRegisterSystemRateLimitPolicy("security.otp.register", c.Security.OTP.Register); err != nil {
		return err
	}
	if err := validateOTPPolicy("security.otp.password_reset", c.Security.OTP.PasswordReset); err != nil {
		return err
	}

	c.CORS.AllowedOrigins = cleanStringSlice(c.CORS.AllowedOrigins)
	c.CORS.AllowedMethods = cleanStringSlice(c.CORS.AllowedMethods)
	c.CORS.AllowedHeaders = cleanStringSlice(c.CORS.AllowedHeaders)
	c.CORS.ExposedHeaders = cleanStringSlice(c.CORS.ExposedHeaders)

	if len(c.CORS.AllowedOrigins) == 0 {
		return fmt.Errorf("cors.allowed_origins must contain at least one origin")
	}
	if len(c.CORS.AllowedMethods) == 0 {
		return fmt.Errorf("cors.allowed_methods must contain at least one method")
	}
	if len(c.CORS.AllowedHeaders) == 0 {
		return fmt.Errorf("cors.allowed_headers must contain at least one header")
	}
	if c.CORS.MaxAge < 0 {
		return fmt.Errorf("cors.max_age must be greater than or equal to 0")
	}
	if c.CORS.AllowCredentials {
		for _, origin := range c.CORS.AllowedOrigins {
			if origin == "*" {
				return fmt.Errorf("cors.allowed_origins cannot contain * when cors.allow_credentials is true")
			}
		}
	}

	if c.Security.Auth.Issuer == "" {
		return fmt.Errorf("security.auth.issuer is required")
	}
	if c.Security.Auth.Audience == "" {
		return fmt.Errorf("security.auth.audience is required")
	}
	if c.Security.Auth.AccessTokenTTL <= 0 {
		return fmt.Errorf("security.auth.access_token_ttl must be greater than 0")
	}
	if c.Security.Auth.RefreshTokenTTL <= 0 {
		return fmt.Errorf("security.auth.refresh_token_ttl must be greater than 0")
	}
	if c.Security.Auth.LoginSessionTTL <= 0 {
		return fmt.Errorf("security.auth.login_session_ttl must be greater than 0")
	}
	if c.Security.Auth.SigningKeyRotation <= 0 {
		return fmt.Errorf("security.auth.signing_key_rotation must be greater than 0")
	}
	if c.Security.Auth.SigningKeyRetention <= 0 {
		return fmt.Errorf("security.auth.signing_key_retention must be greater than 0")
	}
	if c.Security.Auth.SigningKeyRetention < c.Security.Auth.SigningKeyRotation {
		return fmt.Errorf("security.auth.signing_key_retention must be greater than or equal to security.auth.signing_key_rotation")
	}
	if c.Security.Auth.SessionCookieName == "" {
		return fmt.Errorf("security.auth.session_cookie_name is required")
	}
	if c.Security.Auth.SessionCookieMaxAge < 0 {
		return fmt.Errorf("security.auth.session_cookie_max_age must be greater than or equal to 0")
	}
	if c.Security.Auth.SessionCookieMaxAge > 0 && c.Security.Auth.SessionCookieMaxAge > c.Security.Auth.LoginSessionTTL {
		return fmt.Errorf("security.auth.session_cookie_max_age must be less than or equal to security.auth.login_session_ttl")
	}
	switch strings.ToLower(c.Security.Auth.SessionCookieSameSite) {
	case "lax", "strict", "none":
	default:
		return fmt.Errorf("security.auth.session_cookie_same_site must be one of lax, strict, none")
	}
	if strings.EqualFold(c.Security.Auth.SessionCookieSameSite, "none") && !c.Security.Auth.SessionCookieSecure {
		return fmt.Errorf("security.auth.session_cookie_secure must be true when security.auth.session_cookie_same_site is none")
	}

	return nil
}

func validateDexBotKiller(cfg DexBotKillerConfig) error {
	switch strings.ToLower(strings.TrimSpace(cfg.Mode)) {
	case "passive", "delay", "challenge", "enforce":
	default:
		return fmt.Errorf("dexbotkiller.mode must be one of passive, delay, challenge, enforce")
	}
	if cfg.Enabled && strings.TrimSpace(cfg.Pepper) == "" {
		return fmt.Errorf("dexbotkiller.pepper is required when dexbotkiller.enabled is true")
	}
	if strings.TrimSpace(cfg.RedisPrefix) == "" {
		return fmt.Errorf("dexbotkiller.redis_prefix is required")
	}
	if cfg.CounterWindow <= 0 {
		return fmt.Errorf("dexbotkiller.counter_window must be greater than 0")
	}
	if cfg.UniqueWindow <= 0 {
		return fmt.Errorf("dexbotkiller.unique_window must be greater than 0")
	}
	if cfg.ScoreTTL <= 0 {
		return fmt.Errorf("dexbotkiller.score_ttl must be greater than 0")
	}
	if cfg.Delay < 0 {
		return fmt.Errorf("dexbotkiller.delay must be greater than or equal to 0")
	}
	if cfg.Thresholds.DelayScore <= 0 {
		return fmt.Errorf("dexbotkiller.thresholds.delay_score must be greater than 0")
	}
	if cfg.Thresholds.ChallengeScore < cfg.Thresholds.DelayScore {
		return fmt.Errorf("dexbotkiller.thresholds.challenge_score must be greater than or equal to dexbotkiller.thresholds.delay_score")
	}
	if cfg.Thresholds.BlockScore < cfg.Thresholds.ChallengeScore {
		return fmt.Errorf("dexbotkiller.thresholds.block_score must be greater than or equal to dexbotkiller.thresholds.challenge_score")
	}
	if err := validateCloudflareTurnstile(cfg); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.DeviceCookieName) == "" {
		return fmt.Errorf("dexbotkiller.device_cookie_name is required")
	}
	if cfg.DeviceCookieMaxAge <= 0 {
		return fmt.Errorf("dexbotkiller.device_cookie_max_age must be greater than 0")
	}
	switch strings.ToLower(strings.TrimSpace(cfg.DeviceCookieSameSite)) {
	case "lax", "strict", "none":
	default:
		return fmt.Errorf("dexbotkiller.device_cookie_same_site must be one of lax, strict, none")
	}
	if strings.EqualFold(cfg.DeviceCookieSameSite, "none") && !cfg.DeviceCookieSecure {
		return fmt.Errorf("dexbotkiller.device_cookie_secure must be true when dexbotkiller.device_cookie_same_site is none")
	}

	return nil
}

func validateCloudflareTurnstile(cfg DexBotKillerConfig) error {
	if cfg.CloudflareTurnstile.Timeout <= 0 {
		return fmt.Errorf("dexbotkiller.cloudflare_turnstile.timeout must be greater than 0")
	}
	if strings.TrimSpace(cfg.CloudflareTurnstile.VerifyURL) == "" {
		return fmt.Errorf("dexbotkiller.cloudflare_turnstile.verify_url is required")
	}
	if !cfg.Enabled {
		return nil
	}

	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode != "challenge" && mode != "enforce" {
		return nil
	}
	if strings.TrimSpace(cfg.CloudflareTurnstile.SiteKey) == "" {
		return fmt.Errorf("dexbotkiller.cloudflare_turnstile.site_key is required when challenge mode is enabled")
	}
	if strings.TrimSpace(cfg.CloudflareTurnstile.SecretKey) == "" {
		return fmt.Errorf("dexbotkiller.cloudflare_turnstile.secret_key is required when challenge mode is enabled")
	}

	return nil
}

func validateOTPPolicy(path string, cfg OTPPolicyConfig) error {
	if cfg.TTL <= 0 {
		return fmt.Errorf("%s.ttl must be greater than 0", path)
	}
	if cfg.PhoneWindow <= 0 {
		return fmt.Errorf("%s.phone_window must be greater than 0", path)
	}
	if cfg.ResendCooldown <= 0 {
		return fmt.Errorf("%s.resend_cooldown must be greater than 0", path)
	}
	if cfg.VerifyAttemptWindow <= 0 {
		return fmt.Errorf("%s.verify_attempt_window must be greater than 0", path)
	}
	if cfg.MaxPhoneRequests <= 0 {
		return fmt.Errorf("%s.max_phone_requests must be greater than 0", path)
	}
	if cfg.MaxResends <= 0 {
		return fmt.Errorf("%s.max_resends must be greater than 0", path)
	}
	if cfg.MaxVerifyAttempts <= 0 {
		return fmt.Errorf("%s.max_verify_attempts must be greater than 0", path)
	}

	return nil
}

func validateRegisterSystemRateLimitPolicy(path string, cfg RegisterOTPPolicyConfig) error {
	if cfg.SystemWindow <= 0 {
		return fmt.Errorf("%s.system_window must be greater than 0", path)
	}
	if cfg.MaxSystemRequests <= 0 {
		return fmt.Errorf("%s.max_system_requests must be greater than 0", path)
	}

	return nil
}

func (c Config) DatabaseDSN() string {
	return c.Database.DSN()
}

func (c DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s&timezone=%s&connect_timeout=%d",
		url.QueryEscape(c.Username),
		url.QueryEscape(c.Password),
		c.Host,
		c.Port,
		c.Name,
		url.QueryEscape(c.SSLMode),
		url.QueryEscape(c.TimeZone),
		c.ConnectTimeout,
	)
}

func (c Config) RedisAddr() string {
	return c.Redis.Addr()
}

func (c AuthConfig) EffectiveSessionCookieMaxAge() time.Duration {
	if c.SessionCookieMaxAge > 0 {
		return c.SessionCookieMaxAge
	}

	return c.LoginSessionTTL
}

func cleanStringSlice(values []string) []string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		cleaned = append(cleaned, trimmed)
	}

	return cleaned
}

func (c RedisConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}
