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
		Debug bool
		Port  int
	}
	Database  DatabaseConfig
	Redis     RedisConfig
	CORS      CORSConfig
	Auth      AuthConfig
	WenovaAPI WenovaAPIConfig
}

type DatabaseConfig struct {
	URL             string
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
}

type RedisConfig struct {
	URL          string
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

type WenovaAPIConfig struct {
	Token string
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
	SigningKeyRotation    time.Duration `mapstructure:"signing_key_rotation"`
	SigningKeyRetention   time.Duration `mapstructure:"signing_key_retention"`
	RefreshCookieName     string        `mapstructure:"refresh_cookie_name"`
	RefreshCookieSecure   bool          `mapstructure:"refresh_cookie_secure"`
	RefreshCookieSameSite string        `mapstructure:"refresh_cookie_same_site"`
}

func Load() (*Config, error) {
	var cfg Config

	godotenv.Load()

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")

	viper.SetDefault("app.debug", false)
	viper.SetDefault("app.port", 3000)
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.sslmode", "require")
	viper.SetDefault("database.timezone", "UTC")
	viper.SetDefault("database.connect_timeout", 10)
	viper.SetDefault("database.max_open_conns", 25)
	viper.SetDefault("database.max_idle_conns", 5)
	viper.SetDefault("database.conn_max_lifetime", "30m")
	viper.SetDefault("database.conn_max_idle_time", "15m")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("redis.dial_timeout", "5s")
	viper.SetDefault("redis.read_timeout", "3s")
	viper.SetDefault("redis.write_timeout", "3s")
	viper.SetDefault("redis.pool_size", 10)
	viper.SetDefault("redis.min_idle_conns", 2)
	viper.SetDefault("cors.allowed_origins", []string{"*"})
	viper.SetDefault("cors.allowed_methods", []string{"GET", "POST", "OPTIONS"})
	viper.SetDefault("cors.allowed_headers", []string{"Origin", "Content-Type", "Accept", "Authorization"})
	viper.SetDefault("cors.exposed_headers", []string{})
	viper.SetDefault("cors.allow_credentials", false)
	viper.SetDefault("cors.max_age", "12h")
	viper.SetDefault("auth.issuer", "ddone-server-auth")
	viper.SetDefault("auth.audience", "ddone-clients")
	viper.SetDefault("auth.access_token_ttl", "15m")
	viper.SetDefault("auth.refresh_token_ttl", "720h")
	viper.SetDefault("auth.signing_key_rotation", "2160h")
	viper.SetDefault("auth.signing_key_retention", "4320h")
	viper.SetDefault("auth.refresh_cookie_name", "ddone_refresh_token")
	viper.SetDefault("auth.refresh_cookie_secure", false)
	viper.SetDefault("auth.refresh_cookie_same_site", "lax")

	viper.SetEnvPrefix("DDONE")
	viper.SetEnvKeyReplacer(
		strings.NewReplacer(".", "_"),
	)
	viper.AutomaticEnv()

	viper.BindEnv("app.port", "DDONE_APP_PORT")
	viper.BindEnv("app.debug", "DDONE_APP_DEBUG")
	viper.BindEnv("database.url", "DDONE_DATABASE_URL")
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
	viper.BindEnv("redis.url", "DDONE_REDIS_URL")
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
	viper.BindEnv("cors.allowed_origins", "DDONE_CORS_ALLOWED_ORIGINS")
	viper.BindEnv("cors.allowed_methods", "DDONE_CORS_ALLOWED_METHODS")
	viper.BindEnv("cors.allowed_headers", "DDONE_CORS_ALLOWED_HEADERS")
	viper.BindEnv("cors.exposed_headers", "DDONE_CORS_EXPOSED_HEADERS")
	viper.BindEnv("cors.allow_credentials", "DDONE_CORS_ALLOW_CREDENTIALS")
	viper.BindEnv("cors.max_age", "DDONE_CORS_MAX_AGE")
	viper.BindEnv("auth.issuer", "DDONE_AUTH_ISSUER")
	viper.BindEnv("auth.audience", "DDONE_AUTH_AUDIENCE")
	viper.BindEnv("auth.access_token_ttl", "DDONE_AUTH_ACCESS_TOKEN_TTL")
	viper.BindEnv("auth.refresh_token_ttl", "DDONE_AUTH_REFRESH_TOKEN_TTL")
	viper.BindEnv("auth.signing_key_rotation", "DDONE_AUTH_SIGNING_KEY_ROTATION")
	viper.BindEnv("auth.signing_key_retention", "DDONE_AUTH_SIGNING_KEY_RETENTION")
	viper.BindEnv("auth.refresh_cookie_name", "DDONE_AUTH_REFRESH_COOKIE_NAME")
	viper.BindEnv("auth.refresh_cookie_secure", "DDONE_AUTH_REFRESH_COOKIE_SECURE")
	viper.BindEnv("auth.refresh_cookie_same_site", "DDONE_AUTH_REFRESH_COOKIE_SAME_SITE")
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

	if c.Database.URL == "" {
		if c.Database.Host == "" {
			return fmt.Errorf("database.host is required when database.url is empty")
		}
		if c.Database.Port <= 0 {
			return fmt.Errorf("database.port must be greater than 0")
		}
		if c.Database.Name == "" {
			return fmt.Errorf("database.name is required when database.url is empty")
		}
		if c.Database.Username == "" {
			return fmt.Errorf("database.username is required when database.url is empty")
		}
		if c.Database.SSLMode == "" {
			return fmt.Errorf("database.sslmode is required")
		}
	}

	if c.Redis.URL == "" {
		if c.Redis.Host == "" {
			return fmt.Errorf("redis.host is required when redis.url is empty")
		}
		if c.Redis.Port <= 0 {
			return fmt.Errorf("redis.port must be greater than 0")
		}
		if c.Redis.DB < 0 {
			return fmt.Errorf("redis.db must be greater than or equal to 0")
		}
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

	if c.Auth.Issuer == "" {
		return fmt.Errorf("auth.issuer is required")
	}
	if c.Auth.Audience == "" {
		return fmt.Errorf("auth.audience is required")
	}
	if c.Auth.AccessTokenTTL <= 0 {
		return fmt.Errorf("auth.access_token_ttl must be greater than 0")
	}
	if c.Auth.RefreshTokenTTL <= 0 {
		return fmt.Errorf("auth.refresh_token_ttl must be greater than 0")
	}
	if c.Auth.SigningKeyRotation <= 0 {
		return fmt.Errorf("auth.signing_key_rotation must be greater than 0")
	}
	if c.Auth.SigningKeyRetention <= 0 {
		return fmt.Errorf("auth.signing_key_retention must be greater than 0")
	}
	if c.Auth.SigningKeyRetention < c.Auth.SigningKeyRotation {
		return fmt.Errorf("auth.signing_key_retention must be greater than or equal to auth.signing_key_rotation")
	}
	if c.Auth.RefreshCookieName == "" {
		return fmt.Errorf("auth.refresh_cookie_name is required")
	}
	switch strings.ToLower(c.Auth.RefreshCookieSameSite) {
	case "lax", "strict", "none":
	default:
		return fmt.Errorf("auth.refresh_cookie_same_site must be one of lax, strict, none")
	}

	return nil
}

func (c Config) DatabaseDSN() string {
	return c.Database.DSN()
}

func (c DatabaseConfig) DSN() string {
	if c.URL != "" {
		return c.URL
	}

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
