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

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c Config) validate() error {
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

func (c RedisConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}
