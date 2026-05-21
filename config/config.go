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
	Database DatabaseConfig
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

	if c.Database.URL != "" {
		return nil
	}

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
