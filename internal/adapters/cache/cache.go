package cache

import (
	"context"
	"ddone-server-auth/config"
	"time"

	"github.com/redis/go-redis/v9"
)

func New(cfg config.RedisConfig, _ bool) (*redis.Client, error) {
	opts, err := optionsFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	client := redis.NewClient(opts)

	pingTimeout := cfg.DialTimeout
	if pingTimeout <= 0 {
		pingTimeout = 5 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}

	return client, nil
}

func optionsFromConfig(cfg config.RedisConfig) (*redis.Options, error) {
	if cfg.URL != "" {
		opts, err := redis.ParseURL(cfg.URL)
		if err != nil {
			return nil, err
		}

		applyConfig(opts, cfg)
		return opts, nil
	}

	opts := &redis.Options{
		Addr:     cfg.Addr(),
		Username: cfg.Username,
		Password: cfg.Password,
		DB:       cfg.DB,
	}
	applyConfig(opts, cfg)

	return opts, nil
}

func applyConfig(opts *redis.Options, cfg config.RedisConfig) {
	if cfg.DialTimeout > 0 {
		opts.DialTimeout = cfg.DialTimeout
	}
	if cfg.ReadTimeout > 0 {
		opts.ReadTimeout = cfg.ReadTimeout
	}
	if cfg.WriteTimeout > 0 {
		opts.WriteTimeout = cfg.WriteTimeout
	}
	if cfg.PoolSize > 0 {
		opts.PoolSize = cfg.PoolSize
	}
	if cfg.MinIdleConns > 0 {
		opts.MinIdleConns = cfg.MinIdleConns
	}
}
