package cache

import (
	"context"
	applogin "ddone-server-auth/internal/application/login"
	"errors"
	"github.com/redis/go-redis/v9"
	"time"
)

type LoginRateLimiter struct {
	client *redis.Client
}

var _ applogin.LoginRateLimiter = (*LoginRateLimiter)(nil)

func NewLoginRateLimiter(client *redis.Client) *LoginRateLimiter {
	return &LoginRateLimiter{client: client}
}

func (s *LoginRateLimiter) GetCounter(ctx context.Context, key string) (int64, error) {
	value, err := s.client.Get(ctx, key).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, err
	}

	return value, nil
}

func (s *LoginRateLimiter) IncrementCounter(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	count, err := s.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}

	if count == 1 {
		if err := s.client.Expire(ctx, key, ttl).Err(); err != nil {
			return 0, err
		}
	}

	return count, nil
}

func (s *LoginRateLimiter) DeleteCounter(ctx context.Context, key string) error {
	return s.client.Del(ctx, key).Err()
}

func (s *LoginRateLimiter) IsLocked(ctx context.Context, key string) (bool, error) {
	locked, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}

	return locked > 0, nil
}

func (s *LoginRateLimiter) Lock(ctx context.Context, key string, ttl time.Duration) error {
	return s.client.Set(ctx, key, "1", ttl).Err()
}
