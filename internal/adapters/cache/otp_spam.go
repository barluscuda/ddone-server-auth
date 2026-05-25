package cache

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type OTPSpamStore struct {
	client *redis.Client
}

func NewOTPSpamStore(client *redis.Client) *OTPSpamStore {
	return &OTPSpamStore{client: client}
}

func (s *OTPSpamStore) IncrementCounter(ctx context.Context, key string, ttl time.Duration) (int64, error) {
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

func (s *OTPSpamStore) AdjustScore(ctx context.Context, key string, delta float64, ttl time.Duration) (float64, error) {
	return adjustScore(ctx, s.client, key, delta, ttl)
}
