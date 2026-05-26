package cache

import (
	"context"
	appdexbotkiller "ddone-server-auth/internal/application/dexbotkiller"
	"errors"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

type DexBotKillerStore struct {
	client *redis.Client
}

var _ appdexbotkiller.Store = (*DexBotKillerStore)(nil)

func NewDexBotKillerStore(client *redis.Client) *DexBotKillerStore {
	return &DexBotKillerStore{client: client}
}

func (s *DexBotKillerStore) IncrementCounter(ctx context.Context, key string, ttl time.Duration) (int64, error) {
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

func (s *DexBotKillerStore) GetCounter(ctx context.Context, key string) (int64, error) {
	count, err := s.client.Get(ctx, key).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}

		return 0, err
	}

	return count, nil
}

func (s *DexBotKillerStore) AddUnique(ctx context.Context, key string, member string, ttl time.Duration) error {
	added, err := s.client.SAdd(ctx, key, member).Result()
	if err != nil {
		return err
	}
	if added > 0 {
		return s.client.Expire(ctx, key, ttl).Err()
	}

	return nil
}

func (s *DexBotKillerStore) UniqueCount(ctx context.Context, key string) (int64, error) {
	return s.client.SCard(ctx, key).Result()
}

func (s *DexBotKillerStore) IncrementScore(ctx context.Context, key string, delta float64, ttl time.Duration) (float64, error) {
	score, err := s.client.IncrByFloat(ctx, key, delta).Result()
	if err != nil {
		return 0, err
	}
	if ttl > 0 {
		if err := s.client.Expire(ctx, key, ttl).Err(); err != nil {
			return 0, err
		}
	}

	return score, nil
}

func (s *DexBotKillerStore) GetScore(ctx context.Context, key string) (float64, error) {
	raw, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}

		return 0, err
	}

	score, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, err
	}

	return score, nil
}
