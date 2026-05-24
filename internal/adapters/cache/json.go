package cache

import (
	"context"
	"time"

	json "github.com/bytedance/sonic"
	"github.com/redis/go-redis/v9"
)

type jsonCache struct {
	client *redis.Client
}

func newJSONCache(client *redis.Client) jsonCache {
	return jsonCache{client: client}
}

func (c jsonCache) get(ctx context.Context, key string, dst any) bool {
	if c.client == nil || key == "" {
		return false
	}

	payload, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		return false
	}

	if err := json.Unmarshal(payload, dst); err != nil {
		return false
	}

	return true
}

func (c jsonCache) set(ctx context.Context, key string, value any, ttl time.Duration) {
	if c.client == nil || key == "" || ttl <= 0 {
		return
	}

	payload, err := json.Marshal(value)
	if err != nil {
		return
	}

	_ = c.client.Set(ctx, key, payload, ttl).Err()
}

func (c jsonCache) delete(ctx context.Context, keys ...string) {
	if c.client == nil {
		return
	}

	filtered := make([]string, 0, len(keys))
	for _, key := range keys {
		if key != "" {
			filtered = append(filtered, key)
		}
	}
	if len(filtered) == 0 {
		return
	}

	_ = c.client.Del(ctx, filtered...).Err()
}
