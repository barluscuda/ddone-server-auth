package cache

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

var adjustScoreScript = redis.NewScript(`
local key = KEYS[1]
local delta = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
if not delta then
	return redis.error_reply("invalid score delta")
end
if not ttl or ttl <= 0 then
	return redis.error_reply("invalid score ttl")
end

local current = tonumber(redis.call("GET", key) or "0")
local currentTTL = redis.call("PTTL", key)
local nextScore = current + delta
if nextScore <= 0 then
	redis.call("DEL", key)
	return "0"
end

if currentTTL > 0 then
	redis.call("SET", key, tostring(nextScore), "PX", currentTTL)
else
	redis.call("SET", key, tostring(nextScore), "PX", ttl)
end

return tostring(nextScore)
`)

func adjustScore(ctx context.Context, client *redis.Client, key string, delta float64, ttl time.Duration) (float64, error) {
	result, err := adjustScoreScript.Run(
		ctx,
		client,
		[]string{key},
		strconv.FormatFloat(delta, 'f', -1, 64),
		strconv.FormatInt(ttl.Milliseconds(), 10),
	).Result()
	if err != nil {
		return 0, err
	}

	switch value := result.(type) {
	case string:
		return strconv.ParseFloat(value, 64)
	case []byte:
		return strconv.ParseFloat(string(value), 64)
	case int64:
		return float64(value), nil
	case float64:
		return value, nil
	default:
		return 0, fmt.Errorf("unexpected redis score result %T", result)
	}
}
