package middleware

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"ddone-server-auth/internal/adapters/dto"

	"github.com/gin-gonic/gin"
)

type BotProtectionConfig struct {
	Enabled       bool
	Window        time.Duration
	MaxRequests   int
	BlockDuration time.Duration
	Now           func() time.Time
}

type botProtectionState struct {
	windowStart  time.Time
	requestCount int
	blockedUntil time.Time
}

func BotProtection(cfg BotProtectionConfig) gin.HandlerFunc {
	nowFunc := cfg.Now
	if nowFunc == nil {
		nowFunc = func() time.Time { return time.Now().UTC() }
	}

	states := map[string]botProtectionState{}
	var mu sync.Mutex
	var lastCleanup time.Time

	return func(c *gin.Context) {
		if !cfg.Enabled || cfg.Window <= 0 || cfg.MaxRequests <= 0 || cfg.BlockDuration <= 0 {
			c.Next()
			return
		}

		now := nowFunc().UTC()
		key := c.ClientIP()
		if key == "" {
			key = "unknown"
		}

		mu.Lock()
		state := states[key]
		if now.Sub(lastCleanup) >= cfg.Window {
			cleanupBotProtectionStates(states, now)
			lastCleanup = now
		}
		if now.Before(state.blockedUntil) {
			retryAfter := retryAfterSeconds(now, state.blockedUntil)
			mu.Unlock()
			c.Header("Retry-After", strconv.FormatInt(retryAfter, 10))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, dto.ResMessage{
				Success: false,
				Code:    "bot_protection_rate_limited",
				Message: "too many requests, please try again later",
			})
			return
		}

		if state.windowStart.IsZero() || now.Sub(state.windowStart) >= cfg.Window {
			state.windowStart = now
			state.requestCount = 0
		}
		state.requestCount++
		if state.requestCount > cfg.MaxRequests {
			state.blockedUntil = now.Add(cfg.BlockDuration)
			states[key] = state
			retryAfter := retryAfterSeconds(now, state.blockedUntil)
			mu.Unlock()
			c.Header("Retry-After", strconv.FormatInt(retryAfter, 10))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, dto.ResMessage{
				Success: false,
				Code:    "bot_protection_rate_limited",
				Message: "too many requests, please try again later",
			})
			return
		}

		states[key] = state
		mu.Unlock()
		c.Next()
	}
}

func cleanupBotProtectionStates(states map[string]botProtectionState, now time.Time) {
	for key, state := range states {
		if now.After(state.blockedUntil) && now.Sub(state.windowStart) > 2*time.Hour {
			delete(states, key)
		}
	}
}

func retryAfterSeconds(now time.Time, blockedUntil time.Time) int64 {
	remaining := blockedUntil.Sub(now)
	if remaining <= 0 {
		return 0
	}

	seconds := int64(remaining / time.Second)
	if remaining%time.Second != 0 {
		seconds++
	}
	return seconds
}
