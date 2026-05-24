package cache

import (
	"context"
	apppassword "ddone-server-auth/internal/application/password"
	"errors"
	"fmt"
	"time"

	json "github.com/bytedance/sonic"
	"github.com/redis/go-redis/v9"
)

type PasswordResetStore struct {
	client *redis.Client
}

var _ apppassword.ResetStore = (*PasswordResetStore)(nil)

func NewPasswordResetStore(client *redis.Client) *PasswordResetStore {
	return &PasswordResetStore{client: client}
}

func (s *PasswordResetStore) Save(
	ctx context.Context,
	state *apppassword.ResetTicketState,
	ttl time.Duration,
) error {
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}

	return s.client.Set(ctx, passwordResetKey(state.TicketID), payload, ttl).Err()
}

func (s *PasswordResetStore) Get(ctx context.Context, ticketID string) (*apppassword.ResetTicketState, error) {
	payload, err := s.client.Get(ctx, passwordResetKey(ticketID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, apppassword.ErrPasswordResetTicketNotFound
		}

		return nil, err
	}

	var state apppassword.ResetTicketState
	if err := json.Unmarshal([]byte(payload), &state); err != nil {
		return nil, err
	}

	return &state, nil
}

func (s *PasswordResetStore) Delete(ctx context.Context, ticketID string) error {
	return s.client.Del(ctx, passwordResetKey(ticketID)).Err()
}

func (s *PasswordResetStore) IncrementCounter(ctx context.Context, key string, ttl time.Duration) (int64, error) {
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

func (s *PasswordResetStore) DeleteCounter(ctx context.Context, key string) error {
	return s.client.Del(ctx, key).Err()
}

func passwordResetKey(ticketID string) string {
	return fmt.Sprintf("password_reset:ticket:%s", ticketID)
}
