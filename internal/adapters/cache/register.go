package cache

import (
	"context"
	appregister "ddone-server-auth/internal/application/register"
	"ddone-server-auth/internal/domain/user"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RegisterStore struct {
	client *redis.Client
}

var _ appregister.RegistrationStore = (*RegisterStore)(nil)

func NewRegisterStore(client *redis.Client) *RegisterStore {
	return &RegisterStore{client: client}
}

func (s *RegisterStore) Save(ctx context.Context, registration *user.RegisterModel, ttl time.Duration) error {
	payload, err := json.Marshal(registration)
	if err != nil {
		return err
	}

	return s.client.Set(ctx, registerKey(registration.TicketID), payload, ttl).Err()
}

func (s *RegisterStore) Get(ctx context.Context, ticketID string) (*user.RegisterModel, error) {
	payload, err := s.client.Get(ctx, registerKey(ticketID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, user.ErrPendingRegistrationNotFound
		}

		return nil, err
	}

	var registration user.RegisterModel
	if err := json.Unmarshal([]byte(payload), &registration); err != nil {
		return nil, err
	}

	return &registration, nil
}

func (s *RegisterStore) Delete(ctx context.Context, ticketID string) error {
	return s.client.Del(ctx, registerKey(ticketID)).Err()
}

func (s *RegisterStore) IncrementCounter(ctx context.Context, key string, ttl time.Duration) (int64, error) {
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

func (s *RegisterStore) DeleteCounter(ctx context.Context, key string) error {
	return s.client.Del(ctx, key).Err()
}

func registerKey(ticketID string) string {
	return fmt.Sprintf("register:ticket:%s", ticketID)
}
