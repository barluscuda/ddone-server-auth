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

type pendingRegistrationRecord struct {
	TicketID      string    `json:"ticket_id"`
	Username      *string   `json:"username"`
	PasswordHash  string    `json:"password_hash"`
	PhoneNumber   string    `json:"phone_number"`
	OTPCodeHash   string    `json:"otp_code_hash"`
	OTPExpiresAt  time.Time `json:"otp_expires_at"`
	ResendCount   int       `json:"resend_count"`
	LastOTPSentAt time.Time `json:"last_otp_sent_at"`
	CreatedAt     time.Time `json:"created_at"`
}

var _ appregister.RegistrationStore = (*RegisterStore)(nil)

func NewRegisterStore(client *redis.Client) *RegisterStore {
	return &RegisterStore{client: client}
}

func (s *RegisterStore) Save(ctx context.Context, registration *user.PendingRegistration, ttl time.Duration) error {
	payload, err := json.Marshal(toPendingRegistrationRecord(registration))
	if err != nil {
		return err
	}

	return s.client.Set(ctx, registerKey(registration.TicketID), payload, ttl).Err()
}

func (s *RegisterStore) Get(ctx context.Context, ticketID string) (*user.PendingRegistration, error) {
	payload, err := s.client.Get(ctx, registerKey(ticketID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, user.ErrPendingRegistrationNotFound
		}

		return nil, err
	}

	var record pendingRegistrationRecord
	if err := json.Unmarshal([]byte(payload), &record); err != nil {
		return nil, err
	}

	return toPendingRegistration(&record), nil
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

func toPendingRegistrationRecord(registration *user.PendingRegistration) *pendingRegistrationRecord {
	return &pendingRegistrationRecord{
		TicketID:      registration.TicketID,
		Username:      registration.Username,
		PasswordHash:  registration.PasswordHash,
		PhoneNumber:   registration.PhoneNumber,
		OTPCodeHash:   registration.OTPCodeHash,
		OTPExpiresAt:  registration.OTPExpiresAt,
		ResendCount:   registration.ResendCount,
		LastOTPSentAt: registration.LastOTPSentAt,
		CreatedAt:     registration.CreatedAt,
	}
}

func toPendingRegistration(record *pendingRegistrationRecord) *user.PendingRegistration {
	return &user.PendingRegistration{
		TicketID:      record.TicketID,
		Username:      record.Username,
		PasswordHash:  record.PasswordHash,
		PhoneNumber:   record.PhoneNumber,
		OTPCodeHash:   record.OTPCodeHash,
		OTPExpiresAt:  record.OTPExpiresAt,
		ResendCount:   record.ResendCount,
		LastOTPSentAt: record.LastOTPSentAt,
		CreatedAt:     record.CreatedAt,
	}
}
