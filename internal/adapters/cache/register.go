package cache

import (
	"context"
	appregister "ddone-server-auth/internal/application/register"
	"ddone-server-auth/internal/domain/user"
	"errors"
	"fmt"
	"strconv"
	"time"

	json "github.com/bytedance/sonic"
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

var registerAdjustScoreScript = redis.NewScript(`
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

func (s *RegisterStore) AdjustScore(ctx context.Context, key string, delta float64, ttl time.Duration) (float64, error) {
	result, err := registerAdjustScoreScript.Run(
		ctx,
		s.client,
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
