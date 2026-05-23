package auth

import "time"

type LoginSession struct {
	ID                   string
	AccountID            string
	TokenHash            string
	UserAgent            string
	ClientIP             string
	CurrentAccessToken   string
	CurrentAccessExpires time.Time
	ExpiresAt            time.Time
	RevokedAt            *time.Time
	RevokeReason         string
	CreatedAt            time.Time
}

func (s LoginSession) IsRevoked() bool {
	return s.RevokedAt != nil
}

func (s LoginSession) IsExpired(now time.Time) bool {
	return s.ExpiresAt.IsZero() || !now.Before(s.ExpiresAt)
}

func (s LoginSession) HasActiveAccessToken(now time.Time) bool {
	return s.CurrentAccessToken != "" && now.Before(s.CurrentAccessExpires)
}
