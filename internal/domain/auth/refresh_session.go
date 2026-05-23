package auth

import "time"

type RefreshSession struct {
	ID              string
	AccountID       string
	RootSessionID   string
	ParentSessionID *string
	TokenHash       string
	UserAgent       string
	ClientIP        string
	ExpiresAt       time.Time
	LastUsedAt      *time.Time
	ReplacedAt      *time.Time
	RevokedAt       *time.Time
	RevokeReason    string
	CreatedAt       time.Time
}

func (s RefreshSession) IsExpired(now time.Time) bool {
	return !s.ExpiresAt.IsZero() && !now.Before(s.ExpiresAt)
}

func (s RefreshSession) IsReplaced() bool {
	return s.ReplacedAt != nil
}

func (s RefreshSession) IsRevoked() bool {
	return s.RevokedAt != nil
}
