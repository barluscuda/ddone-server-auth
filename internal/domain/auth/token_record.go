package auth

import "time"

// TokenRecord is the server-side record for a client-managed raw refresh token.
// Rotations create a replacement record so the token lineage remains auditable.
type TokenRecord struct {
	ID            string
	AccountID     string
	RootTokenID   string
	ParentTokenID *string
	TokenHash     string
	UserAgent     string
	ClientIP      string
	ExpiresAt     time.Time
	LastUsedAt    *time.Time
	ReplacedAt    *time.Time
	RevokedAt     *time.Time
	RevokeReason  string
	CreatedAt     time.Time
}

func (t TokenRecord) IsExpired(now time.Time) bool {
	return !t.ExpiresAt.IsZero() && !now.Before(t.ExpiresAt)
}

func (t TokenRecord) IsReplaced() bool {
	return t.ReplacedAt != nil
}

func (t TokenRecord) IsRevoked() bool {
	return t.RevokedAt != nil
}
