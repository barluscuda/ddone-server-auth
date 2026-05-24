package auth

import "time"

// LoginSession is a server-managed session. Its current access token is replaced
// in place when the session needs a fresh JWT.
type LoginSession struct {
	ID                   string
	UserID            string
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
