package settings

import "time"

type GetInput struct {
	AccountID string
}

type ListSessionsInput struct {
	AccountID string
}

type View struct {
	ID              string
	Username        *string
	PhoneNumber     string
	PhoneVerifiedAt time.Time
	CreatedAt       time.Time
}

type SessionView struct {
	ID                   string
	ClientIP             string
	UserAgent            string
	CurrentAccessExpires time.Time
	CreatedAt            time.Time
	RevokedAt            *time.Time
}
