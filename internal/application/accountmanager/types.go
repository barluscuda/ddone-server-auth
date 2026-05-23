package accountmanager

import "time"

type GetMeInput struct {
	AccountID string
}

type ListMySessionsInput struct {
	AccountID string
}

type AccountView struct {
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
