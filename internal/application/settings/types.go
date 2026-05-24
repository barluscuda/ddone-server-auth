package settings

import "time"

type GetInput struct {
	AccountID string
}

type UpdateUsernameInput struct {
	AccountID string
	Username  string
}

type View struct {
	ID              string
	Username        *string
	PhoneNumber     string
	PhoneVerifiedAt time.Time
	CreatedAt       time.Time
}

type UsernameView struct {
	Username          string
	UsernameChangedAt time.Time
}
