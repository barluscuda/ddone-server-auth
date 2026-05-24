package settings

import "time"

type GetInput struct {
	UserID string
}

type UpdateUsernameInput struct {
	UserID   string
	Username string
}

type View struct {
	ID                  string
	Username            *string
	PhoneNumber         string
	PhoneVerifiedAt     time.Time
	UsernameChangedAt   *time.Time
	UsernameCanChangeAt *time.Time
	CanChangeUsername   bool
	CanChangePassword   bool
	PasswordChangedAt   *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type UsernameView struct {
	Username          string
	UsernameChangedAt time.Time
}
