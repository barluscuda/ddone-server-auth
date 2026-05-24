package user

import "time"

type User struct {
	ID                string
	Username          *string
	PasswordHash      string
	PhoneNumber       string
	PhoneVerifiedAt   time.Time
	UsernameChangedAt *time.Time
	PasswordChangedAt *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type PendingRegistration struct {
	TicketID      string
	Username      *string
	PasswordHash  string
	PhoneNumber   string
	OTPCodeHash   string
	OTPExpiresAt  time.Time
	ResendCount   int
	LastOTPSentAt time.Time
	CreatedAt     time.Time
}
