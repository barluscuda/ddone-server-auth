package account

import "time"

type AccountModel struct {
	ID              string    `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Username        *string   `gorm:"size:50;uniqueIndex"`
	PasswordHash    string    `gorm:"size:255;not null"`
	PhoneNumber     string    `gorm:"size:20;not null;uniqueIndex"`
	PhoneVerifiedAt time.Time `gorm:"not null"`
	CreatedAt       time.Time `gorm:"not null"`
	UpdatedAt       time.Time `gorm:"not null"`
}

type RegisterModel struct {
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

func (AccountModel) TableName() string {
	return "accounts"
}
