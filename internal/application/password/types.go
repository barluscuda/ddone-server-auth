package password

import (
	"context"
	"time"
)

type UseCase interface {
	ForgotPassword(ctx context.Context, input ForgotPasswordInput) (*ResetTicketResult, error)
	ResendForgotPasswordOTP(ctx context.Context, input ResendForgotPasswordInput) (*ResetTicketResult, error)
	VerifyForgotPassword(ctx context.Context, input VerifyForgotPasswordInput) error
	ChangePassword(ctx context.Context, input ChangePasswordInput) error
}

type ForgotPasswordInput struct {
	PhoneNumber string
	ClientID    string
}

type ResendForgotPasswordInput struct {
	TicketID string
	ClientID string
}

type VerifyForgotPasswordInput struct {
	TicketID    string
	OTPCode     string
	NewPassword string
	ClientID    string
}

type ChangePasswordInput struct {
	UserID       string
	CurrentPassword string
	NewPassword     string
}

type ResetTicketResult struct {
	TicketID             string
	ExpiresAt            time.Time
	RemainingResendCount int
}

type ResetTicketState struct {
	TicketID      string    `json:"ticket_id"`
	UserID     string    `json:"user_id"`
	PhoneNumber   string    `json:"phone_number"`
	OTPCodeHash   string    `json:"otp_code_hash"`
	OTPExpiresAt  time.Time `json:"otp_expires_at"`
	ResendCount   int       `json:"resend_count"`
	LastOTPSentAt time.Time `json:"last_otp_sent_at"`
	CreatedAt     time.Time `json:"created_at"`
}
