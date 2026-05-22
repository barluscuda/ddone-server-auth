package dto

import "time"

type ReqRegister struct {
	PhoneNumber string `json:"phone_number" binding:"required,min=8,max=20"`
	Password    string `json:"password" binding:"required,min=8,max=72"`
}

type ReqVerifyRegister struct {
	TicketID string `json:"ticket_id" binding:"required"`
	OTPCode  string `json:"otp_code" binding:"required,len=6,numeric"`
}

type ReqResendRegisterOTP struct {
	TicketID string `json:"ticket_id" binding:"required"`
}

type ResRegister struct {
	Message   string    `json:"message"`
	TicketID  string    `json:"ticket_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ResRegisteredAccount struct {
	ID              string    `json:"id"`
	Username        *string   `json:"username"`
	PhoneNumber     string    `json:"phone_number"`
	PhoneVerifiedAt time.Time `json:"phone_verified_at"`
	CreatedAt       time.Time `json:"created_at"`
}
