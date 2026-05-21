package dto

import "time"

type ReqRegisterOTP struct {
	Username    *string `json:"username" binding:"omitempty,min=3,max=50"`
	PhoneNumber string  `json:"phone_number" binding:"required,min=8,max=20"`
}

type ReqVerifyRegisterOTP struct {
	PhoneNumber string `json:"phone_number" binding:"required,min=8,max=20"`
	OTPCode     string `json:"otp_code" binding:"required,len=6,numeric"`
}

type ResRegisterOTPRequested struct {
	Message   string    `json:"message"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ResRegisteredAccount struct {
	ID              string    `json:"id"`
	Username        *string   `json:"username"`
	PhoneNumber     string    `json:"phone_number"`
	PhoneVerifiedAt time.Time `json:"phone_verified_at"`
	CreatedAt       time.Time `json:"created_at"`
}
