package dto

import "time"

type ReqRegister struct {
	PhoneNumber string `json:"phoneNumber" binding:"required,min=8,max=20"`
	Password    string `json:"password" binding:"required,min=8,max=72"`
}

type ReqVerifyRegister struct {
	TicketID string `json:"ticketId" binding:"required"`
	OTPCode  string `json:"otpCode" binding:"required,len=6,numeric"`
}

type ReqResendRegisterOTP struct {
	TicketID string `json:"ticketId" binding:"required"`
}

type ResRegisterTicketData struct {
	TicketID              string    `json:"ticketId"`
	ExpiresAt             time.Time `json:"expiresAt"`
	OTPLength             int       `json:"otpLength"`
	ResendCooldownSeconds int       `json:"resendCooldownSeconds"`
	RemainingResendCount  int       `json:"remainingResendCount"`
}

type ResRegister struct {
	Success bool                  `json:"success"`
	Code    string                `json:"code"`
	Message string                `json:"message"`
	Data    ResRegisterTicketData `json:"data"`
}

type ResRegisteredAccountData struct {
	ID              string    `json:"id"`
	Username        *string   `json:"username"`
	PhoneNumber     string    `json:"phoneNumber"`
	PhoneVerifiedAt time.Time `json:"phoneVerifiedAt"`
	CreatedAt       time.Time `json:"createdAt"`
}

type ResRegisteredAccount struct {
	Success bool                     `json:"success"`
	Code    string                   `json:"code"`
	Message string                   `json:"message"`
	Data    ResRegisteredAccountData `json:"data"`
}
