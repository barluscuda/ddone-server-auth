package dto

import "time"

type ReqForgotPassword struct {
	PhoneNumber string `json:"phoneNumber" binding:"required,min=8,max=20"`
}

type ReqResendForgotPassword struct {
	TicketID string `json:"ticketId" binding:"required"`
}

type ReqVerifyForgotPassword struct {
	TicketID    string `json:"ticketId" binding:"required"`
	OTPCode     string `json:"otpCode" binding:"required,len=6,numeric"`
	NewPassword string `json:"newPassword" binding:"required,min=8,max=72"`
}

type ReqChangePassword struct {
	CurrentPassword string `json:"currentPassword" binding:"required,min=8,max=72"`
	NewPassword     string `json:"newPassword" binding:"required,min=8,max=72"`
}

type ResPasswordResetTicketData struct {
	TicketID              string    `json:"ticketId"`
	ExpiresAt             time.Time `json:"expiresAt"`
	OTPLength             int       `json:"otpLength"`
	ResendCooldownSeconds int       `json:"resendCooldownSeconds"`
	RemainingResendCount  int       `json:"remainingResendCount"`
}

type ResPasswordReset struct {
	Success bool                       `json:"success"`
	Code    string                     `json:"code"`
	Message string                     `json:"message"`
	Data    ResPasswordResetTicketData `json:"data"`
}
