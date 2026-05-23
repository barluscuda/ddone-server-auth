package dto

import "time"

type ReqLogin struct {
	PhoneNumber string `json:"phone_number" binding:"required,min=8,max=20"`
	Password    string `json:"password" binding:"required,min=8,max=72"`
}

type ReqRefreshLogin struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type ResLoginData struct {
	AccessToken      string    `json:"access_token"`
	TokenType        string    `json:"token_type"`
	ExpiresAt        time.Time `json:"expires_at"`
	ExpiresIn        int64     `json:"expires_in"`
	RefreshToken     string    `json:"refresh_token,omitempty"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at,omitempty"`
}

type ResLogin struct {
	Success bool         `json:"success"`
	Code    string       `json:"code"`
	Message string       `json:"message"`
	Data    ResLoginData `json:"data"`
}
