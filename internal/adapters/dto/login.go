package dto

import "time"

type ReqLogin struct {
	PhoneNumber string `json:"phoneNumber" binding:"required,min=8,max=20"`
	Password    string `json:"password" binding:"required,min=8,max=72"`
}

type ReqRefreshLogin struct {
	RefreshToken string `json:"refreshToken" binding:"required"`
}

type ResLoginData struct {
	AccessToken      string    `json:"accessToken,omitempty"`
	TokenType        string    `json:"tokenType,omitempty"`
	ExpiresAt        time.Time `json:"expiresAt,omitempty"`
	ExpiresIn        int64     `json:"expiresIn,omitempty"`
	RefreshToken     string    `json:"refreshToken,omitempty"`
	RefreshExpiresAt time.Time `json:"refreshExpiresAt,omitempty"`
}

type ResLogin struct {
	Success bool         `json:"success"`
	Code    string       `json:"code"`
	Message string       `json:"message"`
	Data    ResLoginData `json:"data"`
}
