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
	AccessToken      string    `json:"accessToken"`
	TokenType        string    `json:"tokenType"`
	ExpiresAt        time.Time `json:"expiresAt"`
	ExpiresIn        int64     `json:"expiresIn"`
	RefreshToken     string    `json:"refreshToken,omitempty"`
	RefreshExpiresAt time.Time `json:"refreshExpiresAt,omitempty"`
}

type ResLogin struct {
	Success bool         `json:"success"`
	Code    string       `json:"code"`
	Message string       `json:"message"`
	Data    ResLoginData `json:"data"`
}
