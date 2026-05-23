package dto

import "time"

type ResAccountMe struct {
	Success bool             `json:"success"`
	Code    string           `json:"code"`
	Message string           `json:"message"`
	Data    ResAccountMeData `json:"data"`
}

type ResAccountMeData struct {
	ID              string    `json:"id"`
	Username        *string   `json:"username,omitempty"`
	PhoneNumber     string    `json:"phoneNumber"`
	PhoneVerifiedAt time.Time `json:"phoneVerifiedAt"`
	CreatedAt       time.Time `json:"createdAt"`
}

type ResAccountSessions struct {
	Success bool                    `json:"success"`
	Code    string                  `json:"code"`
	Message string                  `json:"message"`
	Data    []ResAccountSessionData `json:"data"`
}

type ResAccountSessionData struct {
	ID                   string     `json:"id"`
	ClientIP             string     `json:"clientIp,omitempty"`
	UserAgent            string     `json:"userAgent,omitempty"`
	CurrentAccessExpires time.Time  `json:"currentAccessExpires"`
	CreatedAt            time.Time  `json:"createdAt"`
	RevokedAt            *time.Time `json:"revokedAt,omitempty"`
}
