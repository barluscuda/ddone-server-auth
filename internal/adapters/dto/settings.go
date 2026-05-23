package dto

import "time"

type ResSettingsMe struct {
	Success bool              `json:"success"`
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Data    ResSettingsMeData `json:"data"`
}

type ResSettingsMeData struct {
	ID              string    `json:"id"`
	Username        *string   `json:"username,omitempty"`
	PhoneNumber     string    `json:"phoneNumber"`
	PhoneVerifiedAt time.Time `json:"phoneVerifiedAt"`
	CreatedAt       time.Time `json:"createdAt"`
}

type ResSettingsSessions struct {
	Success bool                     `json:"success"`
	Code    string                   `json:"code"`
	Message string                   `json:"message"`
	Data    []ResSettingsSessionData `json:"data"`
}

type ResSettingsSessionData struct {
	ID                   string     `json:"id"`
	ClientIP             string     `json:"clientIp,omitempty"`
	UserAgent            string     `json:"userAgent,omitempty"`
	CurrentAccessExpires time.Time  `json:"currentAccessExpires"`
	CreatedAt            time.Time  `json:"createdAt"`
	RevokedAt            *time.Time `json:"revokedAt,omitempty"`
}
