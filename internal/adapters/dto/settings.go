package dto

import "time"

type ResSettingsMe struct {
	Success bool              `json:"success"`
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Data    ResSettingsMeData `json:"data"`
}

type ResSettingsMeData struct {
	ID                  string     `json:"id"`
	Username            *string    `json:"username,omitempty"`
	PhoneNumber         string     `json:"phoneNumber"`
	PhoneVerifiedAt     time.Time  `json:"phoneVerifiedAt"`
	UsernameChangedAt   *time.Time `json:"usernameChangedAt,omitempty"`
	UsernameCanChangeAt *time.Time `json:"usernameCanChangeAt,omitempty"`
	CanChangeUsername   bool       `json:"canChangeUsername"`
	CanChangePassword   bool       `json:"canChangePassword"`
	PasswordChangedAt   *time.Time `json:"passwordChangedAt,omitempty"`
	CreatedAt           time.Time  `json:"createdAt"`
	UpdatedAt           time.Time  `json:"updatedAt"`
}

type ReqUpdateUsername struct {
	Username string `json:"username"`
}

type ResSettingsUsername struct {
	Success bool                    `json:"success"`
	Code    string                  `json:"code"`
	Message string                  `json:"message"`
	Data    ResSettingsUsernameData `json:"data"`
}

type ResSettingsUsernameData struct {
	Username          string    `json:"username"`
	UsernameChangedAt time.Time `json:"usernameChangedAt"`
}

type ResSettingsSessions struct {
	Success bool                     `json:"success"`
	Code    string                   `json:"code"`
	Message string                   `json:"message"`
	Data    []ResSettingsSessionData `json:"data"`
}

type ResSettingsSession struct {
	Success bool                   `json:"success"`
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Data    ResSettingsSessionData `json:"data"`
}

type ResSettingsSessionData struct {
	ID                   string     `json:"id"`
	ClientIP             string     `json:"clientIp,omitempty"`
	UserAgent            string     `json:"userAgent,omitempty"`
	CurrentAccessExpires time.Time  `json:"currentAccessExpires"`
	CreatedAt            time.Time  `json:"createdAt"`
	RevokedAt            *time.Time `json:"revokedAt,omitempty"`
}
