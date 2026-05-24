package dto

import "time"

type ResTokenManagerTokens struct {
	Success bool                  `json:"success"`
	Code    string                `json:"code"`
	Message string                `json:"message"`
	Data    []ResTokenManagerData `json:"data"`
}

type ResTokenManagerData struct {
	ID         string     `json:"id"`
	ClientIP   string     `json:"clientIp,omitempty"`
	UserAgent  string     `json:"userAgent,omitempty"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	ReplacedAt *time.Time `json:"replacedAt,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
}
