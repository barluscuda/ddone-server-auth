package login

import (
	"time"

	"ddone-server-auth/internal/domain/auth"
)

type Settings struct {
	RefreshTokenTTL time.Duration
	LoginSessionTTL time.Duration
}

type LoginInput struct {
	PhoneNumber string
	Password    string
	ClientIP    string
	UserAgent   string
}

type RefreshInput struct {
	RefreshToken string
	ClientIP     string
	UserAgent    string
}

type Result struct {
	AccessToken      *auth.AccessToken
	RefreshToken     string
	RefreshExpiresAt time.Time
}

type SessionResult struct {
	SessionToken string
	AccessToken  *auth.AccessToken
}
