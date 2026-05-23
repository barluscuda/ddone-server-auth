package auth

import "time"

type AccessToken struct {
	Token     string
	TokenType string
	ExpiresAt time.Time
	ExpiresIn int64
	KeyID     string
}

type AccessTokenClaims struct {
	Issuer      string
	AccountID   string
	Subject     string
	Audience    string
	JWTID       string
	PhoneNumber string
	IssuedAt    time.Time
	NotBefore   time.Time
	ExpiresAt   time.Time
}
