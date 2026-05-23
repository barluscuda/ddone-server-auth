package auth

import "time"

const (
	SigningKeyStatusActive  = "active"
	SigningKeyStatusRetired = "retired"
)

type SigningKey struct {
	KeyID         string
	Algorithm     string
	Curve         string
	PublicX       string
	PublicY       string
	PrivateKeyPEM string
	Status        string
	CreatedAt     time.Time
	ActivatesAt   time.Time
	RotatesAt     time.Time
	RetiresAt     time.Time
}
