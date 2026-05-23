package auth

import "time"

const (
	SigningKeyStatusActive    = "active"
	SigningKeyStatusScheduled = "scheduled"
	SigningKeyStatusRetired   = "retired"
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

func (k SigningKey) IsActiveAt(now time.Time) bool {
	return !now.Before(k.ActivatesAt) && now.Before(k.RotatesAt)
}

func (k SigningKey) IsPublishedAt(now time.Time) bool {
	return now.Before(k.RetiresAt)
}

func (k SigningKey) IsFutureAt(now time.Time) bool {
	return now.Before(k.ActivatesAt) && k.IsPublishedAt(now)
}
