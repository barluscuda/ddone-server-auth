package tokenmanager

import (
	"context"
	"time"
)

type UseCase interface {
	List(ctx context.Context, input ListInput) ([]View, error)
	Revoke(ctx context.Context, input RevokeInput) error
	RevokeAll(ctx context.Context, input RevokeAllInput) error
}

type ListInput struct {
	AccountID string
}

type RevokeInput struct {
	AccountID string
	TokenID   string
}

type RevokeAllInput struct {
	AccountID string
}

type View struct {
	ID         string
	ClientIP   string
	UserAgent  string
	ExpiresAt  time.Time
	LastUsedAt *time.Time
	ReplacedAt *time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
}
