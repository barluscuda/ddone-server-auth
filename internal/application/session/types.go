package session

import (
	"context"
	"time"
)

type UseCase interface {
	List(ctx context.Context, input ListInput) ([]View, error)
	Current(ctx context.Context, input CurrentInput) (*View, error)
	Revoke(ctx context.Context, input RevokeInput) error
	RevokeOthers(ctx context.Context, input RevokeOthersInput) error
	RevokeAll(ctx context.Context, input RevokeAllInput) error
}

type ListInput struct {
	AccountID string
}

type RevokeInput struct {
	AccountID string
	SessionID string
}

type CurrentInput struct {
	AccountID   string
	AccessToken string
}

type RevokeOthersInput struct {
	AccountID   string
	AccessToken string
}

type RevokeAllInput struct {
	AccountID string
}

type View struct {
	ID                   string
	ClientIP             string
	UserAgent            string
	CurrentAccessExpires time.Time
	CreatedAt            time.Time
	RevokedAt            *time.Time
}
