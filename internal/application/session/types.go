package session

import (
	"context"
	"ddone-server-auth/internal/domain/auth"
	"time"
)

type UseCase interface {
	List(ctx context.Context, input ListInput) ([]View, error)
	Current(ctx context.Context, input CurrentInput) (*View, error)
	IssueAccessToken(ctx context.Context, input IssueAccessTokenInput) (*IssueAccessTokenResult, error)
	Revoke(ctx context.Context, input RevokeInput) error
	RevokeOthers(ctx context.Context, input RevokeOthersInput) error
	RevokeAll(ctx context.Context, input RevokeAllInput) error
}

type ListInput struct {
	UserID string
}

type RevokeInput struct {
	UserID    string
	SessionID string
}

type CurrentInput struct {
	UserID    string
	SessionID string
}

type RevokeOthersInput struct {
	UserID    string
	SessionID string
}

type RevokeAllInput struct {
	UserID string
}

type IssueAccessTokenInput struct {
	UserID    string
	SessionID string
}

type IssueAccessTokenResult struct {
	AccessToken *auth.AccessToken
	Refreshed   bool
}

type Settings struct {
	LoginSessionTTL time.Duration
}

type View struct {
	ID                   string
	ClientIP             string
	UserAgent            string
	CurrentAccessExpires time.Time
	CreatedAt            time.Time
	RevokedAt            *time.Time
}
