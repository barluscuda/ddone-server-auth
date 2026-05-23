package settings

import (
	"context"

	"ddone-server-auth/internal/domain/account"
	"ddone-server-auth/internal/domain/auth"
)

type AccountReader interface {
	GetByID(ctx context.Context, id string) (*account.AccountModel, error)
}

type SessionReader interface {
	ListByAccountID(ctx context.Context, accountID string) ([]auth.LoginSession, error)
}
