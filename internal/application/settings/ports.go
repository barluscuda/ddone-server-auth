package settings

import (
	"context"

	"ddone-server-auth/internal/domain/account"
)

type AccountReader interface {
	GetByID(ctx context.Context, id string) (*account.AccountModel, error)
	GetByUsername(ctx context.Context, username string) (*account.AccountModel, error)
	Update(ctx context.Context, accountModel *account.AccountModel) error
}
