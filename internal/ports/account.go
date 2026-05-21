package ports

import (
	"context"

	"ddone-server-auth/internal/domain/account"
)

type AccountRepository interface {
	Create(ctx context.Context, account *account.AccountModel) error
	GetByID(ctx context.Context, id string) (*account.AccountModel, error)
	GetByPhoneNumber(ctx context.Context, phoneNumber string) (*account.AccountModel, error)
	GetByUsername(ctx context.Context, username string) (*account.AccountModel, error)
	GetByProvider(ctx context.Context, provider account.AuthProvider, providerUserID string) (*account.AccountModel, error)
	Update(ctx context.Context, account *account.AccountModel) error
	Delete(ctx context.Context, id string) error
}
