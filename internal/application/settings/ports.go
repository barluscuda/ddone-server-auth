package settings

import (
	"context"

	"ddone-server-auth/internal/domain/user"
)

type UserReader interface {
	GetByID(ctx context.Context, id string) (*user.UserModel, error)
	GetByUsername(ctx context.Context, username string) (*user.UserModel, error)
	Update(ctx context.Context, userModel *user.UserModel) error
}
