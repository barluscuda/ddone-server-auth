package settings

import (
	"context"

	"ddone-server-auth/internal/domain/user"
)

type UserReader interface {
	GetByID(ctx context.Context, id string) (*user.User, error)
	GetByUsername(ctx context.Context, username string) (*user.User, error)
	Update(ctx context.Context, userModel *user.User) error
}
