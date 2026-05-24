package repository

import (
	"context"
	applogin "ddone-server-auth/internal/application/login"
	apppassword "ddone-server-auth/internal/application/password"
	appregister "ddone-server-auth/internal/application/register"
	appsettings "ddone-server-auth/internal/application/settings"
	"ddone-server-auth/internal/domain/user"
	"errors"

	"gorm.io/gorm"
)

type UserRepository struct {
	db *gorm.DB
}

var _ appregister.UserStore = (*UserRepository)(nil)
var _ applogin.UserLookup = (*UserRepository)(nil)
var _ appsettings.UserReader = (*UserRepository)(nil)
var _ apppassword.UserStore = (*UserRepository)(nil)

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, userModel *user.UserModel) error {
	return r.baseQuery(ctx).Create(userModel).Error
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (*user.UserModel, error) {
	var userModel user.UserModel

	err := r.baseQuery(ctx).First(&userModel, "id = ?", id).Error
	if err != nil {
		return nil, translateUserError(err)
	}

	return &userModel, nil
}

func (r *UserRepository) GetByPhoneNumber(ctx context.Context, phoneNumber string) (*user.UserModel, error) {
	var userModel user.UserModel

	err := r.baseQuery(ctx).First(&userModel, "phone_number = ?", phoneNumber).Error
	if err != nil {
		return nil, translateUserError(err)
	}

	return &userModel, nil
}

func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*user.UserModel, error) {
	var userModel user.UserModel

	err := r.baseQuery(ctx).First(&userModel, "username = ?", username).Error
	if err != nil {
		return nil, translateUserError(err)
	}

	return &userModel, nil
}

func (r *UserRepository) Update(ctx context.Context, userModel *user.UserModel) error {
	return r.baseQuery(ctx).Transaction(func(tx *gorm.DB) error {
		var existing user.UserModel

		err := tx.Select("id").First(&existing, "id = ?", userModel.ID).Error
		if err != nil {
			return translateUserError(err)
		}

		return tx.Session(&gorm.Session{FullSaveAssociations: true}).
			Save(userModel).
			Error
	})
}

func (r *UserRepository) Delete(ctx context.Context, id string) error {
	var userModel user.UserModel

	err := r.baseQuery(ctx).First(&userModel, "id = ?", id).Error
	if err != nil {
		return translateUserError(err)
	}

	return r.baseQuery(ctx).Delete(&userModel).Error
}

func (r *UserRepository) baseQuery(ctx context.Context) *gorm.DB {
	return r.db.WithContext(ctx)
}

func translateUserError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return user.ErrUserNotFound
	}

	return err
}
