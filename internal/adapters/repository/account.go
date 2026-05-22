package repository

import (
	"context"
	"ddone-server-auth/internal/domain/account"
	"ddone-server-auth/internal/ports"
	"errors"

	"gorm.io/gorm"
)

type AccountRepository struct {
	db *gorm.DB
}

var _ ports.AccountRepository = (*AccountRepository)(nil)

func NewAccountRepository(db *gorm.DB) *AccountRepository {
	return &AccountRepository{db: db}
}

func (r *AccountRepository) Create(ctx context.Context, accountModel *account.AccountModel) error {
	return r.baseQuery(ctx).Create(accountModel).Error
}

func (r *AccountRepository) GetByID(ctx context.Context, id string) (*account.AccountModel, error) {
	var accountModel account.AccountModel

	err := r.preloadProviders(r.baseQuery(ctx)).
		First(&accountModel, "id = ?", id).
		Error
	if err != nil {
		return nil, translateAccountError(err)
	}

	return &accountModel, nil
}

func (r *AccountRepository) GetByPhoneNumber(ctx context.Context, phoneNumber string) (*account.AccountModel, error) {
	var accountModel account.AccountModel

	err := r.preloadProviders(r.baseQuery(ctx)).
		First(&accountModel, "phone_number = ?", phoneNumber).
		Error
	if err != nil {
		return nil, translateAccountError(err)
	}

	return &accountModel, nil
}

func (r *AccountRepository) GetByUsername(ctx context.Context, username string) (*account.AccountModel, error) {
	var accountModel account.AccountModel

	err := r.preloadProviders(r.baseQuery(ctx)).
		First(&accountModel, "username = ?", username).
		Error
	if err != nil {
		return nil, translateAccountError(err)
	}

	return &accountModel, nil
}

func (r *AccountRepository) GetByProvider(
	ctx context.Context,
	provider account.AuthProvider,
	providerUserID string,
) (*account.AccountModel, error) {
	var accountModel account.AccountModel

	err := r.preloadProviders(r.baseQuery(ctx)).
		Joins("JOIN account_providers ON account_providers.account_id = accounts.id").
		Where(
			"account_providers.provider = ? AND account_providers.provider_user_id = ?",
			provider,
			providerUserID,
		).
		First(&accountModel).
		Error
	if err != nil {
		return nil, translateAccountError(err)
	}

	return &accountModel, nil
}

func (r *AccountRepository) Update(ctx context.Context, accountModel *account.AccountModel) error {
	return r.baseQuery(ctx).Transaction(func(tx *gorm.DB) error {
		var existing account.AccountModel

		err := tx.Select("id").First(&existing, "id = ?", accountModel.ID).Error
		if err != nil {
			return translateAccountError(err)
		}

		return tx.Session(&gorm.Session{FullSaveAssociations: true}).
			Save(accountModel).
			Error
	})
}

func (r *AccountRepository) Delete(ctx context.Context, id string) error {
	var accountModel account.AccountModel

	err := r.baseQuery(ctx).First(&accountModel, "id = ?", id).Error
	if err != nil {
		return translateAccountError(err)
	}

	return r.baseQuery(ctx).Delete(&accountModel).Error
}

func (r *AccountRepository) baseQuery(ctx context.Context) *gorm.DB {
	return r.db.WithContext(ctx)
}

func (r *AccountRepository) preloadProviders(query *gorm.DB) *gorm.DB {
	return query.Preload("Providers", func(db *gorm.DB) *gorm.DB {
		return db.Order("linked_at ASC")
	})
}

func translateAccountError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return account.ErrAccountNotFound
	}

	return err
}
