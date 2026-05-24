package repository

import (
	"context"
	applogin "ddone-server-auth/internal/application/login"
	apppassword "ddone-server-auth/internal/application/password"
	appregister "ddone-server-auth/internal/application/register"
	appsettings "ddone-server-auth/internal/application/settings"
	"ddone-server-auth/internal/domain/user"
	"errors"
	"time"

	"gorm.io/gorm"
)

type UserRepository struct {
	db *gorm.DB
}

type accountRecord struct {
	ID                string    `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Username          *string   `gorm:"size:50;uniqueIndex"`
	PasswordHash      string    `gorm:"size:255;not null"`
	PhoneNumber       string    `gorm:"size:20;not null;uniqueIndex"`
	PhoneVerifiedAt   time.Time `gorm:"not null"`
	UsernameChangedAt *time.Time
	PasswordChangedAt *time.Time
	CreatedAt         time.Time `gorm:"not null"`
	UpdatedAt         time.Time `gorm:"not null"`
}

func (accountRecord) TableName() string {
	return "accounts"
}

var _ appregister.UserStore = (*UserRepository)(nil)
var _ applogin.UserLookup = (*UserRepository)(nil)
var _ appsettings.UserReader = (*UserRepository)(nil)
var _ apppassword.UserStore = (*UserRepository)(nil)

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, userModel *user.User) error {
	record := toAccountRecord(userModel)
	if err := r.baseQuery(ctx).Create(record).Error; err != nil {
		return err
	}

	*userModel = *toUser(record)
	return nil
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (*user.User, error) {
	var record accountRecord

	err := r.baseQuery(ctx).First(&record, "id = ?", id).Error
	if err != nil {
		return nil, translateUserError(err)
	}

	return toUser(&record), nil
}

func (r *UserRepository) GetByPhoneNumber(ctx context.Context, phoneNumber string) (*user.User, error) {
	var record accountRecord

	err := r.baseQuery(ctx).First(&record, "phone_number = ?", phoneNumber).Error
	if err != nil {
		return nil, translateUserError(err)
	}

	return toUser(&record), nil
}

func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*user.User, error) {
	var record accountRecord

	err := r.baseQuery(ctx).First(&record, "username = ?", username).Error
	if err != nil {
		return nil, translateUserError(err)
	}

	return toUser(&record), nil
}

func (r *UserRepository) Update(ctx context.Context, userModel *user.User) error {
	return r.baseQuery(ctx).Transaction(func(tx *gorm.DB) error {
		var existing accountRecord

		err := tx.Select("id").First(&existing, "id = ?", userModel.ID).Error
		if err != nil {
			return translateUserError(err)
		}

		record := toAccountRecord(userModel)
		return tx.Session(&gorm.Session{FullSaveAssociations: true}).
			Save(record).
			Error
	})
}

func (r *UserRepository) Delete(ctx context.Context, id string) error {
	var record accountRecord

	err := r.baseQuery(ctx).First(&record, "id = ?", id).Error
	if err != nil {
		return translateUserError(err)
	}

	return r.baseQuery(ctx).Delete(&record).Error
}

func (r *UserRepository) baseQuery(ctx context.Context) *gorm.DB {
	return r.db.WithContext(ctx)
}

func toAccountRecord(userModel *user.User) *accountRecord {
	return &accountRecord{
		ID:                userModel.ID,
		Username:          userModel.Username,
		PasswordHash:      userModel.PasswordHash,
		PhoneNumber:       userModel.PhoneNumber,
		PhoneVerifiedAt:   userModel.PhoneVerifiedAt,
		UsernameChangedAt: userModel.UsernameChangedAt,
		PasswordChangedAt: userModel.PasswordChangedAt,
		CreatedAt:         userModel.CreatedAt,
		UpdatedAt:         userModel.UpdatedAt,
	}
}

func toUser(record *accountRecord) *user.User {
	return &user.User{
		ID:                record.ID,
		Username:          record.Username,
		PasswordHash:      record.PasswordHash,
		PhoneNumber:       record.PhoneNumber,
		PhoneVerifiedAt:   record.PhoneVerifiedAt,
		UsernameChangedAt: record.UsernameChangedAt,
		PasswordChangedAt: record.PasswordChangedAt,
		CreatedAt:         record.CreatedAt,
		UpdatedAt:         record.UpdatedAt,
	}
}

func translateUserError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return user.ErrUserNotFound
	}

	return err
}
