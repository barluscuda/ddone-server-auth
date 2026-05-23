package repository

import (
	"ddone-server-auth/internal/domain/account"

	"gorm.io/gorm"
)

func Migrate(db *gorm.DB) error {
	if err := enableGenRandomUUID(db); err != nil {
		return err
	}

	return db.AutoMigrate(
		&account.AccountModel{},
		&account.AccountProviderModel{},
		&refreshSessionRecord{},
		&loginSessionRecord{},
		&signingKeyRecord{},
	)
}

func enableGenRandomUUID(db *gorm.DB) error {
	return db.Exec(`CREATE EXTENSION IF NOT EXISTS pgcrypto`).Error
}
