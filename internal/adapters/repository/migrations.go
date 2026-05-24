package repository

import (
	"ddone-server-auth/internal/domain/user"

	"gorm.io/gorm"
)

func Migrate(db *gorm.DB) error {
	if err := enableGenRandomUUID(db); err != nil {
		return err
	}

	return db.AutoMigrate(
		&user.UserModel{},
		&tokenRow{},
		&loginSessionRecord{},
		&signingKeyRecord{},
	)
}

func enableGenRandomUUID(db *gorm.DB) error {
	return db.Exec(`CREATE EXTENSION IF NOT EXISTS pgcrypto`).Error
}
