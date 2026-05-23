package repository

import "gorm.io/gorm"

func MigrateAuth(db *gorm.DB) error {
	return db.AutoMigrate(
		&refreshSessionRecord{},
		&loginSessionRecord{},
		&signingKeyRecord{},
	)
}
