package repository

import "gorm.io/gorm"

func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&accountRecord{},
		&tokenRow{},
		&loginSessionRecord{},
		&signingKeyRecord{},
	)
}
