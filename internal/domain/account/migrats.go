package account

import "gorm.io/gorm"

func EnableGenRandomUUID(db *gorm.DB) error {
	return db.Exec(`CREATE EXTENSION IF NOT EXISTS pgcrypto`).Error
}

func Migrate(db *gorm.DB) error {
	if err := EnableGenRandomUUID(db); err != nil {
		return err
	}

	return db.AutoMigrate(
		&AccountModel{},
		&AccountProviderModel{},
		&DeletedAccountModel{},
	)
}
