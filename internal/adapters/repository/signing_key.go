package repository

import (
	"context"
	"ddone-server-auth/internal/application/jwks"
	"ddone-server-auth/internal/domain/auth"
	"errors"
	"time"

	"gorm.io/gorm"
)

const signingKeyRotationLockID int64 = 4193372101

type SigningKeyRepository struct {
	db *gorm.DB
}

type signingKeyRecord struct {
	KeyID         string    `gorm:"size:64;primaryKey"`
	Algorithm     string    `gorm:"size:16;not null"`
	Curve         string    `gorm:"size:16;not null"`
	PublicX       string    `gorm:"size:128;not null"`
	PublicY       string    `gorm:"size:128;not null"`
	PrivateKeyPEM string    `gorm:"type:text;not null"`
	Status        string    `gorm:"size:20;not null;index"`
	CreatedAt     time.Time `gorm:"not null"`
	ActivatesAt   time.Time `gorm:"not null"`
	RotatesAt     time.Time `gorm:"not null;index"`
	RetiresAt     time.Time `gorm:"not null;index"`
}

func (signingKeyRecord) TableName() string {
	return "auth_signing_keys"
}

var _ jwks.SigningKeyStore = (*SigningKeyRepository)(nil)

func NewSigningKeyRepository(db *gorm.DB) *SigningKeyRepository {
	return &SigningKeyRepository{db: db}
}

func (r *SigningKeyRepository) GetActive(
	ctx context.Context,
	now time.Time,
) (*auth.SigningKey, error) {
	var record signingKeyRecord
	if err := r.baseQuery(ctx).
		Where("status = ? AND activates_at <= ? AND retires_at > ?", auth.SigningKeyStatusActive, now, now).
		Order("created_at DESC").
		First(&record).
		Error; err != nil {
		return nil, translateSigningKeyError(err)
	}

	return toSigningKey(record), nil
}

func (r *SigningKeyRepository) Create(ctx context.Context, key *auth.SigningKey) error {
	return r.baseQuery(ctx).Create(toSigningKeyRecord(key)).Error
}

func (r *SigningKeyRepository) Retire(ctx context.Context, keyID string) error {
	return r.baseQuery(ctx).
		Model(&signingKeyRecord{}).
		Where("key_id = ?", keyID).
		Update("status", auth.SigningKeyStatusRetired).
		Error
}

func (r *SigningKeyRepository) ListPublicKeys(
	ctx context.Context,
	now time.Time,
) ([]auth.SigningKey, error) {
	var records []signingKeyRecord
	if err := r.baseQuery(ctx).
		Where("activates_at <= ? AND retires_at > ?", now, now).
		Order("created_at DESC").
		Find(&records).
		Error; err != nil {
		return nil, err
	}

	keys := make([]auth.SigningKey, 0, len(records))
	for _, record := range records {
		keys = append(keys, *toSigningKey(record))
	}

	return keys, nil
}

func (r *SigningKeyRepository) DeleteExpired(ctx context.Context, now time.Time) error {
	return r.baseQuery(ctx).
		Where("retires_at <= ?", now).
		Delete(&signingKeyRecord{}).
		Error
}

func (r *SigningKeyRepository) WithRotationLock(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	return r.baseQuery(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", signingKeyRotationLockID).Error; err != nil {
			return err
		}

		return fn(context.WithValue(ctx, signingKeyTxKey{}, tx))
	})
}

func (r *SigningKeyRepository) baseQuery(ctx context.Context) *gorm.DB {
	if tx, ok := ctx.Value(signingKeyTxKey{}).(*gorm.DB); ok {
		return tx.WithContext(ctx)
	}

	return r.db.WithContext(ctx)
}

type signingKeyTxKey struct{}

func toSigningKeyRecord(key *auth.SigningKey) *signingKeyRecord {
	return &signingKeyRecord{
		KeyID:         key.KeyID,
		Algorithm:     key.Algorithm,
		Curve:         key.Curve,
		PublicX:       key.PublicX,
		PublicY:       key.PublicY,
		PrivateKeyPEM: key.PrivateKeyPEM,
		Status:        key.Status,
		CreatedAt:     key.CreatedAt,
		ActivatesAt:   key.ActivatesAt,
		RotatesAt:     key.RotatesAt,
		RetiresAt:     key.RetiresAt,
	}
}

func toSigningKey(record signingKeyRecord) *auth.SigningKey {
	return &auth.SigningKey{
		KeyID:         record.KeyID,
		Algorithm:     record.Algorithm,
		Curve:         record.Curve,
		PublicX:       record.PublicX,
		PublicY:       record.PublicY,
		PrivateKeyPEM: record.PrivateKeyPEM,
		Status:        record.Status,
		CreatedAt:     record.CreatedAt,
		ActivatesAt:   record.ActivatesAt,
		RotatesAt:     record.RotatesAt,
		RetiresAt:     record.RetiresAt,
	}
}

func translateSigningKeyError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return auth.ErrSigningKeyNotFound
	}

	return err
}
