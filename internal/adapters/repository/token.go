package repository

import (
	"context"
	"ddone-server-auth/internal/application/login"
	apppassword "ddone-server-auth/internal/application/password"
	apptokenmanager "ddone-server-auth/internal/application/tokenmanager"
	"ddone-server-auth/internal/domain/auth"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type TokenRepository struct {
	db *gorm.DB
}

type tokenRow struct {
	ID            string    `gorm:"type:uuid;primaryKey"`
	AccountID     string    `gorm:"type:uuid;not null;index"`
	RootTokenID   string    `gorm:"column:root_session_id;type:uuid;not null;index"`
	ParentTokenID *string   `gorm:"column:parent_session_id;type:uuid;index"`
	TokenHash     string    `gorm:"size:64;not null;uniqueIndex"`
	UserAgent     string    `gorm:"type:text"`
	ClientIP      string    `gorm:"size:64"`
	ExpiresAt     time.Time `gorm:"not null;index"`
	LastUsedAt    *time.Time
	ReplacedAt    *time.Time
	RevokedAt     *time.Time `gorm:"index"`
	RevokeReason  string     `gorm:"type:text"`
	CreatedAt     time.Time  `gorm:"not null"`
}

// Keep the legacy table name so existing token history stays intact.
func (tokenRow) TableName() string {
	return "auth_refresh_sessions"
}

var _ login.TokenStore = (*TokenRepository)(nil)
var _ apppassword.TokenRevoker = (*TokenRepository)(nil)
var _ apptokenmanager.Store = (*TokenRepository)(nil)

func NewTokenRepository(db *gorm.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

func (r *TokenRepository) Create(ctx context.Context, tokenRecord *auth.TokenRecord) error {
	return r.baseQuery(ctx).Create(toTokenRow(tokenRecord)).Error
}

func (r *TokenRepository) GetByTokenHash(
	ctx context.Context,
	tokenHash string,
) (*auth.TokenRecord, error) {
	var record tokenRow

	if err := r.baseQuery(ctx).First(&record, "token_hash = ?", tokenHash).Error; err != nil {
		return nil, translateTokenError(err)
	}

	return toTokenRecord(record), nil
}

func (r *TokenRepository) GetByID(ctx context.Context, tokenID string) (*auth.TokenRecord, error) {
	var record tokenRow

	if err := r.baseQuery(ctx).First(&record, "id = ?", tokenID).Error; err != nil {
		return nil, translateTokenError(err)
	}

	return toTokenRecord(record), nil
}

func (r *TokenRepository) Rotate(
	ctx context.Context,
	currentTokenID string,
	replacement *auth.TokenRecord,
	usedAt time.Time,
) error {
	return r.baseQuery(ctx).Transaction(func(tx *gorm.DB) error {
		var current tokenRow
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&current, "id = ?", currentTokenID).
			Error; err != nil {
			return translateTokenError(err)
		}

		if current.RevokedAt != nil {
			return auth.ErrTokenRevoked
		}
		if current.ReplacedAt != nil {
			return auth.ErrRefreshTokenReplayDetected
		}
		if !usedAt.Before(current.ExpiresAt) {
			return auth.ErrTokenExpired
		}

		current.LastUsedAt = &usedAt
		current.ReplacedAt = &usedAt
		if err := tx.Save(&current).Error; err != nil {
			return err
		}

		return tx.Create(toTokenRow(replacement)).Error
	})
}

func (r *TokenRepository) RevokeLineage(
	ctx context.Context,
	rootTokenID string,
	reason string,
	revokedAt time.Time,
) error {
	return r.baseQuery(ctx).
		Model(&tokenRow{}).
		Where("root_session_id = ? AND revoked_at IS NULL", rootTokenID).
		Updates(map[string]any{
			"revoked_at":    revokedAt,
			"revoke_reason": reason,
		}).
		Error
}

func (r *TokenRepository) ListByAccountID(
	ctx context.Context,
	accountID string,
) ([]auth.TokenRecord, error) {
	var records []tokenRow

	if err := r.baseQuery(ctx).
		Where("account_id = ?", accountID).
		Order("created_at DESC").
		Find(&records).
		Error; err != nil {
		return nil, err
	}

	tokens := make([]auth.TokenRecord, 0, len(records))
	for _, record := range records {
		tokens = append(tokens, *toTokenRecord(record))
	}

	return tokens, nil
}

func (r *TokenRepository) RevokeByAccountID(
	ctx context.Context,
	accountID string,
	reason string,
	revokedAt time.Time,
) error {
	return r.baseQuery(ctx).
		Model(&tokenRow{}).
		Where("account_id = ? AND revoked_at IS NULL", accountID).
		Updates(map[string]any{
			"revoked_at":    revokedAt,
			"revoke_reason": reason,
		}).
		Error
}

func (r *TokenRepository) RevokeByID(
	ctx context.Context,
	tokenID string,
	reason string,
	revokedAt time.Time,
) error {
	result := r.baseQuery(ctx).
		Model(&tokenRow{}).
		Where("id = ? AND revoked_at IS NULL", tokenID).
		Updates(map[string]any{
			"revoked_at":    revokedAt,
			"revoke_reason": reason,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return auth.ErrTokenNotFound
	}

	return nil
}

func (r *TokenRepository) baseQuery(ctx context.Context) *gorm.DB {
	return r.db.WithContext(ctx)
}

func toTokenRow(tokenRecord *auth.TokenRecord) *tokenRow {
	return &tokenRow{
		ID:            tokenRecord.ID,
		AccountID:     tokenRecord.AccountID,
		RootTokenID:   tokenRecord.RootTokenID,
		ParentTokenID: tokenRecord.ParentTokenID,
		TokenHash:     tokenRecord.TokenHash,
		UserAgent:     tokenRecord.UserAgent,
		ClientIP:      tokenRecord.ClientIP,
		ExpiresAt:     tokenRecord.ExpiresAt,
		LastUsedAt:    tokenRecord.LastUsedAt,
		ReplacedAt:    tokenRecord.ReplacedAt,
		RevokedAt:     tokenRecord.RevokedAt,
		RevokeReason:  tokenRecord.RevokeReason,
		CreatedAt:     tokenRecord.CreatedAt,
	}
}

func toTokenRecord(record tokenRow) *auth.TokenRecord {
	return &auth.TokenRecord{
		ID:            record.ID,
		AccountID:     record.AccountID,
		RootTokenID:   record.RootTokenID,
		ParentTokenID: record.ParentTokenID,
		TokenHash:     record.TokenHash,
		UserAgent:     record.UserAgent,
		ClientIP:      record.ClientIP,
		ExpiresAt:     record.ExpiresAt,
		LastUsedAt:    record.LastUsedAt,
		ReplacedAt:    record.ReplacedAt,
		RevokedAt:     record.RevokedAt,
		RevokeReason:  record.RevokeReason,
		CreatedAt:     record.CreatedAt,
	}
}

func translateTokenError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return auth.ErrTokenNotFound
	}

	return err
}
