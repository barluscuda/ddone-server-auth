package repository

import (
	"context"
	"ddone-server-auth/internal/application/login"
	apppassword "ddone-server-auth/internal/application/password"
	"ddone-server-auth/internal/domain/auth"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type RefreshSessionRepository struct {
	db *gorm.DB
}

type refreshSessionRecord struct {
	ID              string    `gorm:"type:uuid;primaryKey"`
	AccountID       string    `gorm:"type:uuid;not null;index"`
	RootSessionID   string    `gorm:"type:uuid;not null;index"`
	ParentSessionID *string   `gorm:"type:uuid;index"`
	TokenHash       string    `gorm:"size:64;not null;uniqueIndex"`
	UserAgent       string    `gorm:"type:text"`
	ClientIP        string    `gorm:"size:64"`
	ExpiresAt       time.Time `gorm:"not null;index"`
	LastUsedAt      *time.Time
	ReplacedAt      *time.Time
	RevokedAt       *time.Time `gorm:"index"`
	RevokeReason    string     `gorm:"type:text"`
	CreatedAt       time.Time  `gorm:"not null"`
}

func (refreshSessionRecord) TableName() string {
	return "auth_refresh_sessions"
}

var _ login.RefreshSessionStore = (*RefreshSessionRepository)(nil)
var _ apppassword.RefreshSessionRevoker = (*RefreshSessionRepository)(nil)

func NewRefreshSessionRepository(db *gorm.DB) *RefreshSessionRepository {
	return &RefreshSessionRepository{db: db}
}

func (r *RefreshSessionRepository) Create(ctx context.Context, session *auth.RefreshSession) error {
	return r.baseQuery(ctx).Create(toRefreshSessionRecord(session)).Error
}

func (r *RefreshSessionRepository) GetByTokenHash(
	ctx context.Context,
	tokenHash string,
) (*auth.RefreshSession, error) {
	var record refreshSessionRecord

	if err := r.baseQuery(ctx).First(&record, "token_hash = ?", tokenHash).Error; err != nil {
		return nil, translateRefreshSessionError(err)
	}

	return toRefreshSession(record), nil
}

func (r *RefreshSessionRepository) Rotate(
	ctx context.Context,
	currentSessionID string,
	replacement *auth.RefreshSession,
	usedAt time.Time,
) error {
	return r.baseQuery(ctx).Transaction(func(tx *gorm.DB) error {
		var current refreshSessionRecord
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&current, "id = ?", currentSessionID).
			Error; err != nil {
			return translateRefreshSessionError(err)
		}

		if current.RevokedAt != nil {
			return auth.ErrRefreshSessionRevoked
		}
		if current.ReplacedAt != nil {
			return auth.ErrRefreshTokenReplayDetected
		}
		if !usedAt.Before(current.ExpiresAt) {
			return auth.ErrRefreshSessionExpired
		}

		current.LastUsedAt = &usedAt
		current.ReplacedAt = &usedAt
		if err := tx.Save(&current).Error; err != nil {
			return err
		}

		return tx.Create(toRefreshSessionRecord(replacement)).Error
	})
}

func (r *RefreshSessionRepository) RevokeLineage(
	ctx context.Context,
	rootSessionID string,
	reason string,
	revokedAt time.Time,
) error {
	return r.baseQuery(ctx).
		Model(&refreshSessionRecord{}).
		Where("root_session_id = ? AND revoked_at IS NULL", rootSessionID).
		Updates(map[string]any{
			"revoked_at":    revokedAt,
			"revoke_reason": reason,
		}).
		Error
}

func (r *RefreshSessionRepository) ListByAccountID(
	ctx context.Context,
	accountID string,
) ([]auth.RefreshSession, error) {
	var records []refreshSessionRecord

	if err := r.baseQuery(ctx).
		Where("account_id = ?", accountID).
		Order("created_at DESC").
		Find(&records).
		Error; err != nil {
		return nil, err
	}

	sessions := make([]auth.RefreshSession, 0, len(records))
	for _, record := range records {
		sessions = append(sessions, *toRefreshSession(record))
	}

	return sessions, nil
}

func (r *RefreshSessionRepository) RevokeByAccountID(
	ctx context.Context,
	accountID string,
	reason string,
	revokedAt time.Time,
) error {
	return r.baseQuery(ctx).
		Model(&refreshSessionRecord{}).
		Where("account_id = ? AND revoked_at IS NULL", accountID).
		Updates(map[string]any{
			"revoked_at":    revokedAt,
			"revoke_reason": reason,
		}).
		Error
}

func (r *RefreshSessionRepository) baseQuery(ctx context.Context) *gorm.DB {
	return r.db.WithContext(ctx)
}

func toRefreshSessionRecord(session *auth.RefreshSession) *refreshSessionRecord {
	return &refreshSessionRecord{
		ID:              session.ID,
		AccountID:       session.AccountID,
		RootSessionID:   session.RootSessionID,
		ParentSessionID: session.ParentSessionID,
		TokenHash:       session.TokenHash,
		UserAgent:       session.UserAgent,
		ClientIP:        session.ClientIP,
		ExpiresAt:       session.ExpiresAt,
		LastUsedAt:      session.LastUsedAt,
		ReplacedAt:      session.ReplacedAt,
		RevokedAt:       session.RevokedAt,
		RevokeReason:    session.RevokeReason,
		CreatedAt:       session.CreatedAt,
	}
}

func toRefreshSession(record refreshSessionRecord) *auth.RefreshSession {
	return &auth.RefreshSession{
		ID:              record.ID,
		AccountID:       record.AccountID,
		RootSessionID:   record.RootSessionID,
		ParentSessionID: record.ParentSessionID,
		TokenHash:       record.TokenHash,
		UserAgent:       record.UserAgent,
		ClientIP:        record.ClientIP,
		ExpiresAt:       record.ExpiresAt,
		LastUsedAt:      record.LastUsedAt,
		ReplacedAt:      record.ReplacedAt,
		RevokedAt:       record.RevokedAt,
		RevokeReason:    record.RevokeReason,
		CreatedAt:       record.CreatedAt,
	}
}

func translateRefreshSessionError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return auth.ErrRefreshSessionNotFound
	}

	return err
}
