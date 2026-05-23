package repository

import (
	"context"
	appaccountmanager "ddone-server-auth/internal/application/accountmanager"
	"ddone-server-auth/internal/application/login"
	"ddone-server-auth/internal/domain/auth"
	"errors"
	"time"

	"gorm.io/gorm"
)

type LoginSessionRepository struct {
	db *gorm.DB
}

type loginSessionRecord struct {
	ID                   string     `gorm:"type:uuid;primaryKey"`
	AccountID            string     `gorm:"type:uuid;not null;index"`
	TokenHash            string     `gorm:"size:64;not null;uniqueIndex"`
	UserAgent            string     `gorm:"type:text"`
	ClientIP             string     `gorm:"size:64"`
	CurrentAccessToken   string     `gorm:"type:text;not null"`
	CurrentAccessExpires time.Time  `gorm:"not null;index"`
	RevokedAt            *time.Time `gorm:"index"`
	RevokeReason         string     `gorm:"type:text"`
	CreatedAt            time.Time  `gorm:"not null"`
}

func (loginSessionRecord) TableName() string {
	return "auth_login_sessions"
}

var _ login.LoginSessionStore = (*LoginSessionRepository)(nil)
var _ appaccountmanager.SessionReader = (*LoginSessionRepository)(nil)

func NewLoginSessionRepository(db *gorm.DB) *LoginSessionRepository {
	return &LoginSessionRepository{db: db}
}

func (r *LoginSessionRepository) Create(ctx context.Context, session *auth.LoginSession) error {
	return r.baseQuery(ctx).Create(toLoginSessionRecord(session)).Error
}

func (r *LoginSessionRepository) GetByTokenHash(
	ctx context.Context,
	tokenHash string,
) (*auth.LoginSession, error) {
	var record loginSessionRecord

	if err := r.baseQuery(ctx).First(&record, "token_hash = ?", tokenHash).Error; err != nil {
		return nil, translateLoginSessionError(err)
	}

	return toLoginSession(record), nil
}

func (r *LoginSessionRepository) ListByAccountID(
	ctx context.Context,
	accountID string,
) ([]auth.LoginSession, error) {
	var records []loginSessionRecord

	if err := r.baseQuery(ctx).
		Where("account_id = ?", accountID).
		Order("created_at DESC").
		Find(&records).
		Error; err != nil {
		return nil, err
	}

	sessions := make([]auth.LoginSession, 0, len(records))
	for _, record := range records {
		sessions = append(sessions, *toLoginSession(record))
	}

	return sessions, nil
}

func (r *LoginSessionRepository) UpdateAccessToken(
	ctx context.Context,
	sessionID string,
	accessToken *auth.AccessToken,
) error {
	return r.baseQuery(ctx).
		Model(&loginSessionRecord{}).
		Where("id = ?", sessionID).
		Updates(map[string]any{
			"current_access_token":   accessToken.Token,
			"current_access_expires": accessToken.ExpiresAt,
		}).
		Error
}

func (r *LoginSessionRepository) baseQuery(ctx context.Context) *gorm.DB {
	return r.db.WithContext(ctx)
}

func toLoginSessionRecord(session *auth.LoginSession) *loginSessionRecord {
	return &loginSessionRecord{
		ID:                   session.ID,
		AccountID:            session.AccountID,
		TokenHash:            session.TokenHash,
		UserAgent:            session.UserAgent,
		ClientIP:             session.ClientIP,
		CurrentAccessToken:   session.CurrentAccessToken,
		CurrentAccessExpires: session.CurrentAccessExpires,
		RevokedAt:            session.RevokedAt,
		RevokeReason:         session.RevokeReason,
		CreatedAt:            session.CreatedAt,
	}
}

func toLoginSession(record loginSessionRecord) *auth.LoginSession {
	return &auth.LoginSession{
		ID:                   record.ID,
		AccountID:            record.AccountID,
		TokenHash:            record.TokenHash,
		UserAgent:            record.UserAgent,
		ClientIP:             record.ClientIP,
		CurrentAccessToken:   record.CurrentAccessToken,
		CurrentAccessExpires: record.CurrentAccessExpires,
		RevokedAt:            record.RevokedAt,
		RevokeReason:         record.RevokeReason,
		CreatedAt:            record.CreatedAt,
	}
}

func translateLoginSessionError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return auth.ErrLoginSessionNotFound
	}

	return err
}
