package account

import "time"

type AccountModel struct {
	ID              string                 `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	Username        *string                `gorm:"size:50;uniqueIndex"`
	PasswordHash    string                 `gorm:"size:255;not null"`
	PhoneNumber     string                 `gorm:"size:20;not null;uniqueIndex"`
	PhoneVerifiedAt time.Time              `gorm:"not null"`
	Providers       []AccountProviderModel `gorm:"foreignKey:AccountID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	CreatedAt       time.Time              `gorm:"not null"`
	UpdatedAt       time.Time              `gorm:"not null"`
}

type RegisterModel struct {
	Username     *string   `json:"username"`
	PasswordHash string    `json:"password_hash"`
	PhoneNumber  string    `json:"phone_number"`
	OTPCode      string    `json:"otp_code"`
	OTPExpiresAt time.Time `json:"otp_expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

type DeletedAccountModel struct {
	ID          string    `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	AccountID   string    `gorm:"type:uuid;not null;uniqueIndex"`
	Username    *string   `gorm:"size:50;index"`
	PhoneNumber string    `gorm:"size:20;not null;index"`
	DeletedAt   time.Time `gorm:"not null;index"`
}

type AccountProviderModel struct {
	ID             string       `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	AccountID      string       `gorm:"type:uuid;not null;index;uniqueIndex:idx_account_provider"`
	Provider       AuthProvider `gorm:"type:varchar(20);not null;uniqueIndex:idx_account_provider;uniqueIndex:idx_provider_user"`
	ProviderUserID string       `gorm:"size:191;not null;uniqueIndex:idx_provider_user"`
	LinkedAt       time.Time    `gorm:"not null"`
}

type AuthProvider string

const (
	AuthProviderGoogle   AuthProvider = "google"
	AuthProviderFacebook AuthProvider = "facebook"
)

func (AccountModel) TableName() string {
	return "accounts"
}

func (AccountProviderModel) TableName() string {
	return "account_providers"
}

func (DeletedAccountModel) TableName() string {
	return "deleted_accounts"
}
