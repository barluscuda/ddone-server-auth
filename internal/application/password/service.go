package password

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"ddone-server-auth/internal/application/otp"
	"ddone-server-auth/internal/domain/user"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	resetOTPLength    = 6
	passwordCooldown  = 7 * 24 * time.Hour
	resetTicketPrefix = "pwd_"
	resetTicketBytes  = 12
)

var ErrPhoneNumberRequired = errors.New("phone number is required")
var ErrInvalidPhoneNumber = user.ErrInvalidPhoneNumber
var ErrPasswordResetTicketRequired = errors.New("ticket id is required")
var ErrPasswordResetTicketNotFound = errors.New("password reset ticket not found")
var ErrOTPCodeRequired = errors.New("otp code is required")
var ErrNewPasswordRequired = errors.New("new password is required")
var ErrCurrentPasswordRequired = errors.New("current password is required")
var ErrPendingPasswordResetInvalid = errors.New("password reset ticket is invalid, request otp again")
var ErrResetRateLimited = errors.New("too many password reset requests, try again later")
var ErrResendRateLimited = errors.New("too many otp resend requests, request a new password reset")
var ErrResendCooldownActive = errors.New("otp resend cooldown is active")
var ErrVerifyRateLimited = errors.New("too many invalid otp attempts, request a new code")
var ErrAuthenticatedUserRequired = errors.New("authenticated user is required")
var ErrInvalidCurrentPassword = errors.New("current password is incorrect")
var ErrPasswordCooldownActive = errors.New("password can only be changed once every 7 days")

var defaultOTPPolicy = otp.Policy{
	TTL:                 5 * time.Minute,
	PhoneWindow:         5 * time.Minute,
	IPWindow:            5 * time.Minute,
	ResendCooldown:      60 * time.Second,
	VerifyAttemptWindow: 5 * time.Minute,
	MaxPhoneRequests:    1,
	MaxIPRequests:       20,
	MaxResends:          3,
	MaxVerifyAttempts:   5,
}

type Service struct {
	users           UserStore
	store           ResetStore
	sender          OTPSender
	tokenRecords    TokenRevoker
	loginSessions   LoginSessionRevoker
	otpPolicy       otp.Policy
	now             func() time.Time
	otpGenerator    func(int) (string, error)
	ticketGenerator func() (string, error)
	passwordHasher  func(string) (string, error)
}

func NewService(
	users UserStore,
	store ResetStore,
	sender OTPSender,
	tokenRecords TokenRevoker,
	loginSessions LoginSessionRevoker,
) *Service {
	return NewServiceWithSettings(users, store, sender, tokenRecords, loginSessions, Settings{})
}

func NewServiceWithSettings(
	users UserStore,
	store ResetStore,
	sender OTPSender,
	tokenRecords TokenRevoker,
	loginSessions LoginSessionRevoker,
	settings Settings,
) *Service {
	return &Service{
		users:           users,
		store:           store,
		sender:          sender,
		tokenRecords:    tokenRecords,
		loginSessions:   loginSessions,
		otpPolicy:       settings.OTPPolicy.WithDefaults(defaultOTPPolicy),
		now:             func() time.Time { return time.Now().UTC() },
		otpGenerator:    GenerateOTP,
		ticketGenerator: generateResetTicket,
		passwordHasher:  hashPassword,
	}
}

func (s *Service) ForgotPassword(
	ctx context.Context,
	input ForgotPasswordInput,
) (*ResetTicketResult, error) {
	phoneNumber, err := user.ParsePhoneNumber(input.PhoneNumber)
	if err != nil {
		return nil, err
	}
	globalPhoneNumber := phoneNumber.Global()
	if globalPhoneNumber == "" {
		return nil, ErrPhoneNumberRequired
	}
	if err := s.enforceResetRateLimits(ctx, globalPhoneNumber); err != nil {
		return nil, err
	}

	userModel, err := s.users.GetByPhoneNumber(ctx, globalPhoneNumber)
	if err != nil {
		return nil, err
	}
	if s.passwordCooldownActive(userModel, s.now()) {
		return nil, ErrPasswordCooldownActive
	}

	otpCode, err := s.otpGenerator(resetOTPLength)
	if err != nil {
		return nil, err
	}
	ticketID, err := s.ticketGenerator()
	if err != nil {
		return nil, err
	}

	now := s.now()
	state := &ResetTicketState{
		TicketID:      ticketID,
		UserID:        userModel.ID,
		PhoneNumber:   globalPhoneNumber,
		OTPCodeHash:   hashResetOTP(ticketID, otpCode),
		OTPExpiresAt:  now.Add(s.otpPolicy.TTL),
		ResendCount:   0,
		LastOTPSentAt: now,
		CreatedAt:     now,
	}
	if err := s.store.Save(ctx, state, s.otpPolicy.TTL); err != nil {
		return nil, err
	}

	message := ForgotPasswordOTPMessage(otpCode, s.otpPolicy.TTL)
	if err := s.sender.SendOTP(ctx, phoneNumber.TelCode, phoneNumber.Number, message); err != nil {
		_ = s.store.Delete(ctx, ticketID)
		return nil, err
	}

	return &ResetTicketResult{
		TicketID:             ticketID,
		ExpiresAt:            state.OTPExpiresAt,
		ResendCooldown:       s.otpPolicy.ResendCooldown,
		RemainingResendCount: s.otpPolicy.MaxResends,
	}, nil
}

func (s *Service) ResendForgotPasswordOTP(
	ctx context.Context,
	input ResendForgotPasswordInput,
) (*ResetTicketResult, error) {
	ticketID := strings.TrimSpace(input.TicketID)
	if ticketID == "" {
		return nil, ErrPasswordResetTicketRequired
	}

	state, err := s.store.Get(ctx, ticketID)
	if err != nil {
		return nil, err
	}

	now := s.now()
	if now.After(state.OTPExpiresAt) {
		_ = s.store.Delete(ctx, ticketID)
		_ = s.store.DeleteCounter(ctx, resetVerifyAttemptKey(ticketID))
		return nil, user.ErrOTPExpired
	}
	if state.UserID == "" || state.PhoneNumber == "" || state.OTPCodeHash == "" {
		_ = s.store.Delete(ctx, ticketID)
		_ = s.store.DeleteCounter(ctx, resetVerifyAttemptKey(ticketID))
		return nil, ErrPendingPasswordResetInvalid
	}
	if state.ResendCount >= s.otpPolicy.MaxResends {
		return nil, ErrResendRateLimited
	}

	lastOTPSentAt := state.LastOTPSentAt
	if lastOTPSentAt.IsZero() {
		lastOTPSentAt = state.CreatedAt
	}
	if !lastOTPSentAt.IsZero() && now.Sub(lastOTPSentAt) < s.otpPolicy.ResendCooldown {
		return nil, ErrResendCooldownActive
	}

	otpCode, err := s.otpGenerator(resetOTPLength)
	if err != nil {
		return nil, err
	}

	previousState := *state
	previousTTL := state.OTPExpiresAt.Sub(now)

	state.OTPCodeHash = hashResetOTP(ticketID, otpCode)
	state.OTPExpiresAt = now.Add(s.otpPolicy.TTL)
	state.ResendCount++
	state.LastOTPSentAt = now

	if err := s.store.Save(ctx, state, s.otpPolicy.TTL); err != nil {
		return nil, err
	}

	message := ForgotPasswordOTPMessage(otpCode, s.otpPolicy.TTL)
	phoneNumber, err := user.ParsePhoneNumber(state.PhoneNumber)
	if err != nil {
		return nil, err
	}
	if err := s.sender.SendOTP(ctx, phoneNumber.TelCode, phoneNumber.Number, message); err != nil {
		if restoreErr := s.store.Save(ctx, &previousState, previousTTL); restoreErr != nil {
			return nil, restoreErr
		}

		return nil, err
	}

	return &ResetTicketResult{
		TicketID:             ticketID,
		ExpiresAt:            state.OTPExpiresAt,
		ResendCooldown:       s.otpPolicy.ResendCooldown,
		RemainingResendCount: s.otpPolicy.MaxResends - state.ResendCount,
	}, nil
}

func (s *Service) VerifyForgotPassword(
	ctx context.Context,
	input VerifyForgotPasswordInput,
) error {
	ticketID := strings.TrimSpace(input.TicketID)
	otpCode := strings.TrimSpace(input.OTPCode)
	newPassword := strings.TrimSpace(input.NewPassword)

	if ticketID == "" {
		return ErrPasswordResetTicketRequired
	}
	if otpCode == "" {
		return ErrOTPCodeRequired
	}
	if newPassword == "" {
		return ErrNewPasswordRequired
	}

	state, err := s.store.Get(ctx, ticketID)
	if err != nil {
		return err
	}

	now := s.now()
	if now.After(state.OTPExpiresAt) {
		_ = s.store.Delete(ctx, ticketID)
		_ = s.store.DeleteCounter(ctx, resetVerifyAttemptKey(ticketID))
		return user.ErrOTPExpired
	}
	if state.UserID == "" || state.PhoneNumber == "" || state.OTPCodeHash == "" {
		_ = s.store.Delete(ctx, ticketID)
		_ = s.store.DeleteCounter(ctx, resetVerifyAttemptKey(ticketID))
		return ErrPendingPasswordResetInvalid
	}

	if !matchResetOTP(state.OTPCodeHash, ticketID, otpCode) {
		attempts, err := s.store.IncrementCounter(ctx, resetVerifyAttemptKey(ticketID), s.otpPolicy.VerifyAttemptWindow)
		if err != nil {
			return err
		}
		if attempts >= int64(s.otpPolicy.MaxVerifyAttempts) {
			_ = s.store.Delete(ctx, ticketID)
			_ = s.store.DeleteCounter(ctx, resetVerifyAttemptKey(ticketID))
			return ErrVerifyRateLimited
		}

		return user.ErrInvalidOTPCode
	}

	userModel, err := s.users.GetByID(ctx, state.UserID)
	if err != nil {
		return err
	}
	if s.passwordCooldownActive(userModel, now) {
		return ErrPasswordCooldownActive
	}

	passwordHash, err := s.passwordHasher(newPassword)
	if err != nil {
		return err
	}

	userModel.PasswordHash = passwordHash
	userModel.PasswordChangedAt = &now
	userModel.UpdatedAt = now
	if err := s.users.Update(ctx, userModel); err != nil {
		return err
	}
	if err := s.revokeSessions(ctx, userModel.ID, "password_reset", now); err != nil {
		return err
	}
	if err := s.store.Delete(ctx, ticketID); err != nil {
		return err
	}
	if err := s.store.DeleteCounter(ctx, resetVerifyAttemptKey(ticketID)); err != nil {
		return err
	}

	return nil
}

func (s *Service) ChangePassword(ctx context.Context, input ChangePasswordInput) error {
	userID := strings.TrimSpace(input.UserID)
	currentPassword := strings.TrimSpace(input.CurrentPassword)
	newPassword := strings.TrimSpace(input.NewPassword)

	if userID == "" {
		return ErrAuthenticatedUserRequired
	}
	if currentPassword == "" {
		return ErrCurrentPasswordRequired
	}
	if newPassword == "" {
		return ErrNewPasswordRequired
	}

	userModel, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	now := s.now()
	if s.passwordCooldownActive(userModel, now) {
		return ErrPasswordCooldownActive
	}
	if err := bcrypt.CompareHashAndPassword([]byte(userModel.PasswordHash), []byte(currentPassword)); err != nil {
		return ErrInvalidCurrentPassword
	}

	passwordHash, err := s.passwordHasher(newPassword)
	if err != nil {
		return err
	}

	userModel.PasswordHash = passwordHash
	userModel.PasswordChangedAt = &now
	userModel.UpdatedAt = now
	if err := s.users.Update(ctx, userModel); err != nil {
		return err
	}

	return s.revokeSessions(ctx, userModel.ID, "password_changed", now)
}

func (s *Service) revokeSessions(ctx context.Context, userID string, reason string, revokedAt time.Time) error {
	if err := s.tokenRecords.RevokeByUserID(ctx, userID, reason, revokedAt); err != nil {
		return err
	}
	if err := s.loginSessions.RevokeByUserID(ctx, userID, reason, revokedAt); err != nil {
		return err
	}

	return nil
}

func (s *Service) enforceResetRateLimits(ctx context.Context, phoneNumber string) error {
	count, err := s.store.IncrementCounter(ctx, resetPhoneRateKey(phoneNumber), s.otpPolicy.PhoneWindow)
	if err != nil {
		return err
	}
	if count > int64(s.otpPolicy.MaxPhoneRequests) {
		return ErrResetRateLimited
	}

	return nil
}

func (s *Service) passwordCooldownActive(userModel *user.User, now time.Time) bool {
	if userModel == nil || userModel.PasswordChangedAt == nil {
		return false
	}

	return now.Before(userModel.PasswordChangedAt.Add(passwordCooldown))
}

func generateResetTicket() (string, error) {
	randomBytes := make([]byte, resetTicketBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	return resetTicketPrefix + hex.EncodeToString(randomBytes), nil
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func hashResetOTP(ticketID string, otpCode string) string {
	sum := sha256.Sum256([]byte(ticketID + ":" + otpCode))
	return hex.EncodeToString(sum[:])
}

func matchResetOTP(expectedHash string, ticketID string, otpCode string) bool {
	actualHash := hashResetOTP(ticketID, otpCode)
	return subtle.ConstantTimeCompare([]byte(expectedHash), []byte(actualHash)) == 1
}

func resetPhoneRateKey(phoneNumber string) string {
	return fmt.Sprintf("password_reset:phone:%s", phoneNumber)
}

func resetVerifyAttemptKey(ticketID string) string {
	return fmt.Sprintf("password_reset:verify:%s", ticketID)
}
