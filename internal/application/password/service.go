package password

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"ddone-server-auth/internal/domain/account"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	resetOTPLength           = 6
	resetOTPTTL              = 5 * time.Minute
	resetPhoneWindow         = 5 * time.Minute
	resetResendCooldown      = 60 * time.Second
	resetVerifyAttemptWindow = resetOTPTTL
	maxResetPhoneRequests    = 1
	maxResetResends          = 3
	maxResetVerifyAttempts   = 5
	resetTicketPrefix        = "pwd_"
	resetTicketBytes         = 12
)

var ErrPhoneNumberRequired = errors.New("phone number is required")
var ErrInvalidPhoneNumber = account.ErrInvalidPhoneNumber
var ErrPasswordResetTicketRequired = errors.New("ticket id is required")
var ErrPasswordResetTicketNotFound = errors.New("password reset ticket not found")
var ErrOTPCodeRequired = errors.New("otp code is required")
var ErrNewPasswordRequired = errors.New("new password is required")
var ErrCurrentPasswordRequired = errors.New("current password is required")
var ErrPendingPasswordResetInvalid = errors.New("password reset ticket is invalid, request otp again")
var ErrResetRateLimited = errors.New("too many password reset requests, try again later")
var ErrResendRateLimited = errors.New("too many otp resend requests, request a new password reset")
var ErrResendCooldownActive = errors.New("please wait 60 seconds before requesting another otp")
var ErrVerifyRateLimited = errors.New("too many invalid otp attempts, request a new code")
var ErrAuthenticatedAccountRequired = errors.New("authenticated account is required")
var ErrInvalidCurrentPassword = errors.New("current password is incorrect")

type Service struct {
	accounts        AccountStore
	store           ResetStore
	sender          OTPSender
	refreshSessions RefreshSessionRevoker
	loginSessions   LoginSessionRevoker
	now             func() time.Time
	otpGenerator    func(int) (string, error)
	ticketGenerator func() (string, error)
	passwordHasher  func(string) (string, error)
}

func NewService(
	accounts AccountStore,
	store ResetStore,
	sender OTPSender,
	refreshSessions RefreshSessionRevoker,
	loginSessions LoginSessionRevoker,
) *Service {
	return &Service{
		accounts:        accounts,
		store:           store,
		sender:          sender,
		refreshSessions: refreshSessions,
		loginSessions:   loginSessions,
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
	phoneNumber, err := account.NormalizePhoneNumber(input.PhoneNumber)
	if err != nil {
		return nil, err
	}
	if phoneNumber == "" {
		return nil, ErrPhoneNumberRequired
	}
	if err := s.enforceResetRateLimits(ctx, phoneNumber); err != nil {
		return nil, err
	}

	accountModel, err := s.accounts.GetByPhoneNumber(ctx, phoneNumber)
	if err != nil {
		return nil, err
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
		AccountID:     accountModel.ID,
		PhoneNumber:   phoneNumber,
		OTPCodeHash:   hashResetOTP(ticketID, otpCode),
		OTPExpiresAt:  now.Add(resetOTPTTL),
		ResendCount:   0,
		LastOTPSentAt: now,
		CreatedAt:     now,
	}
	if err := s.store.Save(ctx, state, resetOTPTTL); err != nil {
		return nil, err
	}

	message := ForgotPasswordOTPMessage(otpCode, resetOTPTTL)
	if err := s.sender.SendOTP(ctx, phoneNumber, message); err != nil {
		_ = s.store.Delete(ctx, ticketID)
		return nil, err
	}

	return &ResetTicketResult{
		TicketID:             ticketID,
		ExpiresAt:            state.OTPExpiresAt,
		RemainingResendCount: maxResetResends,
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
		return nil, account.ErrOTPExpired
	}
	if state.AccountID == "" || state.PhoneNumber == "" || state.OTPCodeHash == "" {
		_ = s.store.Delete(ctx, ticketID)
		_ = s.store.DeleteCounter(ctx, resetVerifyAttemptKey(ticketID))
		return nil, ErrPendingPasswordResetInvalid
	}
	if state.ResendCount >= maxResetResends {
		return nil, ErrResendRateLimited
	}

	lastOTPSentAt := state.LastOTPSentAt
	if lastOTPSentAt.IsZero() {
		lastOTPSentAt = state.CreatedAt
	}
	if !lastOTPSentAt.IsZero() && now.Sub(lastOTPSentAt) < resetResendCooldown {
		return nil, ErrResendCooldownActive
	}

	otpCode, err := s.otpGenerator(resetOTPLength)
	if err != nil {
		return nil, err
	}

	previousState := *state
	previousTTL := state.OTPExpiresAt.Sub(now)

	state.OTPCodeHash = hashResetOTP(ticketID, otpCode)
	state.OTPExpiresAt = now.Add(resetOTPTTL)
	state.ResendCount++
	state.LastOTPSentAt = now

	if err := s.store.Save(ctx, state, resetOTPTTL); err != nil {
		return nil, err
	}

	message := ForgotPasswordOTPMessage(otpCode, resetOTPTTL)
	if err := s.sender.SendOTP(ctx, state.PhoneNumber, message); err != nil {
		if restoreErr := s.store.Save(ctx, &previousState, previousTTL); restoreErr != nil {
			return nil, restoreErr
		}

		return nil, err
	}

	return &ResetTicketResult{
		TicketID:             ticketID,
		ExpiresAt:            state.OTPExpiresAt,
		RemainingResendCount: maxResetResends - state.ResendCount,
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
		return account.ErrOTPExpired
	}
	if state.AccountID == "" || state.PhoneNumber == "" || state.OTPCodeHash == "" {
		_ = s.store.Delete(ctx, ticketID)
		_ = s.store.DeleteCounter(ctx, resetVerifyAttemptKey(ticketID))
		return ErrPendingPasswordResetInvalid
	}

	if !matchResetOTP(state.OTPCodeHash, ticketID, otpCode) {
		attempts, err := s.store.IncrementCounter(ctx, resetVerifyAttemptKey(ticketID), resetVerifyAttemptWindow)
		if err != nil {
			return err
		}
		if attempts >= maxResetVerifyAttempts {
			_ = s.store.Delete(ctx, ticketID)
			_ = s.store.DeleteCounter(ctx, resetVerifyAttemptKey(ticketID))
			return ErrVerifyRateLimited
		}

		return account.ErrInvalidOTPCode
	}

	accountModel, err := s.accounts.GetByID(ctx, state.AccountID)
	if err != nil {
		return err
	}

	passwordHash, err := s.passwordHasher(newPassword)
	if err != nil {
		return err
	}

	accountModel.PasswordHash = passwordHash
	accountModel.PasswordChangedAt = &now
	accountModel.UpdatedAt = now
	if err := s.accounts.Update(ctx, accountModel); err != nil {
		return err
	}
	if err := s.revokeSessions(ctx, accountModel.ID, "password_reset", now); err != nil {
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
	accountID := strings.TrimSpace(input.AccountID)
	currentPassword := strings.TrimSpace(input.CurrentPassword)
	newPassword := strings.TrimSpace(input.NewPassword)

	if accountID == "" {
		return ErrAuthenticatedAccountRequired
	}
	if currentPassword == "" {
		return ErrCurrentPasswordRequired
	}
	if newPassword == "" {
		return ErrNewPasswordRequired
	}

	accountModel, err := s.accounts.GetByID(ctx, accountID)
	if err != nil {
		return err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(accountModel.PasswordHash), []byte(currentPassword)); err != nil {
		return ErrInvalidCurrentPassword
	}

	passwordHash, err := s.passwordHasher(newPassword)
	if err != nil {
		return err
	}

	now := s.now()
	accountModel.PasswordHash = passwordHash
	accountModel.PasswordChangedAt = &now
	accountModel.UpdatedAt = now
	if err := s.accounts.Update(ctx, accountModel); err != nil {
		return err
	}

	return s.revokeSessions(ctx, accountModel.ID, "password_changed", now)
}

func (s *Service) revokeSessions(ctx context.Context, accountID string, reason string, revokedAt time.Time) error {
	if err := s.refreshSessions.RevokeByAccountID(ctx, accountID, reason, revokedAt); err != nil {
		return err
	}
	if err := s.loginSessions.RevokeByAccountID(ctx, accountID, reason, revokedAt); err != nil {
		return err
	}

	return nil
}

func (s *Service) enforceResetRateLimits(ctx context.Context, phoneNumber string) error {
	count, err := s.store.IncrementCounter(ctx, resetPhoneRateKey(phoneNumber), resetPhoneWindow)
	if err != nil {
		return err
	}
	if count > maxResetPhoneRequests {
		return ErrResetRateLimited
	}

	return nil
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
