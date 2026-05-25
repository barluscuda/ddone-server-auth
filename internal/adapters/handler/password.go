package handler

import (
	"ddone-server-auth/internal/adapters/dto"
	"ddone-server-auth/internal/adapters/middleware"
	apppassword "ddone-server-auth/internal/application/password"
	"ddone-server-auth/internal/domain/user"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	passwordResetOTPLength             = 6
	codePasswordResetOTPSent           = "password_reset_otp_sent"
	codePasswordResetOTPResent         = "password_reset_otp_resent"
	codePasswordResetVerified          = "password_reset_completed"
	codePasswordChanged                = "password_changed"
	codePasswordResetTicketRequired    = "password_reset_ticket_required"
	codePasswordResetTicketNotFound    = "password_reset_ticket_not_found"
	codeNewPasswordRequired            = "new_password_required"
	codeCurrentPasswordRequired        = "current_password_required"
	codeInvalidCurrentPassword         = "invalid_current_password"
	codePasswordResetPendingState      = "pending_password_reset_invalid"
	codePasswordResetRateLimited       = "password_reset_rate_limited"
	codePasswordResetResendRateLimited = "password_reset_resend_rate_limited"
	codePasswordResetResendCooldown    = "password_reset_resend_cooldown_active"
	codePasswordResetVerifyRateLimited = "password_reset_verify_rate_limited"
	codePasswordChangeCooldown         = "password_change_cooldown_active"
	messagePasswordResetOTPSent        = "password reset otp sent successfully"
	messagePasswordResetOTPResent      = "password reset otp resent successfully"
	messagePasswordResetVerified       = "password reset completed successfully"
	messagePasswordChanged             = "password changed successfully"
)

type PasswordHandler struct {
	password apppassword.UseCase
}

func NewPasswordHandler(password apppassword.UseCase) *PasswordHandler {
	return &PasswordHandler{password: password}
}

func (h *PasswordHandler) ForgotPassword(c *gin.Context) {
	var req dto.ReqForgotPassword
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, codeInvalidRequestBody, messageInvalidRequestBody)
		return
	}

	result, err := h.password.ForgotPassword(c.Request.Context(), apppassword.ForgotPasswordInput{
		PhoneNumber: req.PhoneNumber,
		ClientIP:    c.ClientIP(),
	})
	if err != nil {
		handlePasswordError(c, err)
		return
	}

	c.JSON(http.StatusAccepted, dto.ResPasswordReset{
		Success: true,
		Code:    codePasswordResetOTPSent,
		Message: messagePasswordResetOTPSent,
		Data: dto.ResPasswordResetTicketData{
			TicketID:              result.TicketID,
			ExpiresAt:             result.ExpiresAt,
			OTPLength:             passwordResetOTPLength,
			ResendCooldownSeconds: int(result.ResendCooldown / time.Second),
			RemainingResendCount:  result.RemainingResendCount,
		},
	})
}

func (h *PasswordHandler) ResendForgotPassword(c *gin.Context) {
	var req dto.ReqResendForgotPassword
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, codeInvalidRequestBody, messageInvalidRequestBody)
		return
	}

	result, err := h.password.ResendForgotPasswordOTP(c.Request.Context(), apppassword.ResendForgotPasswordInput{
		TicketID: req.TicketID,
		ClientIP: c.ClientIP(),
	})
	if err != nil {
		handlePasswordError(c, err)
		return
	}

	c.JSON(http.StatusAccepted, dto.ResPasswordReset{
		Success: true,
		Code:    codePasswordResetOTPResent,
		Message: messagePasswordResetOTPResent,
		Data: dto.ResPasswordResetTicketData{
			TicketID:              result.TicketID,
			ExpiresAt:             result.ExpiresAt,
			OTPLength:             passwordResetOTPLength,
			ResendCooldownSeconds: int(result.ResendCooldown / time.Second),
			RemainingResendCount:  result.RemainingResendCount,
		},
	})
}

func (h *PasswordHandler) VerifyForgotPassword(c *gin.Context) {
	var req dto.ReqVerifyForgotPassword
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, codeInvalidRequestBody, messageInvalidRequestBody)
		return
	}

	err := h.password.VerifyForgotPassword(c.Request.Context(), apppassword.VerifyForgotPasswordInput{
		TicketID:    req.TicketID,
		OTPCode:     req.OTPCode,
		NewPassword: req.NewPassword,
		ClientIP:    c.ClientIP(),
	})
	if err != nil {
		handlePasswordError(c, err)
		return
	}

	c.JSON(http.StatusOK, dto.ResMessage{
		Success: true,
		Code:    codePasswordResetVerified,
		Message: messagePasswordResetVerified,
	})
}

func (h *PasswordHandler) ChangePassword(c *gin.Context) {
	authContext, ok := middleware.CurrentAuth(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "authorization_required", "authorization header is required")
		return
	}

	var req dto.ReqChangePassword
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, codeInvalidRequestBody, messageInvalidRequestBody)
		return
	}

	err := h.password.ChangePassword(c.Request.Context(), apppassword.ChangePasswordInput{
		UserID:          authContext.UserID,
		CurrentPassword: req.CurrentPassword,
		NewPassword:     req.NewPassword,
	})
	if err != nil {
		handlePasswordError(c, err)
		return
	}

	c.JSON(http.StatusOK, dto.ResMessage{
		Success: true,
		Code:    codePasswordChanged,
		Message: messagePasswordChanged,
	})
}

func handlePasswordError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, apppassword.ErrPhoneNumberRequired),
		errors.Is(err, apppassword.ErrPasswordResetTicketRequired),
		errors.Is(err, apppassword.ErrOTPCodeRequired),
		errors.Is(err, apppassword.ErrNewPasswordRequired),
		errors.Is(err, apppassword.ErrCurrentPasswordRequired),
		errors.Is(err, apppassword.ErrPendingPasswordResetInvalid):
		respondError(c, http.StatusBadRequest, passwordErrorCode(err), passwordErrorMessage(err))
	case errors.Is(err, apppassword.ErrInvalidPhoneNumber),
		errors.Is(err, apppassword.ErrAuthenticatedUserRequired),
		errors.Is(err, apppassword.ErrInvalidCurrentPassword),
		errors.Is(err, user.ErrUnsupportedTelCode):
		respondError(c, http.StatusBadRequest, passwordErrorCode(err), passwordErrorMessage(err))
	case errors.Is(err, apppassword.ErrResetRateLimited),
		errors.Is(err, apppassword.ErrResendRateLimited),
		errors.Is(err, apppassword.ErrResendCooldownActive),
		errors.Is(err, apppassword.ErrVerifyRateLimited),
		errors.Is(err, apppassword.ErrPasswordCooldownActive):
		respondError(c, http.StatusTooManyRequests, passwordErrorCode(err), passwordErrorMessage(err))
	case errors.Is(err, apppassword.ErrPasswordResetTicketNotFound),
		errors.Is(err, user.ErrUserNotFound):
		respondError(c, http.StatusNotFound, passwordErrorCode(err), passwordErrorMessage(err))
	case errors.Is(err, user.ErrInvalidOTPCode),
		errors.Is(err, user.ErrOTPExpired):
		respondError(c, http.StatusBadRequest, passwordErrorCode(err), passwordErrorMessage(err))
	default:
		respondError(c, http.StatusInternalServerError, codeInternalServerError, "internal server error")
	}
}

func passwordErrorCode(err error) string {
	switch {
	case errors.Is(err, apppassword.ErrPhoneNumberRequired):
		return codePhoneNumberRequired
	case errors.Is(err, apppassword.ErrInvalidPhoneNumber):
		return codeInvalidPhoneNumber
	case errors.Is(err, user.ErrUnsupportedTelCode):
		return codeUnsupportedTelCode
	case errors.Is(err, apppassword.ErrPasswordResetTicketRequired):
		return codePasswordResetTicketRequired
	case errors.Is(err, apppassword.ErrPasswordResetTicketNotFound):
		return codePasswordResetTicketNotFound
	case errors.Is(err, apppassword.ErrOTPCodeRequired):
		return codeOTPCodeRequired
	case errors.Is(err, apppassword.ErrNewPasswordRequired):
		return codeNewPasswordRequired
	case errors.Is(err, apppassword.ErrCurrentPasswordRequired):
		return codeCurrentPasswordRequired
	case errors.Is(err, apppassword.ErrInvalidCurrentPassword):
		return codeInvalidCurrentPassword
	case errors.Is(err, apppassword.ErrPendingPasswordResetInvalid):
		return codePasswordResetPendingState
	case errors.Is(err, apppassword.ErrResetRateLimited):
		return codePasswordResetRateLimited
	case errors.Is(err, apppassword.ErrResendRateLimited):
		return codePasswordResetResendRateLimited
	case errors.Is(err, apppassword.ErrResendCooldownActive):
		return codePasswordResetResendCooldown
	case errors.Is(err, apppassword.ErrVerifyRateLimited):
		return codePasswordResetVerifyRateLimited
	case errors.Is(err, apppassword.ErrPasswordCooldownActive):
		return codePasswordChangeCooldown
	case errors.Is(err, apppassword.ErrAuthenticatedUserRequired):
		return "authorization_required"
	case errors.Is(err, user.ErrUserNotFound):
		return "user_not_found"
	case errors.Is(err, user.ErrInvalidOTPCode):
		return codeInvalidOTPCode
	case errors.Is(err, user.ErrOTPExpired):
		return codeOTPExpired
	default:
		return codeInternalServerError
	}
}

func passwordErrorMessage(err error) string {
	switch {
	case errors.Is(err, apppassword.ErrPhoneNumberRequired):
		return "phone number is required"
	case errors.Is(err, apppassword.ErrInvalidPhoneNumber):
		return "phone number format is invalid"
	case errors.Is(err, user.ErrUnsupportedTelCode):
		return "phone tel code is unsupported"
	case errors.Is(err, apppassword.ErrPasswordResetTicketRequired):
		return "ticket id is required"
	case errors.Is(err, apppassword.ErrPasswordResetTicketNotFound):
		return "password reset ticket not found"
	case errors.Is(err, apppassword.ErrOTPCodeRequired):
		return "otp code is required"
	case errors.Is(err, apppassword.ErrNewPasswordRequired):
		return "new password is required"
	case errors.Is(err, apppassword.ErrCurrentPasswordRequired):
		return "current password is required"
	case errors.Is(err, apppassword.ErrInvalidCurrentPassword):
		return "current password is incorrect"
	case errors.Is(err, apppassword.ErrPendingPasswordResetInvalid):
		return "password reset ticket is invalid, please request a new otp"
	case errors.Is(err, apppassword.ErrResetRateLimited):
		return "too many password reset requests, please try again later"
	case errors.Is(err, apppassword.ErrResendRateLimited):
		return "resend limit reached, please start a new password reset"
	case errors.Is(err, apppassword.ErrResendCooldownActive):
		return "please wait before requesting another otp"
	case errors.Is(err, apppassword.ErrVerifyRateLimited):
		return "too many invalid otp attempts, please request a new code"
	case errors.Is(err, apppassword.ErrPasswordCooldownActive):
		return "password can only be changed once every 7 days"
	case errors.Is(err, apppassword.ErrAuthenticatedUserRequired):
		return "authorization header is required"
	case errors.Is(err, user.ErrUserNotFound):
		return "user not found"
	case errors.Is(err, user.ErrInvalidOTPCode):
		return "invalid otp code"
	case errors.Is(err, user.ErrOTPExpired):
		return "otp code has expired"
	default:
		return "internal server error"
	}
}
