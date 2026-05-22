package handler

import (
	"ddone-server-auth/internal/adapters/dto"
	"ddone-server-auth/internal/domain/account"
	"ddone-server-auth/internal/services"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	registerOTPLength               = 6
	resendCooldownSeconds           = 60
	codeInvalidRequestBody          = "invalid_request_body"
	codeRegisterOTPSent             = "register_otp_sent"
	codeRegisterOTPResent           = "register_otp_resent"
	codeRegisterVerified            = "register_verified"
	codePhoneNumberRequired         = "phone_number_required"
	codeInvalidPhoneNumber          = "invalid_phone_number"
	codeRegisterTicketRequired      = "ticket_id_required"
	codeOTPCodeRequired             = "otp_code_required"
	codePasswordRequired            = "password_required"
	codePendingRegistrationState    = "pending_registration_invalid"
	codeRegisterRateLimited         = "register_rate_limited"
	codeResendRateLimited           = "resend_rate_limited"
	codeResendCooldownActive        = "resend_cooldown_active"
	codeVerifyRateLimited           = "verify_rate_limited"
	codePhoneAlreadyRegistered      = "phone_number_already_registered"
	codeUsernameAlreadyRegistered   = "username_already_registered"
	codePendingRegistrationNotFound = "pending_registration_not_found"
	codeInvalidOTPCode              = "invalid_otp_code"
	codeOTPExpired                  = "otp_expired"
	codeInternalServerError         = "internal_server_error"
	messageInvalidRequestBody       = "invalid request body"
	messageRegisterOTPSent          = "otp sent successfully"
	messageRegisterOTPResent        = "otp resent successfully"
	messageRegisterVerified         = "registration completed successfully"
)

type RegisterHandler struct {
	register *services.RegisterService
}

func NewRegisterHandler(register *services.RegisterService) *RegisterHandler {
	return &RegisterHandler{register: register}
}

func (h *RegisterHandler) Register(c *gin.Context) {
	var req dto.ReqRegister
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, codeInvalidRequestBody, messageInvalidRequestBody)
		return
	}

	result, err := h.register.Register(c.Request.Context(), services.RegisterInput{
		PhoneNumber: req.PhoneNumber,
		Password:    req.Password,
		ClientID:    c.ClientIP(),
	})
	if err != nil {
		handleRegisterError(c, err)
		return
	}

	c.JSON(http.StatusAccepted, dto.ResRegister{
		Success: true,
		Code:    codeRegisterOTPSent,
		Message: messageRegisterOTPSent,
		Data: dto.ResRegisterTicketData{
			TicketID:              result.TicketID,
			ExpiresAt:             result.ExpiresAt,
			OTPLength:             registerOTPLength,
			ResendCooldownSeconds: resendCooldownSeconds,
			RemainingResendCount:  result.RemainingResendCount,
		},
	})
}

func (h *RegisterHandler) VerifyRegister(c *gin.Context) {
	var req dto.ReqVerifyRegister
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, codeInvalidRequestBody, messageInvalidRequestBody)
		return
	}

	accountModel, err := h.register.VerifyRegister(c.Request.Context(), services.VerifyRegisterInput{
		TicketID: req.TicketID,
		OTPCode:  req.OTPCode,
		ClientID: c.ClientIP(),
	})
	if err != nil {
		handleRegisterError(c, err)
		return
	}

	c.JSON(http.StatusCreated, dto.ResRegisteredAccount{
		Success: true,
		Code:    codeRegisterVerified,
		Message: messageRegisterVerified,
		Data: dto.ResRegisteredAccountData{
			ID:              accountModel.ID,
			Username:        accountModel.Username,
			PhoneNumber:     accountModel.PhoneNumber,
			PhoneVerifiedAt: accountModel.PhoneVerifiedAt,
			CreatedAt:       accountModel.CreatedAt,
		},
	})
}

func (h *RegisterHandler) ResendOTP(c *gin.Context) {
	var req dto.ReqResendRegisterOTP
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, codeInvalidRequestBody, messageInvalidRequestBody)
		return
	}

	result, err := h.register.ResendRegisterOTP(c.Request.Context(), services.ResendRegisterOTPInput{
		TicketID: req.TicketID,
		ClientID: c.ClientIP(),
	})
	if err != nil {
		handleRegisterError(c, err)
		return
	}

	c.JSON(http.StatusAccepted, dto.ResRegister{
		Success: true,
		Code:    codeRegisterOTPResent,
		Message: messageRegisterOTPResent,
		Data: dto.ResRegisterTicketData{
			TicketID:              result.TicketID,
			ExpiresAt:             result.ExpiresAt,
			OTPLength:             registerOTPLength,
			ResendCooldownSeconds: resendCooldownSeconds,
			RemainingResendCount:  result.RemainingResendCount,
		},
	})
}

func handleRegisterError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, services.ErrPhoneNumberRequired),
		errors.Is(err, services.ErrRegisterTicketRequired),
		errors.Is(err, services.ErrPasswordRequired),
		errors.Is(err, services.ErrPendingRegistrationInvalid):
		respondError(c, http.StatusBadRequest, registerErrorCode(err), registerErrorMessage(err))
	case errors.Is(err, services.ErrInvalidPhoneNumber),
		errors.Is(err, services.ErrOTPCodeRequired):
		respondError(c, http.StatusBadRequest, registerErrorCode(err), registerErrorMessage(err))
	case errors.Is(err, services.ErrRegisterRateLimited),
		errors.Is(err, services.ErrResendRateLimited),
		errors.Is(err, services.ErrResendCooldownActive),
		errors.Is(err, services.ErrVerifyRateLimited):
		respondError(c, http.StatusTooManyRequests, registerErrorCode(err), registerErrorMessage(err))
	case errors.Is(err, account.ErrPhoneNumberAlreadyRegistered),
		errors.Is(err, account.ErrUsernameAlreadyRegistered):
		respondError(c, http.StatusConflict, registerErrorCode(err), registerErrorMessage(err))
	case errors.Is(err, account.ErrPendingRegistrationNotFound),
		errors.Is(err, account.ErrInvalidOTPCode),
		errors.Is(err, account.ErrOTPExpired):
		respondError(c, http.StatusBadRequest, registerErrorCode(err), registerErrorMessage(err))
	default:
		respondError(c, http.StatusInternalServerError, codeInternalServerError, registerErrorMessage(err))
	}
}

func respondError(c *gin.Context, statusCode int, code string, message string) {
	c.JSON(statusCode, dto.ResMessage{
		Success: false,
		Code:    code,
		Message: message,
	})
}

func registerErrorCode(err error) string {
	switch {
	case errors.Is(err, services.ErrPhoneNumberRequired):
		return codePhoneNumberRequired
	case errors.Is(err, services.ErrInvalidPhoneNumber):
		return codeInvalidPhoneNumber
	case errors.Is(err, services.ErrRegisterTicketRequired):
		return codeRegisterTicketRequired
	case errors.Is(err, services.ErrOTPCodeRequired):
		return codeOTPCodeRequired
	case errors.Is(err, services.ErrPasswordRequired):
		return codePasswordRequired
	case errors.Is(err, services.ErrPendingRegistrationInvalid):
		return codePendingRegistrationState
	case errors.Is(err, services.ErrRegisterRateLimited):
		return codeRegisterRateLimited
	case errors.Is(err, services.ErrResendRateLimited):
		return codeResendRateLimited
	case errors.Is(err, services.ErrResendCooldownActive):
		return codeResendCooldownActive
	case errors.Is(err, services.ErrVerifyRateLimited):
		return codeVerifyRateLimited
	case errors.Is(err, account.ErrPhoneNumberAlreadyRegistered):
		return codePhoneAlreadyRegistered
	case errors.Is(err, account.ErrUsernameAlreadyRegistered):
		return codeUsernameAlreadyRegistered
	case errors.Is(err, account.ErrPendingRegistrationNotFound):
		return codePendingRegistrationNotFound
	case errors.Is(err, account.ErrInvalidOTPCode):
		return codeInvalidOTPCode
	case errors.Is(err, account.ErrOTPExpired):
		return codeOTPExpired
	default:
		return codeInternalServerError
	}
}

func registerErrorMessage(err error) string {
	switch {
	case errors.Is(err, services.ErrPhoneNumberRequired):
		return "phone number is required"
	case errors.Is(err, services.ErrInvalidPhoneNumber):
		return "phone number format is invalid"
	case errors.Is(err, services.ErrRegisterTicketRequired):
		return "ticket id is required"
	case errors.Is(err, services.ErrOTPCodeRequired):
		return "otp code is required"
	case errors.Is(err, services.ErrPasswordRequired):
		return "password is required"
	case errors.Is(err, services.ErrPendingRegistrationInvalid):
		return "pending registration is invalid, please request a new otp"
	case errors.Is(err, services.ErrRegisterRateLimited):
		return "too many registration requests, please try again later"
	case errors.Is(err, services.ErrResendRateLimited):
		return "resend limit reached, please start a new registration"
	case errors.Is(err, services.ErrResendCooldownActive):
		return "please wait before requesting another otp"
	case errors.Is(err, services.ErrVerifyRateLimited):
		return "too many invalid otp attempts, please request a new code"
	case errors.Is(err, account.ErrPhoneNumberAlreadyRegistered):
		return "phone number is already registered"
	case errors.Is(err, account.ErrUsernameAlreadyRegistered):
		return "username is already registered"
	case errors.Is(err, account.ErrPendingRegistrationNotFound):
		return "registration session not found"
	case errors.Is(err, account.ErrInvalidOTPCode):
		return "invalid otp code"
	case errors.Is(err, account.ErrOTPExpired):
		return "otp code has expired"
	default:
		return "internal server error"
	}
}
