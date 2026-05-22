package handler

import (
	"ddone-server-auth/internal/adapters/dto"
	appregister "ddone-server-auth/internal/application/register"
	"ddone-server-auth/internal/domain/account"
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
	register appregister.UseCase
}

func NewRegisterHandler(register appregister.UseCase) *RegisterHandler {
	return &RegisterHandler{register: register}
}

func (h *RegisterHandler) Register(c *gin.Context) {
	var req dto.ReqRegister
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, codeInvalidRequestBody, messageInvalidRequestBody)
		return
	}

	result, err := h.register.Register(c.Request.Context(), appregister.RegisterInput{
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

	accountModel, err := h.register.VerifyRegister(c.Request.Context(), appregister.VerifyRegisterInput{
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

	result, err := h.register.ResendRegisterOTP(c.Request.Context(), appregister.ResendRegisterOTPInput{
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
	case errors.Is(err, appregister.ErrPhoneNumberRequired),
		errors.Is(err, appregister.ErrRegisterTicketRequired),
		errors.Is(err, appregister.ErrPasswordRequired),
		errors.Is(err, appregister.ErrPendingRegistrationInvalid):
		respondError(c, http.StatusBadRequest, registerErrorCode(err), registerErrorMessage(err))
	case errors.Is(err, appregister.ErrInvalidPhoneNumber),
		errors.Is(err, appregister.ErrOTPCodeRequired):
		respondError(c, http.StatusBadRequest, registerErrorCode(err), registerErrorMessage(err))
	case errors.Is(err, appregister.ErrRegisterRateLimited),
		errors.Is(err, appregister.ErrResendRateLimited),
		errors.Is(err, appregister.ErrResendCooldownActive),
		errors.Is(err, appregister.ErrVerifyRateLimited):
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
	case errors.Is(err, appregister.ErrPhoneNumberRequired):
		return codePhoneNumberRequired
	case errors.Is(err, appregister.ErrInvalidPhoneNumber):
		return codeInvalidPhoneNumber
	case errors.Is(err, appregister.ErrRegisterTicketRequired):
		return codeRegisterTicketRequired
	case errors.Is(err, appregister.ErrOTPCodeRequired):
		return codeOTPCodeRequired
	case errors.Is(err, appregister.ErrPasswordRequired):
		return codePasswordRequired
	case errors.Is(err, appregister.ErrPendingRegistrationInvalid):
		return codePendingRegistrationState
	case errors.Is(err, appregister.ErrRegisterRateLimited):
		return codeRegisterRateLimited
	case errors.Is(err, appregister.ErrResendRateLimited):
		return codeResendRateLimited
	case errors.Is(err, appregister.ErrResendCooldownActive):
		return codeResendCooldownActive
	case errors.Is(err, appregister.ErrVerifyRateLimited):
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
	case errors.Is(err, appregister.ErrPhoneNumberRequired):
		return "phone number is required"
	case errors.Is(err, appregister.ErrInvalidPhoneNumber):
		return "phone number format is invalid"
	case errors.Is(err, appregister.ErrRegisterTicketRequired):
		return "ticket id is required"
	case errors.Is(err, appregister.ErrOTPCodeRequired):
		return "otp code is required"
	case errors.Is(err, appregister.ErrPasswordRequired):
		return "password is required"
	case errors.Is(err, appregister.ErrPendingRegistrationInvalid):
		return "pending registration is invalid, please request a new otp"
	case errors.Is(err, appregister.ErrRegisterRateLimited):
		return "too many registration requests, please try again later"
	case errors.Is(err, appregister.ErrResendRateLimited):
		return "resend limit reached, please start a new registration"
	case errors.Is(err, appregister.ErrResendCooldownActive):
		return "please wait before requesting another otp"
	case errors.Is(err, appregister.ErrVerifyRateLimited):
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
