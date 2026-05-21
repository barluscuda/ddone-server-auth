package handler

import (
	"ddone-server-auth/internal/adapters/dto"
	"ddone-server-auth/internal/domain/account"
	"ddone-server-auth/internal/services"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	register *services.RegisterService
}

func NewAuthHandler(register *services.RegisterService) *AuthHandler {
	return &AuthHandler{register: register}
}

func (h *AuthHandler) RequestRegisterOTP(c *gin.Context) {
	var req dto.ReqRegisterOTP
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ResMessage{Message: err.Error()})
		return
	}

	result, err := h.register.RequestOTP(c.Request.Context(), services.RequestRegistrationInput{
		Username:    req.Username,
		PhoneNumber: req.PhoneNumber,
	})
	if err != nil {
		handleRegisterError(c, err)
		return
	}

	c.JSON(http.StatusAccepted, dto.ResRegisterOTPRequested{
		Message:   "otp sent successfully",
		ExpiresAt: result.ExpiresAt,
	})
}

func (h *AuthHandler) VerifyRegisterOTP(c *gin.Context) {
	var req dto.ReqVerifyRegisterOTP
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ResMessage{Message: err.Error()})
		return
	}

	accountModel, err := h.register.VerifyOTP(c.Request.Context(), services.VerifyRegistrationInput{
		PhoneNumber: req.PhoneNumber,
		OTPCode:     req.OTPCode,
	})
	if err != nil {
		handleRegisterError(c, err)
		return
	}

	c.JSON(http.StatusCreated, dto.ResRegisteredAccount{
		ID:              accountModel.ID,
		Username:        accountModel.Username,
		PhoneNumber:     accountModel.PhoneNumber,
		PhoneVerifiedAt: accountModel.PhoneVerifiedAt,
		CreatedAt:       accountModel.CreatedAt,
	})
}

func handleRegisterError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, account.ErrPhoneNumberAlreadyRegistered),
		errors.Is(err, account.ErrUsernameAlreadyRegistered):
		c.JSON(http.StatusConflict, dto.ResMessage{Message: err.Error()})
	case errors.Is(err, account.ErrPendingRegistrationNotFound),
		errors.Is(err, account.ErrInvalidOTPCode),
		errors.Is(err, account.ErrOTPExpired):
		c.JSON(http.StatusBadRequest, dto.ResMessage{Message: err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, dto.ResMessage{Message: "internal server error"})
	}
}
