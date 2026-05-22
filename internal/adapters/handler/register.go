package handler

import (
	"ddone-server-auth/internal/adapters/dto"
	"ddone-server-auth/internal/domain/account"
	"ddone-server-auth/internal/services"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
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
		c.JSON(http.StatusBadRequest, dto.ResMessage{Message: err.Error()})
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
		Message:   "otp sent successfully",
		TicketID:  result.TicketID,
		ExpiresAt: result.ExpiresAt,
	})
}

func (h *RegisterHandler) VerifyRegister(c *gin.Context) {
	var req dto.ReqVerifyRegister
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ResMessage{Message: err.Error()})
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
		ID:              accountModel.ID,
		Username:        accountModel.Username,
		PhoneNumber:     accountModel.PhoneNumber,
		PhoneVerifiedAt: accountModel.PhoneVerifiedAt,
		CreatedAt:       accountModel.CreatedAt,
	})
}

func handleRegisterError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, services.ErrPhoneNumberRequired),
		errors.Is(err, services.ErrInvalidPhoneNumber),
		errors.Is(err, services.ErrRegisterTicketRequired),
		errors.Is(err, services.ErrOTPCodeRequired),
		errors.Is(err, services.ErrPasswordRequired),
		errors.Is(err, services.ErrPendingRegistrationInvalid):
		c.JSON(http.StatusBadRequest, dto.ResMessage{Message: err.Error()})
	case errors.Is(err, services.ErrRegisterRateLimited),
		errors.Is(err, services.ErrVerifyRateLimited):
		c.JSON(http.StatusTooManyRequests, dto.ResMessage{Message: err.Error()})
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
