package handler

import (
	"errors"
	"net/http"

	"ddone-server-auth/internal/adapters/dto"
	"ddone-server-auth/internal/adapters/middleware"
	appsettings "ddone-server-auth/internal/application/settings"
	"ddone-server-auth/internal/domain/user"

	"github.com/gin-gonic/gin"
)

const (
	codeSettingsFetched       = "settings_fetched"
	codeSettingsUsernameSaved = "settings_username_updated"
	messageSettingsFetched    = "settings fetched successfully"
	messageUsernameSaved      = "username updated successfully"
)

type SettingsHandler struct {
	settings appsettings.UseCase
}

func NewSettingsHandler(settings appsettings.UseCase) *SettingsHandler {
	return &SettingsHandler{settings: settings}
}

func (h *SettingsHandler) GetMe(c *gin.Context) {
	authContext, ok := middleware.CurrentAuth(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "authorization_required", "authorization header is required")
		return
	}

	result, err := h.settings.Get(c.Request.Context(), appsettings.GetInput{
		UserID: authContext.UserID,
	})
	if err != nil {
		handleSettingsError(c, err)
		return
	}

	c.JSON(http.StatusOK, dto.ResSettingsMe{
		Success: true,
		Code:    codeSettingsFetched,
		Message: messageSettingsFetched,
		Data: dto.ResSettingsMeData{
			ID:                  result.ID,
			Username:            result.Username,
			PhoneNumber:         result.PhoneNumber,
			PhoneVerifiedAt:     result.PhoneVerifiedAt,
			UsernameChangedAt:   result.UsernameChangedAt,
			UsernameCanChangeAt: result.UsernameCanChangeAt,
			CanChangeUsername:   result.CanChangeUsername,
			CanChangePassword:   result.CanChangePassword,
			PasswordChangedAt:   result.PasswordChangedAt,
			CreatedAt:           result.CreatedAt,
			UpdatedAt:           result.UpdatedAt,
		},
	})
}

func (h *SettingsHandler) PatchUsername(c *gin.Context) {
	authContext, ok := middleware.CurrentAuth(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "authorization_required", "authorization header is required")
		return
	}

	var req dto.ReqUpdateUsername
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, codeInvalidRequestBody, messageInvalidRequestBody)
		return
	}

	result, err := h.settings.UpdateUsername(c.Request.Context(), appsettings.UpdateUsernameInput{
		UserID:   authContext.UserID,
		Username: req.Username,
	})
	if err != nil {
		handleSettingsError(c, err)
		return
	}

	c.JSON(http.StatusOK, dto.ResSettingsUsername{
		Success: true,
		Code:    codeSettingsUsernameSaved,
		Message: messageUsernameSaved,
		Data: dto.ResSettingsUsernameData{
			Username:          result.Username,
			UsernameChangedAt: result.UsernameChangedAt,
		},
	})
}

func handleSettingsError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, appsettings.ErrAuthenticatedUserRequired):
		respondError(c, http.StatusUnauthorized, "authorization_required", "authorization header is required")
	case errors.Is(err, appsettings.ErrUsernameRequired),
		errors.Is(err, appsettings.ErrInvalidUsername),
		errors.Is(err, appsettings.ErrUsernameUnchanged):
		respondError(c, http.StatusBadRequest, settingsErrorCode(err), settingsErrorMessage(err))
	case errors.Is(err, appsettings.ErrUsernameCooldownActive):
		respondError(c, http.StatusTooManyRequests, settingsErrorCode(err), settingsErrorMessage(err))
	case errors.Is(err, user.ErrUserNotFound):
		respondError(c, http.StatusNotFound, "user_not_found", "user not found")
	case errors.Is(err, user.ErrUsernameAlreadyRegistered):
		respondError(c, http.StatusConflict, settingsErrorCode(err), settingsErrorMessage(err))
	default:
		respondError(c, http.StatusInternalServerError, codeInternalServerError, "internal server error")
	}
}

func settingsErrorCode(err error) string {
	switch {
	case errors.Is(err, appsettings.ErrUsernameRequired):
		return "username_required"
	case errors.Is(err, appsettings.ErrInvalidUsername):
		return "invalid_username"
	case errors.Is(err, appsettings.ErrUsernameUnchanged):
		return "username_unchanged"
	case errors.Is(err, appsettings.ErrUsernameCooldownActive):
		return "username_change_cooldown_active"
	case errors.Is(err, user.ErrUsernameAlreadyRegistered):
		return "username_already_registered"
	default:
		return codeInternalServerError
	}
}

func settingsErrorMessage(err error) string {
	switch {
	case errors.Is(err, appsettings.ErrUsernameRequired):
		return "username is required"
	case errors.Is(err, appsettings.ErrInvalidUsername):
		return "username is invalid"
	case errors.Is(err, appsettings.ErrUsernameUnchanged):
		return "username is unchanged"
	case errors.Is(err, appsettings.ErrUsernameCooldownActive):
		return "username can only be changed once every 7 days"
	case errors.Is(err, user.ErrUsernameAlreadyRegistered):
		return "username is already registered"
	default:
		return "internal server error"
	}
}
