package handler

import (
	"errors"
	"net/http"

	"ddone-server-auth/internal/adapters/dto"
	"ddone-server-auth/internal/adapters/middleware"
	appsettings "ddone-server-auth/internal/application/settings"
	"ddone-server-auth/internal/domain/account"

	"github.com/gin-gonic/gin"
)

const (
	codeSettingsFetched         = "settings_fetched"
	codeSettingsSessionsFetched = "settings_sessions_fetched"
	messageSettingsFetched      = "settings fetched successfully"
	messageSettingsSessions     = "settings sessions fetched successfully"
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
		AccountID: authContext.AccountID,
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
			ID:              result.ID,
			Username:        result.Username,
			PhoneNumber:     result.PhoneNumber,
			PhoneVerifiedAt: result.PhoneVerifiedAt,
			CreatedAt:       result.CreatedAt,
		},
	})
}

func (h *SettingsHandler) ListSessions(c *gin.Context) {
	authContext, ok := middleware.CurrentAuth(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "authorization_required", "authorization header is required")
		return
	}

	result, err := h.settings.ListSessions(c.Request.Context(), appsettings.ListSessionsInput{
		AccountID: authContext.AccountID,
	})
	if err != nil {
		handleSettingsError(c, err)
		return
	}

	data := make([]dto.ResSettingsSessionData, 0, len(result))
	for _, session := range result {
		data = append(data, dto.ResSettingsSessionData{
			ID:                   session.ID,
			ClientIP:             session.ClientIP,
			UserAgent:            session.UserAgent,
			CurrentAccessExpires: session.CurrentAccessExpires,
			CreatedAt:            session.CreatedAt,
			RevokedAt:            session.RevokedAt,
		})
	}

	c.JSON(http.StatusOK, dto.ResSettingsSessions{
		Success: true,
		Code:    codeSettingsSessionsFetched,
		Message: messageSettingsSessions,
		Data:    data,
	})
}

func handleSettingsError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, appsettings.ErrAuthenticatedAccountRequired):
		respondError(c, http.StatusUnauthorized, "authorization_required", "authorization header is required")
	case errors.Is(err, account.ErrAccountNotFound):
		respondError(c, http.StatusNotFound, "account_not_found", "account not found")
	default:
		respondError(c, http.StatusInternalServerError, codeInternalServerError, "internal server error")
	}
}
