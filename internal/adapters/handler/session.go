package handler

import (
	"errors"
	"net/http"

	"ddone-server-auth/internal/adapters/dto"
	"ddone-server-auth/internal/adapters/middleware"
	appsession "ddone-server-auth/internal/application/session"
	"ddone-server-auth/internal/domain/auth"

	"github.com/gin-gonic/gin"
)

const (
	codeSettingsSessionsFetched = "settings_sessions_fetched"
	codeCurrentSessionFetched   = "settings_current_session_fetched"
	codeSessionRevoked          = "settings_session_revoked"
	codeOtherSessionsRevoked    = "settings_other_sessions_revoked"
	codeAllSessionsRevoked      = "settings_all_sessions_revoked"
	codeSessionIDRequired       = "session_id_required"
	messageSettingsSessions     = "settings sessions fetched successfully"
	messageCurrentSession       = "current session fetched successfully"
	messageSessionRevoked       = "session revoked successfully"
	messageOtherSessionsRevoked = "other sessions revoked successfully"
	messageAllSessionsRevoked   = "all sessions revoked successfully"
)

type SessionHandler struct {
	session appsession.UseCase
}

func NewSessionHandler(session appsession.UseCase) *SessionHandler {
	return &SessionHandler{session: session}
}

func (h *SessionHandler) List(c *gin.Context) {
	authContext, ok := middleware.CurrentAuth(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "authorization_required", "authorization header is required")
		return
	}

	result, err := h.session.List(c.Request.Context(), appsession.ListInput{
		UserID: authContext.UserID,
	})
	if err != nil {
		handleSessionError(c, err)
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

func (h *SessionHandler) Current(c *gin.Context) {
	authContext, ok := middleware.CurrentAuth(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "authorization_required", "authorization header is required")
		return
	}

	result, err := h.session.Current(c.Request.Context(), appsession.CurrentInput{
		UserID:   authContext.UserID,
		AccessToken: authContext.AccessToken,
	})
	if err != nil {
		handleSessionError(c, err)
		return
	}

	c.JSON(http.StatusOK, dto.ResSettingsSession{
		Success: true,
		Code:    codeCurrentSessionFetched,
		Message: messageCurrentSession,
		Data: dto.ResSettingsSessionData{
			ID:                   result.ID,
			ClientIP:             result.ClientIP,
			UserAgent:            result.UserAgent,
			CurrentAccessExpires: result.CurrentAccessExpires,
			CreatedAt:            result.CreatedAt,
			RevokedAt:            result.RevokedAt,
		},
	})
}

func (h *SessionHandler) Revoke(c *gin.Context) {
	authContext, ok := middleware.CurrentAuth(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "authorization_required", "authorization header is required")
		return
	}

	err := h.session.Revoke(c.Request.Context(), appsession.RevokeInput{
		UserID: authContext.UserID,
		SessionID: c.Param("sessionId"),
	})
	if err != nil {
		handleSessionError(c, err)
		return
	}

	c.JSON(http.StatusOK, dto.ResMessage{
		Success: true,
		Code:    codeSessionRevoked,
		Message: messageSessionRevoked,
	})
}

func (h *SessionHandler) RevokeAll(c *gin.Context) {
	authContext, ok := middleware.CurrentAuth(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "authorization_required", "authorization header is required")
		return
	}

	err := h.session.RevokeAll(c.Request.Context(), appsession.RevokeAllInput{
		UserID: authContext.UserID,
	})
	if err != nil {
		handleSessionError(c, err)
		return
	}

	c.JSON(http.StatusOK, dto.ResMessage{
		Success: true,
		Code:    codeAllSessionsRevoked,
		Message: messageAllSessionsRevoked,
	})
}

func (h *SessionHandler) RevokeOthers(c *gin.Context) {
	authContext, ok := middleware.CurrentAuth(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "authorization_required", "authorization header is required")
		return
	}

	err := h.session.RevokeOthers(c.Request.Context(), appsession.RevokeOthersInput{
		UserID:   authContext.UserID,
		AccessToken: authContext.AccessToken,
	})
	if err != nil {
		handleSessionError(c, err)
		return
	}

	c.JSON(http.StatusOK, dto.ResMessage{
		Success: true,
		Code:    codeOtherSessionsRevoked,
		Message: messageOtherSessionsRevoked,
	})
}

func handleSessionError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, appsession.ErrAuthenticatedUserRequired):
		respondError(c, http.StatusUnauthorized, "authorization_required", "authorization header is required")
	case errors.Is(err, appsession.ErrSessionIDRequired):
		respondError(c, http.StatusBadRequest, codeSessionIDRequired, "session id is required")
	case errors.Is(err, appsession.ErrAccessTokenRequired):
		respondError(c, http.StatusBadRequest, "access_token_required", "access token is required")
	case errors.Is(err, auth.ErrLoginSessionNotFound):
		respondError(c, http.StatusNotFound, "session_not_found", "session not found")
	default:
		respondError(c, http.StatusInternalServerError, codeInternalServerError, "internal server error")
	}
}
