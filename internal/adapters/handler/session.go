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
	codeSessionTokenIssued      = "login_session_token_issued"
	codeSessionRevoked          = "settings_session_revoked"
	codeOtherSessionsRevoked    = "settings_other_sessions_revoked"
	codeAllSessionsRevoked      = "settings_all_sessions_revoked"
	codeSessionIDRequired       = "session_id_required"
	messageSettingsSessions     = "settings sessions fetched successfully"
	messageCurrentSession       = "current session fetched successfully"
	messageSessionTokenMade     = "login session token issued successfully"
	messageSessionRevoked       = "session revoked successfully"
	messageOtherSessionsRevoked = "other sessions revoked successfully"
	messageAllSessionsRevoked   = "all sessions revoked successfully"
)

type SessionHandler struct {
	session       appsession.UseCase
	sessionCookie SessionCookieConfig
}

func NewSessionHandler(session appsession.UseCase, sessionCookie SessionCookieConfig) *SessionHandler {
	return &SessionHandler{
		session:       session,
		sessionCookie: sessionCookie,
	}
}

func (h *SessionHandler) List(c *gin.Context) {
	sessionContext, ok := middleware.CurrentSession(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "session_token_required", "session token is required")
		return
	}

	result, err := h.session.List(c.Request.Context(), appsession.ListInput{
		UserID: sessionContext.UserID,
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
	sessionContext, ok := middleware.CurrentSession(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "session_token_required", "session token is required")
		return
	}

	result, err := h.session.Current(c.Request.Context(), appsession.CurrentInput{
		UserID:    sessionContext.UserID,
		SessionID: sessionContext.SessionID,
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

func (h *SessionHandler) Token(c *gin.Context) {
	sessionContext, ok := middleware.CurrentSession(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "session_token_required", "session token is required")
		return
	}

	result, err := h.session.IssueAccessToken(c.Request.Context(), appsession.IssueAccessTokenInput{
		UserID:    sessionContext.UserID,
		SessionID: sessionContext.SessionID,
	})
	if err != nil {
		handleSessionError(c, err)
		return
	}

	if result.Refreshed {
		if tokenValue, err := c.Cookie(h.sessionCookie.Name); err == nil && tokenValue != "" {
			h.setSessionCookie(c, tokenValue)
		}
	}

	c.JSON(http.StatusOK, dto.ResLogin{
		Success: true,
		Code:    codeSessionTokenIssued,
		Message: messageSessionTokenMade,
		Data: dto.ResLoginData{
			AccessToken: result.AccessToken.Token,
			TokenType:   result.AccessToken.TokenType,
			ExpiresAt:   result.AccessToken.ExpiresAt,
			ExpiresIn:   result.AccessToken.ExpiresIn,
		},
	})
}

func (h *SessionHandler) Revoke(c *gin.Context) {
	sessionContext, ok := middleware.CurrentSession(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "session_token_required", "session token is required")
		return
	}

	err := h.session.Revoke(c.Request.Context(), appsession.RevokeInput{
		UserID:    sessionContext.UserID,
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
	sessionContext, ok := middleware.CurrentSession(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "session_token_required", "session token is required")
		return
	}

	err := h.session.RevokeAll(c.Request.Context(), appsession.RevokeAllInput{
		UserID: sessionContext.UserID,
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
	sessionContext, ok := middleware.CurrentSession(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "session_token_required", "session token is required")
		return
	}

	err := h.session.RevokeOthers(c.Request.Context(), appsession.RevokeOthersInput{
		UserID:    sessionContext.UserID,
		SessionID: sessionContext.SessionID,
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
		respondError(c, http.StatusUnauthorized, "session_token_required", "session token is required")
	case errors.Is(err, appsession.ErrSessionIDRequired):
		respondError(c, http.StatusBadRequest, codeSessionIDRequired, "session id is required")
	case errors.Is(err, auth.ErrLoginSessionNotFound):
		respondError(c, http.StatusNotFound, "session_not_found", "session not found")
	case errors.Is(err, auth.ErrLoginSessionExpired), errors.Is(err, auth.ErrLoginSessionRevoked):
		respondError(c, http.StatusUnauthorized, "invalid_session", "login session is no longer valid")
	default:
		respondError(c, http.StatusInternalServerError, codeInternalServerError, "internal server error")
	}
}

func (h *SessionHandler) setSessionCookie(c *gin.Context, tokenValue string) {
	c.SetSameSite(h.sessionCookie.SameSite)
	c.SetCookie(
		h.sessionCookie.Name,
		tokenValue,
		int(h.sessionCookie.MaxAge.Seconds()),
		sessionCookiePath,
		"",
		h.sessionCookie.Secure,
		true,
	)
}
