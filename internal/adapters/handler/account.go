package handler

import (
	"errors"
	"net/http"

	"ddone-server-auth/internal/adapters/dto"
	"ddone-server-auth/internal/adapters/middleware"
	appaccountmanager "ddone-server-auth/internal/application/accountmanager"
	"ddone-server-auth/internal/domain/account"

	"github.com/gin-gonic/gin"
)

const (
	codeAccountFetched     = "account_fetched"
	codeSessionsFetched    = "account_sessions_fetched"
	messageAccountFetched  = "account fetched successfully"
	messageSessionsFetched = "account sessions fetched successfully"
)

type AccountManagerHandler struct {
	accountManager appaccountmanager.UseCase
}

func NewAccountManagerHandler(accountManager appaccountmanager.UseCase) *AccountManagerHandler {
	return &AccountManagerHandler{accountManager: accountManager}
}

func (h *AccountManagerHandler) GetMe(c *gin.Context) {
	authContext, ok := middleware.CurrentAuth(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "authorization_required", "authorization header is required")
		return
	}

	result, err := h.accountManager.GetMe(c.Request.Context(), appaccountmanager.GetMeInput{
		AccountID: authContext.AccountID,
	})
	if err != nil {
		handleAccountManagerError(c, err)
		return
	}

	c.JSON(http.StatusOK, dto.ResAccountMe{
		Success: true,
		Code:    codeAccountFetched,
		Message: messageAccountFetched,
		Data: dto.ResAccountMeData{
			ID:              result.ID,
			Username:        result.Username,
			PhoneNumber:     result.PhoneNumber,
			PhoneVerifiedAt: result.PhoneVerifiedAt,
			CreatedAt:       result.CreatedAt,
		},
	})
}

func (h *AccountManagerHandler) ListSessions(c *gin.Context) {
	authContext, ok := middleware.CurrentAuth(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "authorization_required", "authorization header is required")
		return
	}

	result, err := h.accountManager.ListMySessions(c.Request.Context(), appaccountmanager.ListMySessionsInput{
		AccountID: authContext.AccountID,
	})
	if err != nil {
		handleAccountManagerError(c, err)
		return
	}

	data := make([]dto.ResAccountSessionData, 0, len(result))
	for _, session := range result {
		data = append(data, dto.ResAccountSessionData{
			ID:                   session.ID,
			ClientIP:             session.ClientIP,
			UserAgent:            session.UserAgent,
			CurrentAccessExpires: session.CurrentAccessExpires,
			CreatedAt:            session.CreatedAt,
			RevokedAt:            session.RevokedAt,
		})
	}

	c.JSON(http.StatusOK, dto.ResAccountSessions{
		Success: true,
		Code:    codeSessionsFetched,
		Message: messageSessionsFetched,
		Data:    data,
	})
}

func handleAccountManagerError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, appaccountmanager.ErrAuthenticatedAccountRequired):
		respondError(c, http.StatusUnauthorized, "authorization_required", "authorization header is required")
	case errors.Is(err, account.ErrAccountNotFound):
		respondError(c, http.StatusNotFound, "account_not_found", "account not found")
	default:
		respondError(c, http.StatusInternalServerError, codeInternalServerError, "internal server error")
	}
}
