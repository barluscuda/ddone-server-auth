package handler

import (
	"errors"
	"net/http"

	"ddone-server-auth/internal/adapters/dto"
	"ddone-server-auth/internal/adapters/middleware"
	apptokenmanager "ddone-server-auth/internal/application/tokenmanager"
	"ddone-server-auth/internal/domain/auth"

	"github.com/gin-gonic/gin"
)

const (
	codeTokensFetched       = "tokens_fetched"
	codeTokenRevoked        = "token_revoked"
	codeAllTokensRevoked    = "tokens_revoked"
	codeTokenIDRequired     = "token_id_required"
	messageTokensFetched    = "tokens fetched successfully"
	messageTokenRevoked     = "token revoked successfully"
	messageAllTokensRevoked = "tokens revoked successfully"
)

type TokenManagerHandler struct {
	tokens apptokenmanager.UseCase
}

func NewTokenManagerHandler(tokens apptokenmanager.UseCase) *TokenManagerHandler {
	return &TokenManagerHandler{tokens: tokens}
}

func (h *TokenManagerHandler) List(c *gin.Context) {
	authContext, ok := middleware.CurrentAuth(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "authorization_required", "authorization header is required")
		return
	}

	result, err := h.tokens.List(c.Request.Context(), apptokenmanager.ListInput{
		UserID: authContext.UserID,
	})
	if err != nil {
		handleTokenManagerError(c, err)
		return
	}

	data := make([]dto.ResTokenManagerData, 0, len(result))
	for _, token := range result {
		data = append(data, dto.ResTokenManagerData{
			ID:         token.ID,
			ClientIP:   token.ClientIP,
			UserAgent:  token.UserAgent,
			ExpiresAt:  token.ExpiresAt,
			LastUsedAt: token.LastUsedAt,
			ReplacedAt: token.ReplacedAt,
			RevokedAt:  token.RevokedAt,
			CreatedAt:  token.CreatedAt,
		})
	}

	c.JSON(http.StatusOK, dto.ResTokenManagerTokens{
		Success: true,
		Code:    codeTokensFetched,
		Message: messageTokensFetched,
		Data:    data,
	})
}

func (h *TokenManagerHandler) Revoke(c *gin.Context) {
	authContext, ok := middleware.CurrentAuth(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "authorization_required", "authorization header is required")
		return
	}

	err := h.tokens.Revoke(c.Request.Context(), apptokenmanager.RevokeInput{
		UserID:  authContext.UserID,
		TokenID: c.Param("tokenId"),
	})
	if err != nil {
		handleTokenManagerError(c, err)
		return
	}

	c.JSON(http.StatusOK, dto.ResMessage{
		Success: true,
		Code:    codeTokenRevoked,
		Message: messageTokenRevoked,
	})
}

func (h *TokenManagerHandler) RevokeAll(c *gin.Context) {
	authContext, ok := middleware.CurrentAuth(c)
	if !ok {
		respondError(c, http.StatusUnauthorized, "authorization_required", "authorization header is required")
		return
	}

	err := h.tokens.RevokeAll(c.Request.Context(), apptokenmanager.RevokeAllInput{
		UserID: authContext.UserID,
	})
	if err != nil {
		handleTokenManagerError(c, err)
		return
	}

	c.JSON(http.StatusOK, dto.ResMessage{
		Success: true,
		Code:    codeAllTokensRevoked,
		Message: messageAllTokensRevoked,
	})
}

func handleTokenManagerError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, apptokenmanager.ErrAuthenticatedUserRequired):
		respondError(c, http.StatusUnauthorized, "authorization_required", "authorization header is required")
	case errors.Is(err, apptokenmanager.ErrTokenIDRequired):
		respondError(c, http.StatusBadRequest, codeTokenIDRequired, "token id is required")
	case errors.Is(err, auth.ErrTokenNotFound):
		respondError(c, http.StatusNotFound, "token_not_found", "token not found")
	default:
		respondError(c, http.StatusInternalServerError, codeInternalServerError, "internal server error")
	}
}
