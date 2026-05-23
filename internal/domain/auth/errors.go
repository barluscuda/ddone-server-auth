package auth

import "errors"

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrRefreshTokenRequired = errors.New("refresh token is required")
var ErrRefreshSessionNotFound = errors.New("refresh session not found")
var ErrRefreshSessionExpired = errors.New("refresh session has expired")
var ErrRefreshSessionRevoked = errors.New("refresh session has been revoked")
var ErrRefreshTokenReplayDetected = errors.New("refresh token replay detected")
var ErrSigningKeyNotFound = errors.New("signing key not found")
