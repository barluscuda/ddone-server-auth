package auth

import "errors"

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrRefreshTokenRequired = errors.New("refresh token is required")
var ErrTokenNotFound = errors.New("token not found")
var ErrTokenExpired = errors.New("token has expired")
var ErrTokenRevoked = errors.New("token has been revoked")
var ErrRefreshTokenReplayDetected = errors.New("refresh token replay detected")
var ErrInvalidAccessToken = errors.New("invalid access token")
var ErrSessionTokenRequired = errors.New("session token is required")
var ErrLoginSessionNotFound = errors.New("login session not found")
var ErrLoginSessionRevoked = errors.New("login session has been revoked")
var ErrLoginSessionExpired = errors.New("login session has expired")
var ErrSigningKeyNotFound = errors.New("signing key not found")
