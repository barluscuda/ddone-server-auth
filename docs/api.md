# API Reference

This document describes the public HTTP API for `ddone-server-auth`.

Base URL examples use `http://localhost:3000`. All JSON field names are camelCase. Timestamps are RFC3339 strings. Error responses use the same envelope everywhere:

```json
{
  "success": false,
  "code": "invalid_request_body",
  "message": "invalid request body"
}
```

Requests with a `Content-Length` above the configured request body limit return `413 request_body_too_large`.

## Authentication

Bearer-token routes require:

```http
Authorization: Bearer <accessToken>
```

Session routes require the `HttpOnly` session cookie set by `POST /sessions`. The default cookie name is `ddone_session`. Unsafe session-cookie requests reject missing or untrusted `Origin` and `Referer` values with `403 session_origin_forbidden`.

## Health

### `GET /healthz`

Returns process health.

Success `200 OK`:

```json
{
  "success": true,
  "code": "healthz_ok",
  "message": "server is healthy",
  "active": true,
  "serverTime": "2026-05-25T09:00:00Z"
}
```

### `GET /robots.txt`

Success `200 OK`:

```text
User-agent: *
Disallow: /
```

## Registration

### `POST /registrations`

Starts phone-number registration and sends an OTP by SMS.

Request:

```json
{
  "phoneNumber": "+8562012345678",
  "password": "secretpass",
  "turnstileToken": "optional-cloudflare-turnstile-token"
}
```

Success `202 Accepted`:

```json
{
  "success": true,
  "code": "register_otp_sent",
  "message": "otp sent successfully",
  "data": {
    "ticketId": "reg_abc123",
    "expiresAt": "2026-05-25T09:05:00Z",
    "otpLength": 6,
    "resendCooldownSeconds": 60,
    "remainingResendCount": 3
  }
}
```

Challenge `403 Forbidden`:

```json
{
  "success": false,
  "code": "challenge_required",
  "message": "verification challenge required",
  "data": {
    "provider": "cloudflare_turnstile",
    "siteKey": "0x4AAAAAAA..."
  }
}
```

DexBotKiller delay mode can intentionally wait before returning the normal response. Enforce mode can return `403 register_blocked`.

Common errors: `400 invalid_request_body`, `400 phone_number_required`, `400 invalid_phone_number`, `400 unsupported_tel_code`, `400 password_required`, `403 challenge_required`, `403 challenge_invalid`, `403 register_blocked`, `409 phone_number_already_registered`, `429 register_rate_limited`.

### `POST /registrations/resend`

Resends a registration OTP for an existing ticket.

Request:

```json
{
  "ticketId": "reg_abc123",
  "turnstileToken": "optional-cloudflare-turnstile-token"
}
```

Success `202 Accepted`:

```json
{
  "success": true,
  "code": "register_otp_resent",
  "message": "otp resent successfully",
  "data": {
    "ticketId": "reg_abc123",
    "expiresAt": "2026-05-25T09:06:00Z",
    "otpLength": 6,
    "resendCooldownSeconds": 60,
    "remainingResendCount": 2
  }
}
```

DexBotKiller delay mode can intentionally wait before returning the normal response. Enforce mode can return `403 register_blocked`.

Common errors: `400 ticket_id_required`, `400 pending_registration_not_found`, `400 pending_registration_invalid`, `403 challenge_required`, `403 challenge_invalid`, `403 register_blocked`, `409 phone_number_already_registered`, `429 resend_cooldown_active`, `429 resend_rate_limited`.

### `POST /registrations/verify`

Verifies the registration OTP and creates the user.

Request:

```json
{
  "ticketId": "reg_abc123",
  "otpCode": "123456"
}
```

Success `201 Created`:

```json
{
  "success": true,
  "code": "register_verified",
  "message": "registration completed successfully",
  "data": {
    "id": "9f9d4c17-7f0d-47cf-96af-0de257391111",
    "username": "user1234",
    "phoneNumber": "+8562012345678",
    "phoneVerifiedAt": "2026-05-25T09:01:00Z",
    "createdAt": "2026-05-25T09:01:00Z"
  }
}
```

Common errors: `400 ticket_id_required`, `400 otp_code_required`, `400 invalid_otp_code`, `400 otp_expired`, `400 pending_registration_not_found`, `400 pending_registration_invalid`, `409 phone_number_already_registered`, `409 username_already_registered`, `429 verify_rate_limited`.

## Token Login

### `POST /tokens`

Authenticates a user and returns an access token plus refresh token.

Request:

```json
{
  "phoneNumber": "+8562012345678",
  "password": "secretpass"
}
```

Success `200 OK`:

```json
{
  "success": true,
  "code": "login_succeeded",
  "message": "login completed successfully",
  "data": {
    "accessToken": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtleV8xIiwidHlwIjoiSldUIn0...",
    "tokenType": "Bearer",
    "expiresAt": "2026-05-25T09:06:00Z",
    "expiresIn": 300,
    "refreshToken": "refresh_token_value",
    "refreshExpiresAt": "2026-06-24T09:01:00Z"
  }
}
```

Common errors: `400 invalid_request_body`, `400 phone_number_required`, `400 invalid_phone_number`, `400 password_required`, `401 invalid_credentials`, `429 login_rate_limited`.

### `POST /tokens/refresh`

Rotates a refresh token and returns a new access token plus refresh token. Refresh-token replay revokes the affected token chain.

Request:

```json
{
  "refreshToken": "refresh_token_value"
}
```

Success `200 OK`:

```json
{
  "success": true,
  "code": "token_refreshed",
  "message": "token refreshed successfully",
  "data": {
    "accessToken": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtleV8xIiwidHlwIjoiSldUIn0...",
    "tokenType": "Bearer",
    "expiresAt": "2026-05-25T09:11:00Z",
    "expiresIn": 300,
    "refreshToken": "new_refresh_token_value",
    "refreshExpiresAt": "2026-06-24T09:06:00Z"
  }
}
```

Common errors: `400 refresh_token_required`, `401 invalid_credentials`, `401 refresh_token_expired`, `401 refresh_token_revoked`, `401 refresh_token_replay_detected`.

### `GET /tokens`

Requires bearer token. Lists refresh-token records for the authenticated user.

Success `200 OK`:

```json
{
  "success": true,
  "code": "tokens_fetched",
  "message": "tokens fetched successfully",
  "data": [
    {
      "id": "tok_123",
      "clientIp": "127.0.0.1",
      "userAgent": "Mozilla/5.0",
      "expiresAt": "2026-06-24T09:01:00Z",
      "lastUsedAt": "2026-05-25T09:06:00Z",
      "replacedAt": "2026-05-25T09:06:00Z",
      "createdAt": "2026-05-25T09:01:00Z"
    }
  ]
}
```

Common errors: `401 authorization_required`, `401 invalid_access_token`.

### `DELETE /tokens/:tokenId`

Requires bearer token. Revokes one refresh-token record owned by the authenticated user.

Success `200 OK`:

```json
{
  "success": true,
  "code": "token_revoked",
  "message": "token revoked successfully"
}
```

Common errors: `400 token_id_required`, `401 authorization_required`, `401 invalid_access_token`, `404 token_not_found`.

### `POST /tokens/revoke-all`

Requires bearer token. Revokes all refresh-token records for the authenticated user.

Success `200 OK`:

```json
{
  "success": true,
  "code": "tokens_revoked",
  "message": "tokens revoked successfully"
}
```

Common errors: `401 authorization_required`, `401 invalid_access_token`.

## Browser Session Login

### `POST /sessions`

Authenticates a user, creates a server-side login session, and sets an `HttpOnly` cookie. The response body intentionally does not include tokens.

Request:

```json
{
  "phoneNumber": "+8562012345678",
  "password": "secretpass"
}
```

Success `200 OK`:

```http
Set-Cookie: ddone_session=<opaque-session-token>; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax
```

```json
{
  "success": true,
  "code": "login_session_created",
  "message": "login session created successfully",
  "data": {}
}
```

Common errors: `400 invalid_request_body`, `400 phone_number_required`, `400 invalid_phone_number`, `400 password_required`, `401 invalid_credentials`, `429 login_rate_limited`.

### `POST /sessions/token`

Requires session cookie. Returns an access token for the current session. If the stored access token is expired but the session is valid, the service issues a fresh access token and refreshes the cookie age.

Success `200 OK`:

```json
{
  "success": true,
  "code": "login_session_token_issued",
  "message": "login session token issued successfully",
  "data": {
    "accessToken": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtleV8xIiwidHlwIjoiSldUIn0...",
    "tokenType": "Bearer",
    "expiresAt": "2026-05-25T09:06:00Z",
    "expiresIn": 300
  }
}
```

Common errors: `401 session_token_required`, `401 invalid_session`, `403 session_origin_forbidden`.

### `GET /sessions`

Requires session cookie. Lists login sessions for the current user.

Success `200 OK`:

```json
{
  "success": true,
  "code": "settings_sessions_fetched",
  "message": "settings sessions fetched successfully",
  "data": [
    {
      "id": "sess_123",
      "clientIp": "127.0.0.1",
      "userAgent": "Mozilla/5.0",
      "currentAccessExpires": "2026-05-25T09:06:00Z",
      "createdAt": "2026-05-25T09:01:00Z"
    }
  ]
}
```

Common errors: `401 session_token_required`, `401 invalid_session`.

### `GET /sessions/current`

Requires session cookie.

Success `200 OK`:

```json
{
  "success": true,
  "code": "settings_current_session_fetched",
  "message": "current session fetched successfully",
  "data": {
    "id": "sess_123",
    "clientIp": "127.0.0.1",
    "userAgent": "Mozilla/5.0",
    "currentAccessExpires": "2026-05-25T09:06:00Z",
    "createdAt": "2026-05-25T09:01:00Z"
  }
}
```

Common errors: `401 session_token_required`, `401 invalid_session`, `404 session_not_found`.

### `DELETE /sessions/:sessionId`

Requires session cookie. Revokes a login session owned by the current user.

Success `200 OK`:

```json
{
  "success": true,
  "code": "settings_session_revoked",
  "message": "session revoked successfully"
}
```

Common errors: `400 session_id_required`, `401 session_token_required`, `401 invalid_session`, `403 session_origin_forbidden`, `404 session_not_found`.

### `POST /sessions/revoke-others`

Requires session cookie. Revokes all other sessions and keeps the current session active.

Success `200 OK`:

```json
{
  "success": true,
  "code": "settings_other_sessions_revoked",
  "message": "other sessions revoked successfully"
}
```

Common errors: `401 session_token_required`, `401 invalid_session`, `403 session_origin_forbidden`.

### `POST /sessions/revoke-all`

Requires session cookie. Revokes all login sessions for the current user.

Success `200 OK`:

```json
{
  "success": true,
  "code": "settings_all_sessions_revoked",
  "message": "all sessions revoked successfully"
}
```

Common errors: `401 session_token_required`, `401 invalid_session`, `403 session_origin_forbidden`.

## Password Reset And Password Change

### `POST /password-resets`

Starts password reset and sends an OTP by SMS when the phone number belongs to an account. This is blocked for 7 days after a successful password reset or password change. Unknown phone numbers still receive the same accepted response shape, but no OTP is sent and no reset ticket is persisted.

Request:

```json
{
  "phoneNumber": "+8562012345678"
}
```

Success `202 Accepted`:

```json
{
  "success": true,
  "code": "password_reset_otp_sent",
  "message": "password reset otp sent successfully",
  "data": {
    "ticketId": "reset_abc123",
    "expiresAt": "2026-05-25T09:05:00Z",
    "otpLength": 6,
    "resendCooldownSeconds": 60,
    "remainingResendCount": 3
  }
}
```

Common errors: `400 invalid_request_body`, `400 phone_number_required`, `400 invalid_phone_number`, `400 unsupported_tel_code`, `429 password_reset_rate_limited`, `429 password_change_cooldown_active`.

### `POST /password-resets/resend`

Resends an OTP for an existing password-reset ticket.

Request:

```json
{
  "ticketId": "reset_abc123"
}
```

Success `202 Accepted`:

```json
{
  "success": true,
  "code": "password_reset_otp_resent",
  "message": "password reset otp resent successfully",
  "data": {
    "ticketId": "reset_abc123",
    "expiresAt": "2026-05-25T09:06:00Z",
    "otpLength": 6,
    "resendCooldownSeconds": 60,
    "remainingResendCount": 2
  }
}
```

Common errors: `400 password_reset_ticket_required`, `404 password_reset_ticket_not_found`, `429 password_reset_resend_cooldown_active`, `429 password_reset_resend_rate_limited`.

### `POST /password-resets/verify`

Verifies a password-reset OTP, updates the password, and revokes existing login sessions and refresh-token records.

Request:

```json
{
  "ticketId": "reset_abc123",
  "otpCode": "123456",
  "newPassword": "newsecretpass"
}
```

Success `200 OK`:

```json
{
  "success": true,
  "code": "password_reset_completed",
  "message": "password reset completed successfully"
}
```

Common errors: `400 password_reset_ticket_required`, `400 otp_code_required`, `400 new_password_required`, `400 invalid_otp_code`, `400 otp_expired`, `404 password_reset_ticket_not_found`, `429 password_reset_verify_rate_limited`, `429 password_change_cooldown_active`.

### `POST /settings/password`

Requires bearer token. Changes the password after verifying the current password. A successful change revokes existing login sessions and refresh-token records.

Request:

```json
{
  "currentPassword": "secretpass",
  "newPassword": "newsecretpass"
}
```

Success `200 OK`:

```json
{
  "success": true,
  "code": "password_changed",
  "message": "password changed successfully"
}
```

Common errors: `400 current_password_required`, `400 new_password_required`, `400 invalid_current_password`, `401 authorization_required`, `401 invalid_access_token`, `404 user_not_found`, `429 password_change_cooldown_active`.

## Settings

### `GET /settings`

Requires bearer token. Alias for `GET /settings/me`.

Success `200 OK`:

```json
{
  "success": true,
  "code": "settings_fetched",
  "message": "settings fetched successfully",
  "data": {
    "id": "9f9d4c17-7f0d-47cf-96af-0de257391111",
    "username": "user1234",
    "phoneNumber": "+8562012345678",
    "phoneVerifiedAt": "2026-05-25T09:01:00Z",
    "usernameChangedAt": "2026-05-25T09:02:00Z",
    "usernameCanChangeAt": "2026-06-01T09:02:00Z",
    "canChangeUsername": false,
    "canChangePassword": true,
    "passwordChangedAt": "2026-05-01T09:00:00Z",
    "createdAt": "2026-05-25T09:01:00Z",
    "updatedAt": "2026-05-25T09:02:00Z"
  }
}
```

Common errors: `401 authorization_required`, `401 invalid_access_token`, `404 user_not_found`.

### `GET /settings/me`

Requires bearer token. Response and errors match `GET /settings`.

### `PATCH /settings/username`

Requires bearer token. Updates the current user's username. Username changes are blocked for 7 days after a successful username change.

Request:

```json
{
  "username": "new_username"
}
```

Success `200 OK`:

```json
{
  "success": true,
  "code": "settings_username_updated",
  "message": "username updated successfully",
  "data": {
    "username": "new_username",
    "usernameChangedAt": "2026-05-25T09:02:00Z"
  }
}
```

Common errors: `400 username_required`, `400 invalid_username`, `400 username_unchanged`, `401 authorization_required`, `401 invalid_access_token`, `404 user_not_found`, `409 username_already_registered`, `429 username_change_cooldown_active`.

## JWKS

### `GET /.well-known/jwks.json`

Returns public signing keys for access-token verification. Responses include `Cache-Control: public, max-age=300` and `ETag`. Requests with matching `If-None-Match` return `304 Not Modified`.

Success `200 OK`:

```json
{
  "keys": [
    {
      "kty": "EC",
      "use": "sig",
      "crv": "P-256",
      "alg": "ES256",
      "kid": "key_123",
      "x": "base64url-x-coordinate",
      "y": "base64url-y-coordinate"
    }
  ]
}
```

Common errors: `500 internal_server_error`.
