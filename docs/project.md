# ddone-server-auth Project Handbook

This document is the main engineering reference for `ddone-server-auth`. It covers the service purpose, setup, architecture, API surface, business flows, storage, security model, and maintenance rules.

## 1. Service Overview

`ddone-server-auth` is the authentication service for DDONE. It owns phone-based account registration, password authentication, refresh-token sessions, server-side browser login sessions, password reset, user settings, and ES256 access-token signing with JWKS publication.

The service is written in Go and is moving toward hexagonal architecture. Application use cases orchestrate business behavior. Domain packages hold business concepts and errors. Adapters handle HTTP, PostgreSQL, Redis, SMS, JWT signing, middleware, and DTO mapping.

### Runtime Responsibilities

- Register users by phone number with OTP verification.
- Authenticate users with phone number and password.
- Issue ES256 JWT access tokens.
- Issue, rotate, list, and revoke raw refresh tokens.
- Create and manage database-backed login sessions transported by `HttpOnly` cookies.
- Return access tokens for active login sessions.
- Reset forgotten passwords with OTP verification.
- Change authenticated-user passwords.
- Revoke tokens and login sessions after password reset or password change.
- Expose public JWKS for access-token verification.
- Serve health, CORS, request logging, and panic recovery middleware.

### Main Dependencies

- Go `1.26.2`
- Gin for HTTP delivery
- GORM for PostgreSQL persistence
- PostgreSQL with `pgcrypto` enabled
- Redis for pending OTP state, counters, and read-through caches
- Wenova SMS API for OTP delivery
- Zap for structured logging

## 2. Quick Start

Start PostgreSQL and Redis:

```bash
make infra-up
```

Run the API server:

```bash
make run
```

Run the test suite:

```bash
make test
```

Format Go code:

```bash
make fmt
```

Stop local infrastructure:

```bash
make infra-down
```

The local API listens on `http://localhost:3000` by default.

## 3. Required Setup

### PostgreSQL

The database must support UUID generation through the `pgcrypto` extension:

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
```

Docker Compose installs this extension through [db/init/001_pgcrypto.sql](/home/mrbarlus/coding/DDONE/ddone-server-auth/db/init/001_pgcrypto.sql) when the PostgreSQL data volume is first created.

Important: PostgreSQL init scripts run only on first volume creation. If `postgres_data` already exists, either run the SQL manually in the database or recreate the volume.

### Redis

Redis is required for:

- Pending registration tickets
- Pending password-reset tickets
- OTP resend and verification counters
- User read-through cache
- Login-session list cache
- Public signing-key cache

### Wenova SMS

Registration and password reset require a Wenova API token in real environments:

```bash
DDONE_WENOVA_TOKEN=your-token
```

The service sends OTP messages through the SMS adapter under `internal/adapters/sms`.

## 4. Configuration

Configuration is loaded from:

1. `config/config.yaml`
2. environment variables prefixed with `DDONE_`
3. optional `.env`

### Common Variables

```bash
DDONE_APP_PORT=3000
DDONE_APP_DEBUG=true

DDONE_DATABASE_HOST=localhost
DDONE_DATABASE_PORT=5432
DDONE_DATABASE_NAME=ddone_auth
DDONE_DATABASE_USERNAME=postgres
DDONE_DATABASE_PASSWORD=postgres
DDONE_DATABASE_SSLMODE=disable
DDONE_DATABASE_LOG_SQL=true

DDONE_REDIS_HOST=localhost
DDONE_REDIS_PORT=6380

DDONE_CACHE_USER_TTL=5m
DDONE_CACHE_USER_SESSION_LIST_TTL=1m
DDONE_CACHE_SIGNING_KEYS_TTL=1m

DDONE_CORS_ALLOWED_ORIGINS=http://localhost:5173
DDONE_CORS_ALLOWED_METHODS=GET,POST,OPTIONS
DDONE_CORS_ALLOWED_HEADERS=Origin,Content-Type,Accept,Authorization
DDONE_CORS_ALLOW_CREDENTIALS=false
DDONE_CORS_MAX_AGE=12h

DDONE_AUTH_ISSUER=ddone-server-auth
DDONE_AUTH_AUDIENCE=ddone-clients
DDONE_AUTH_ACCESS_TOKEN_TTL=15m
DDONE_AUTH_REFRESH_TOKEN_TTL=720h
DDONE_AUTH_LOGIN_SESSION_TTL=720h
DDONE_AUTH_SIGNING_KEY_ROTATION=2160h
DDONE_AUTH_SIGNING_KEY_RETENTION=4320h
DDONE_AUTH_SESSION_COOKIE_NAME=ddone_session
DDONE_AUTH_SESSION_COOKIE_SECURE=false
DDONE_AUTH_SESSION_COOKIE_SAME_SITE=lax
DDONE_AUTH_SESSION_COOKIE_MAX_AGE=720h

DDONE_WENOVA_TOKEN=your-token
```

### URL Overrides

Use these when deployment platforms provide full connection URLs:

```bash
DDONE_DATABASE_URL=postgres://user:pass@host:5432/ddone_auth?sslmode=require
DDONE_REDIS_URL=redis://localhost:6379/0
```

### Validation Rules

- `app.port` must be positive.
- `database.host`, `database.name`, `database.username`, and `database.sslmode` are required when `database.url` is empty.
- `redis.host` is required when `redis.url` is empty.
- Cache TTL values must be zero or positive. A zero TTL disables that read-through cache.
- CORS origins, methods, and headers must not be empty.
- `cors.allowed_origins` cannot include `*` when `cors.allow_credentials=true`.
- Auth TTL values must be positive.
- `auth.signing_key_retention` must be greater than or equal to `auth.signing_key_rotation`.
- `auth.session_cookie_same_site` must be `lax`, `strict`, or `none`.
- `auth.session_cookie_secure` must be true when `auth.session_cookie_same_site=none`.
- `auth.session_cookie_max_age`, when set, must not exceed `auth.login_session_ttl`.

## 5. Project Structure

```text
cmd/app/                       Process entrypoint and HTTP server wiring
config/                        Config loading, defaults, validation
db/init/                       Local PostgreSQL initialization SQL
docs/                          Engineering and API documentation
postman/                       Postman collection and local environment
internal/domain/user/          User domain types, phone normalization, domain errors
internal/domain/auth/          Auth token, session, signing-key, JWKS domain types
internal/application/register/ Registration use case and ports
internal/application/login/    Login, refresh-token, and login-session creation use case
internal/application/password/ Password reset and change-password use case
internal/application/settings/ Current-user settings and username update use case
internal/application/session/  Login-session listing, current session, token issue, revocation
internal/application/tokenmanager/ Raw refresh-token listing and revocation
internal/application/jwks/     Signing-key lifecycle, JWT issue/verify, public JWKS
internal/adapters/handler/     Gin HTTP handlers
internal/adapters/middleware/  CORS, auth, session, logging, recovery, 404/405
internal/adapters/dto/         HTTP request/response DTOs
internal/adapters/repository/  GORM PostgreSQL repositories and table records
internal/adapters/cache/       Redis stores and read-through caches
internal/adapters/token/       ES256 JWT/JWK implementation
internal/adapters/sms/         Wenova SMS adapter
internal/adapters/database/    PostgreSQL connection setup
internal/bootstrap/logging/    Zap logger setup
agents/                        Repo-local skills for coding agents
```

## 6. Architecture

The intended architecture is hexagonal.

```text
HTTP / Middleware / CLI
        |
        v
internal/application/<usecase>
        |
        v
internal/domain/<area>
        ^
        |
Postgres / Redis / SMS / Token adapters
```

### Dependency Rule

Dependencies point inward:

- `internal/domain` imports only standard-library or pure business dependencies.
- `internal/application` imports domain packages and defines ports close to use cases.
- `internal/adapters` imports application ports and domain types to implement infrastructure and delivery.
- `cmd/app` is the composition root that wires concrete adapters to application services.

### Domain Layer

Domain packages own business concepts:

- `user.User`
- `user.PendingRegistration`
- phone normalization
- user errors such as duplicate phone, duplicate username, invalid OTP
- `auth.AccessToken`
- `auth.TokenRecord`
- `auth.LoginSession`
- `auth.SigningKey`
- `auth.JWK`
- auth errors such as invalid credentials, token expired, token revoked

Domain packages must not contain:

- GORM tags
- table names
- Redis key names
- JSON DTO tags for HTTP responses
- Gin, GORM, Redis, Viper, or HTTP framework imports

### Application Layer

Application packages own orchestration:

- Validate use-case input.
- Normalize phone numbers and usernames.
- Check rate limits.
- Hash passwords and OTP codes.
- Call persistence, cache, SMS, and token ports.
- Decide transaction-like sequence and rollback behavior where needed.
- Return domain/application errors for handlers to map to HTTP.

Ports are defined close to the use case that owns them. For example, registration defines `UserStore`, `RegistrationStore`, and `OTPSender` in `internal/application/register`.

### Adapter Layer

Adapters own all I/O:

- HTTP handlers map JSON requests to application inputs and application outputs to DTOs.
- Middleware handles CORS, request logging, panic recovery, bearer-token auth, and session-cookie auth.
- Repositories map domain types to GORM row records.
- Redis stores serialize pending OTP state and cache read-heavy data.
- SMS adapter calls Wenova.
- Token adapter implements ES256 JWT signing, verification, and JWK conversion.

### Composition Root

`cmd/app/main.go` wires the service:

1. Load config.
2. Build logger.
3. Connect PostgreSQL.
4. Connect Redis.
5. Run GORM auto-migration for tables.
6. Create SMS client.
7. Create repositories and Redis caches.
8. Create ES256 codec and JWKS service.
9. Ensure an active signing key exists.
10. Create application services.
11. Create handlers and middleware.
12. Start the HTTP server and handle graceful shutdown.

## 7. Data Ownership

### PostgreSQL

PostgreSQL is the source of truth for:

- Accounts
- Raw refresh-token records
- Server-side login sessions
- ES256 signing keys

GORM row types live in `internal/adapters/repository`. The user domain model is mapped to the `accounts` table through an adapter-local `accountRecord`.

### Redis

Redis is used for short-lived and cacheable data:

- `register:ticket:<ticketId>` pending registration tickets
- password-reset ticket state
- OTP request and verification counters
- user cache by id, phone number, and username
- login-session list cache
- public signing-key cache

Private signing keys are not cached in Redis. Public JWKS and token verification paths use public key material only.

### SMS Provider

Wenova sends OTP messages for:

- Registration OTP
- Password reset OTP

The service writes pending OTP state before or around SMS delivery depending on the flow. Registration sends the OTP before saving the ticket. Password reset saves the ticket before SMS and deletes it if SMS delivery fails.

## 8. API Contract

All JSON request and response fields use camelCase.

Most API responses use this envelope:

```json
{
  "success": true,
  "code": "machine_readable_code",
  "message": "human readable message",
  "data": {}
}
```

Error responses use the same envelope without `data`:

```json
{
  "success": false,
  "code": "invalid_request_body",
  "message": "invalid request body"
}
```

### Authentication Types

Bearer-token endpoints require:

```text
Authorization: Bearer <accessToken>
```

Session endpoints require the configured session cookie:

```text
Cookie: ddone_session=<sessionToken>
```

Public endpoints do not require authentication.

## 9. API Reference

### Public

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Health check |
| `GET` | `/.well-known/jwks.json` | Public ES256 JWK set |
| `POST` | `/registrations` | Start phone registration |
| `POST` | `/registrations/resend` | Resend registration OTP |
| `POST` | `/registrations/verify` | Verify registration OTP and create account |
| `POST` | `/tokens` | Login with phone/password and return body tokens |
| `POST` | `/tokens/refresh` | Rotate refresh token and return new body tokens |
| `POST` | `/sessions` | Login with phone/password and set session cookie |
| `POST` | `/password-resets` | Start password reset OTP |
| `POST` | `/password-resets/resend` | Resend password reset OTP |
| `POST` | `/password-resets/verify` | Verify reset OTP and update password |

### Bearer Access Token

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/settings` | Current-user settings |
| `GET` | `/settings/me` | Current-user settings alias |
| `PATCH` | `/settings/username` | Update username |
| `POST` | `/settings/password` | Change password |
| `GET` | `/tokens` | List raw refresh-token records |
| `DELETE` | `/tokens/:tokenId` | Revoke one raw refresh token |
| `POST` | `/tokens/revoke-all` | Revoke all raw refresh tokens |

### Session Cookie

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/sessions/token` | Return current or refreshed session access token |
| `GET` | `/sessions` | List login sessions |
| `GET` | `/sessions/current` | Return current login session |
| `DELETE` | `/sessions/:sessionId` | Revoke one login session |
| `POST` | `/sessions/revoke-others` | Revoke all other login sessions |
| `POST` | `/sessions/revoke-all` | Revoke all login sessions |

## 10. Endpoint Details

### `GET /healthz`

Returns service health.

Example response:

```json
{
  "success": true,
  "code": "healthz_ok",
  "message": "service is healthy",
  "active": true,
  "serverTime": "2026-05-24T00:00:00Z"
}
```

### `POST /registrations`

Starts phone registration and sends a 6-digit OTP.

Request:

```json
{
  "phoneNumber": "+8562012345678",
  "password": "secretpass"
}
```

Success: `202 Accepted`

```json
{
  "success": true,
  "code": "register_otp_sent",
  "message": "otp sent successfully",
  "data": {
    "ticketId": "reg_abc123",
    "expiresAt": "2026-05-24T00:05:00Z",
    "otpLength": 6,
    "resendCooldownSeconds": 60,
    "remainingResendCount": 3
  }
}
```

Rules:

- Phone number is normalized to Lao mobile format.
- Password must be non-empty and is bcrypt hashed.
- OTP TTL is 5 minutes.
- One registration request per phone number per 5-minute window.
- Maximum resend count is 3.
- Resend cooldown is 60 seconds.
- Maximum invalid verification attempts is 5.

### `POST /registrations/resend`

Resends a registration OTP for an existing ticket.

Request:

```json
{
  "ticketId": "reg_abc123"
}
```

Success: `202 Accepted`

Response body matches `/registrations`.

### `POST /registrations/verify`

Verifies a registration OTP and creates the user.

Request:

```json
{
  "ticketId": "reg_abc123",
  "otpCode": "123456"
}
```

Success: `201 Created`

```json
{
  "success": true,
  "code": "register_verified",
  "message": "registration completed successfully",
  "data": {
    "id": "user-id",
    "username": "user_abcd12",
    "phoneNumber": "2012345678",
    "phoneVerifiedAt": "2026-05-24T00:00:00Z",
    "createdAt": "2026-05-24T00:00:00Z"
  }
}
```

### `POST /tokens`

Authenticates with phone number and password. Returns an access token plus raw refresh token in the JSON response body.

Request:

```json
{
  "phoneNumber": "+8562012345678",
  "password": "secretpass"
}
```

Success: `200 OK`

```json
{
  "success": true,
  "code": "login_succeeded",
  "message": "login completed successfully",
  "data": {
    "accessToken": "jwt",
    "tokenType": "Bearer",
    "expiresAt": "2026-05-24T00:15:00Z",
    "expiresIn": 900,
    "refreshToken": "opaque-refresh-token",
    "refreshExpiresAt": "2026-06-23T00:00:00Z"
  }
}
```

Rules:

- Refresh tokens are opaque random values.
- Only the token hash is stored.
- Refresh token records include lineage fields for replay detection.
- A successful login creates a root refresh-token record.

### `POST /tokens/refresh`

Rotates a raw refresh token.

Request:

```json
{
  "refreshToken": "opaque-refresh-token"
}
```

Success: `200 OK`

Response body matches `/tokens`.

Rules:

- The current refresh token is marked used and replaced.
- A replacement refresh token is created in the same lineage.
- Reuse of an already replaced token revokes the whole lineage and returns a replay error.
- Revoked or expired refresh tokens are rejected.

### `GET /tokens`

Lists raw refresh-token records for the authenticated user.

Auth:

```text
Authorization: Bearer <accessToken>
```

Success: `200 OK`

Each item includes:

- `id`
- `clientIp`
- `userAgent`
- `expiresAt`
- `lastUsedAt`
- `replacedAt`
- `revokedAt`
- `createdAt`

### `DELETE /tokens/:tokenId`

Revokes one raw refresh-token record owned by the authenticated user.

Auth:

```text
Authorization: Bearer <accessToken>
```

Success response is a message envelope.

### `POST /tokens/revoke-all`

Revokes all raw refresh-token records for the authenticated user.

Auth:

```text
Authorization: Bearer <accessToken>
```

### `POST /sessions`

Authenticates with phone number and password. Creates a database-backed login session and sets the configured `HttpOnly` cookie.

Request:

```json
{
  "phoneNumber": "+8562012345678",
  "password": "secretpass"
}
```

Success: `200 OK`

```json
{
  "success": true,
  "code": "login_session_created",
  "message": "login session created successfully",
  "data": {}
}
```

Cookie behavior:

- Cookie name defaults to `ddone_session`.
- Cookie path is `/`.
- Cookie is `HttpOnly`.
- `Secure`, `SameSite`, and max age are configurable.
- The raw session token is not returned in the body.

### `POST /sessions/token`

Returns the current access token stored in the login session. If the stored access token has expired but the login session is still active, the service issues a fresh access token, updates the session, and refreshes the cookie max age.

Auth:

```text
Cookie: ddone_session=<sessionToken>
```

Success: `200 OK`

```json
{
  "success": true,
  "code": "session_token_issued",
  "message": "session token issued successfully",
  "data": {
    "accessToken": "jwt",
    "tokenType": "Bearer",
    "expiresAt": "2026-05-24T00:15:00Z",
    "expiresIn": 900
  }
}
```

### `GET /sessions`

Lists login sessions for the current session user.

Auth:

```text
Cookie: ddone_session=<sessionToken>
```

Each item includes:

- `id`
- `clientIp`
- `userAgent`
- `currentAccessExpires`
- `createdAt`
- `revokedAt`

### `GET /sessions/current`

Returns the current login session.

Auth:

```text
Cookie: ddone_session=<sessionToken>
```

### `DELETE /sessions/:sessionId`

Revokes one login session owned by the current session user.

Auth:

```text
Cookie: ddone_session=<sessionToken>
```

### `POST /sessions/revoke-others`

Revokes all other login sessions for the current session user while keeping the current session active.

Auth:

```text
Cookie: ddone_session=<sessionToken>
```

### `POST /sessions/revoke-all`

Revokes all login sessions for the current session user.

Auth:

```text
Cookie: ddone_session=<sessionToken>
```

### `POST /password-resets`

Starts a password reset OTP flow.

Request:

```json
{
  "phoneNumber": "+8562012345678"
}
```

Success: `202 Accepted`

```json
{
  "success": true,
  "code": "password_reset_otp_sent",
  "message": "otp sent successfully",
  "data": {
    "ticketId": "pwd_abc123",
    "expiresAt": "2026-05-24T00:05:00Z",
    "otpLength": 6,
    "resendCooldownSeconds": 60,
    "remainingResendCount": 3
  }
}
```

Rules:

- OTP TTL is 5 minutes.
- One reset request per phone number per 5-minute window.
- Maximum resend count is 3.
- Resend cooldown is 60 seconds.
- Maximum invalid verification attempts is 5.
- Password reset cannot be started within 7 days of the last successful password reset or password change.

### `POST /password-resets/resend`

Resends a password-reset OTP.

Request:

```json
{
  "ticketId": "pwd_abc123"
}
```

Success response matches `/password-resets`.

### `POST /password-resets/verify`

Verifies the reset OTP, updates the password, and revokes existing raw refresh-token records and login sessions.

Request:

```json
{
  "ticketId": "pwd_abc123",
  "otpCode": "123456",
  "newPassword": "newsecretpass"
}
```

Success response is a message envelope.

Additional rule:

- Verification is rejected if the user's password was changed within the last 7 days.

### `GET /settings` and `GET /settings/me`

Returns the current authenticated user's profile and change metadata.

Auth:

```text
Authorization: Bearer <accessToken>
```

Success fields:

- `id`
- `username`
- `phoneNumber`
- `phoneVerifiedAt`
- `usernameChangedAt`
- `usernameCanChangeAt`
- `canChangeUsername`
- `canChangePassword`
- `passwordChangedAt`
- `createdAt`
- `updatedAt`

### `PATCH /settings/username`

Updates the username for the authenticated user.

Auth:

```text
Authorization: Bearer <accessToken>
```

Request:

```json
{
  "username": "new_name"
}
```

Rules:

- Username is lowercased and trimmed.
- Username length must be 3 to 50 characters.
- Allowed characters are `a-z`, `0-9`, and `_`.
- Username must be unique.
- Username can be changed once every 7 days.

### `POST /settings/password`

Changes the authenticated user's password after verifying the current password. A successful change revokes existing raw refresh-token records and login sessions.

Auth:

```text
Authorization: Bearer <accessToken>
```

Request:

```json
{
  "currentPassword": "secretpass",
  "newPassword": "newsecretpass"
}
```

Rules:

- Password change is rejected if the user's password was changed within the last 7 days.

### `GET /.well-known/jwks.json`

Returns public signing keys for access-token verification.

Success: `200 OK`

```json
{
  "keys": [
    {
      "kty": "EC",
      "use": "sig",
      "crv": "P-256",
      "alg": "ES256",
      "kid": "key-id",
      "x": "base64url-x",
      "y": "base64url-y"
    }
  ]
}
```

Response headers:

- `Cache-Control: public, max-age=300`
- `ETag: "<hash>"`

If `If-None-Match` matches the current ETag, the server returns `304 Not Modified`.

## 11. Business Logic

### Phone Normalization

Phone normalization lives in `internal/domain/user/phone.go`.

Accepted input examples include:

- `+8562012345678`
- `8562012345678`
- `008562012345678`
- `02012345678`
- `2012345678`

The normalized result must be 10 digits and start with `20`.

### Registration Flow

1. Normalize the phone number.
2. Require password.
3. Enforce phone-based registration rate limit.
4. Reject if the phone number is already registered.
5. Generate a unique username.
6. Hash the password with bcrypt.
7. Generate a 6-digit OTP.
8. Hash the OTP with the ticket ID.
9. Send the OTP by SMS.
10. Store pending registration state in Redis.
11. Return the registration ticket.

Verification:

1. Load pending registration state from Redis.
2. Reject expired, missing, or malformed ticket state.
3. Enforce invalid OTP attempt limit.
4. Recheck phone and username uniqueness.
5. Create the PostgreSQL account.
6. Delete ticket and verification counter state.

### Password Reset Flow

1. Normalize the phone number.
2. Enforce phone-based reset rate limit.
3. Load the user by phone number.
4. Reject if `PasswordChangedAt` is within the 7-day cooldown window.
5. Generate a 6-digit OTP and reset ticket.
6. Store reset ticket state in Redis.
7. Send OTP by SMS.
8. Return the reset ticket.

Verification:

1. Load reset ticket state.
2. Reject expired, missing, or malformed ticket state.
3. Enforce invalid OTP attempt limit.
4. Load the user by ID.
5. Reject if `PasswordChangedAt` is within the 7-day cooldown window.
6. Hash and store the new password.
7. Delete ticket and verification counter state.
8. Revoke raw refresh tokens with reason `password_reset`.
9. Revoke login sessions with reason `password_reset`.

### Login With Raw Refresh Token

1. Normalize phone number.
2. Load user by phone number.
3. Compare bcrypt password hash.
4. Issue ES256 access token.
5. Generate opaque refresh token and UUID record.
6. Store token hash, metadata, expiry, and lineage.
7. Return access token and raw refresh token.

Refresh:

1. Hash provided refresh token.
2. Load token record.
3. Reject replaced, revoked, or expired tokens.
4. Revoke lineage on refresh-token replay.
5. Load user and issue new access token.
6. Create replacement refresh-token record.
7. Mark current record used and replaced.
8. Return new access token and raw refresh token.

### Login Session Flow

1. Normalize phone number.
2. Authenticate password.
3. Issue ES256 access token.
4. Generate opaque session token and UUID session ID.
5. Store only the session token hash.
6. Store current access token and expiry in the session record.
7. Set `HttpOnly` session cookie.

Session token endpoint:

1. Authenticate session cookie in middleware.
2. Load current session.
3. Reject revoked or expired session.
4. Return existing access token if still active.
5. Issue and store a fresh access token if needed.
6. Extend login-session expiry only when a fresh access token is issued.

### JWKS And Signing Key Flow

Startup calls `EnsureActiveSigningKey`.

The JWKS service:

- Deletes expired signing keys.
- Ensures one active key exists.
- Pre-generates the next scheduled key.
- Uses PostgreSQL advisory locks so multiple app instances do not create duplicate key rings.
- Separates private signing-key reads from public key reads.
- Uses Redis to cache public key material only.

JWT behavior:

- Access tokens are ES256 compact JWTs.
- Header includes `alg=ES256`, `kid`, and `typ=JWT`.
- Claims include `iss`, `sub`, `aud`, `jti`, `iat`, `nbf`, `exp`, `userId`, and optional `phone_number`.
- Verification rejects invalid algorithm, missing key ID, wrong issuer, wrong audience, missing subject, missing JWT ID, invalid time claims, future scheduled keys, retired unpublished keys, malformed signatures, and high-S ECDSA signatures.

## 12. Security Model

### Passwords

- Passwords are bcrypt hashed.
- Password request fields require 8 to 72 characters at the HTTP binding layer.
- Password reset and password change revoke both raw refresh-token records and login sessions.

### OTP

- OTP values are 6 numeric digits.
- OTP values are not stored directly.
- OTP hashes include the ticket ID.
- Registration and password reset OTPs expire after 5 minutes.
- Invalid OTP attempts are rate limited and eventually invalidate the ticket.

### Tokens

- Access tokens are signed JWTs with ES256.
- Refresh tokens and session tokens are opaque random values.
- Only hashes of refresh tokens and session tokens are stored.
- Refresh token replay revokes the full token lineage.
- Login sessions store the current access token server-side.

### Cookies

- Session cookies are `HttpOnly`.
- `Secure` defaults to true in config defaults, but local `config/config.yaml` disables it for HTTP development.
- `SameSite=None` requires `Secure=true`.
- Browser clients using cookies across origins need explicit CORS origins and `DDONE_CORS_ALLOW_CREDENTIALS=true`.

### Signing Keys

- Private signing keys are stored in PostgreSQL.
- Private signing keys are required only for issuing JWTs.
- Public JWKS and token verification use public key material only.
- Redis signing-key cache stores public key material only.
- Public JWKS responses include ETag and `Cache-Control`.

## 13. Maintenance

### Daily Development

Use:

```bash
make test
make fmt
```

Run infrastructure as needed:

```bash
make infra-up
make infra-ps
make infra-logs
make infra-down
```

### Database

The app currently runs GORM `AutoMigrate` on startup for:

- `accounts`
- `auth_refresh_sessions`
- `auth_login_sessions`
- `auth_signing_keys`

The `pgcrypto` extension setup is external to runtime code and belongs to database provisioning.

For production, prefer explicit migration tooling before startup instead of relying only on runtime auto-migration.

### Redis

Redis state is safe to clear in local development, but clearing production Redis can affect:

- Pending registration tickets
- Pending password-reset tickets
- OTP counters
- Read-through cache hit rates

Clearing Redis does not delete accounts, refresh-token records, login sessions, or signing keys because those live in PostgreSQL.

### Signing-Key Rotation

Defaults:

- Rotation interval: `2160h`
- Retention window: `4320h`

The service keeps retired public keys published until retention ends so access tokens signed shortly before rotation can still verify.

Operational notes:

- All app instances should share the same PostgreSQL signing-key table.
- Redis public-key cache TTL should remain short enough that key publication changes propagate quickly.
- If signing keys are lost, existing access tokens cannot be verified and new signing keys must be generated.
- If private key material is suspected compromised, rotate keys and consider shortening access-token TTL or revoking dependent sessions/tokens at the application level.

### Token And Session Revocation

Revocation is represented by timestamps and reason strings.

Known reasons include:

- `refresh_token_replay`
- `password_reset`
- `password_changed`
- `token_revoked`
- `all_tokens_revoked`
- `session_revoked`
- `other_sessions_revoked`
- `all_sessions_revoked`

### Logging

Zap logging is configured under `internal/bootstrap/logging`.

Middleware logs HTTP requests and recovers panics. Avoid logging raw tokens, OTP codes, passwords, or private key material.

## 14. Testing

Run all tests:

```bash
go test ./...
```

Test coverage currently includes:

- Config validation
- DTO JSON field casing
- HTTP handler behavior
- Middleware auth, CORS, and recovery
- ES256 signing and verification
- JWKS key lifecycle
- Registration OTP flow and limits
- Login and refresh-token behavior
- Password reset and password change
- Login-session behavior
- Settings username behavior
- Token manager behavior

When adding behavior:

- Prefer application-level unit tests for business logic.
- Use handler tests for HTTP mapping and status codes.
- Add adapter tests when serialization, token verification, cache key behavior, or persistence mapping changes.

## 15. Postman

Postman assets live in:

- [postman/ddone-server-auth.postman_collection.json](/home/mrbarlus/coding/DDONE/ddone-server-auth/postman/ddone-server-auth.postman_collection.json)
- [postman/ddone-server-auth.local.postman_environment.json](/home/mrbarlus/coding/DDONE/ddone-server-auth/postman/ddone-server-auth.local.postman_environment.json)
- [docs/postman.md](/home/mrbarlus/coding/DDONE/ddone-server-auth/docs/postman.md)

Recommended manual flow:

1. Health check
2. Register
3. Verify registration OTP
4. Login with body tokens
5. Refresh token
6. Create login session
7. Get session access token
8. Forgot password
9. Verify password reset OTP
10. Login again
11. Change password
12. Settings
13. Update username
14. Token manager
15. Session manager
16. JWKS

## 16. Extension Rules

When adding a feature:

1. Put new orchestration in `internal/application/<usecase>`.
2. Define ports close to the use case that owns them.
3. Keep domain types free of framework, transport, cache, and persistence metadata.
4. Add HTTP request and response DTOs under `internal/adapters/dto`.
5. Keep handlers thin and dependent on application interfaces.
6. Put PostgreSQL records and GORM tags in `internal/adapters/repository`.
7. Put Redis keys and JSON cache shapes in `internal/adapters/cache`.
8. Put SMS or other external integrations under `internal/adapters`.
9. Wire concrete adapters only from `cmd/app`.
10. Update README, this document, Postman assets, and tests when behavior or API contracts change.

## 17. Known Architecture Work

The current structure is close to the target hexagonal shape, but these are good future improvements:

- Replace runtime GORM `AutoMigrate` with explicit migration tooling.
- Move route registration and server construction out of `cmd/app` if `cmd/app` grows beyond composition.
- Add repository integration tests with PostgreSQL for key migration and unique constraint behavior.
- Add a formal OpenAPI document generated from the DTO contract.
- Add operational metrics for OTP sends, login failures, token refreshes, session refreshes, and JWKS cache hits.
- Add administrative tooling for emergency signing-key rotation and token/session revocation.
