# ddone-server-auth

`ddone-server-auth` is a Go auth service for DDONE. It currently provides:

- `GET /healthz`
- `POST /registrations`
- `POST /registrations/resend`
- `POST /registrations/verify`
- `POST /tokens`
- `GET /tokens`
- `POST /tokens/refresh`
- `DELETE /tokens/:tokenId`
- `POST /tokens/revoke-all`
- `POST /sessions`
- `GET /sessions`
- `POST /sessions/token`
- `GET /sessions/current`
- `DELETE /sessions/:sessionId`
- `POST /sessions/revoke-others`
- `POST /sessions/revoke-all`
- `POST /password-resets`
- `POST /password-resets/resend`
- `POST /password-resets/verify`
- `GET /settings`
- `GET /settings/me`
- `PATCH /settings/username`
- `POST /settings/password`
- `GET /.well-known/jwks.json`

The service uses:

- `gin` for HTTP delivery
- `gorm` + PostgreSQL for persistent user storage
- `redis` for pending registration state, password-reset state, OTP counters, and read-through caches
- Wenova SMS for OTP delivery
- `zap` for logging

## Architecture

The project is being shaped toward a hexagonal architecture:

- `internal/application` contains use cases and orchestration
- `internal/domain` contains business concepts and rules
- `internal/adapters` contains infrastructure and delivery code
- `cmd/app` is the composition root and HTTP bootstrap

Current note: some legacy persistence concerns still live under `internal/domain/user` through GORM tags on user models. Database migrations now live under `internal/adapters/repository`. New work should keep moving the codebase toward pure domain types and outward-facing adapters.

## Project Layout

```text
cmd/app/                       Entry point and HTTP server wiring
config/                        Config loading and default values
internal/application/register/ Registration use case
internal/application/login/    Login and refresh use case
internal/application/password/ Password reset and change-password use case
internal/application/settings/ Current authenticated-user settings view and username update use case
internal/application/session/  Login-session current/list/revocation use case
internal/application/tokenmanager/ Raw refresh-token listing and revocation use case
internal/application/jwks/     Signing-key and JWKS use case
internal/domain/user/       User and registration domain models
internal/domain/auth/          Auth tokens, sessions, and signing-key models
internal/adapters/cache/       Redis client and registration store
internal/adapters/database/    PostgreSQL connection setup
internal/adapters/repository/  GORM-backed repositories
internal/adapters/token/       ES256 signing and JWK helpers
internal/adapters/sms/         Wenova SMS adapter
internal/adapters/handler/     HTTP handlers
internal/adapters/middleware/  HTTP middleware
internal/bootstrap/logging/    Logger setup
agents/                        Repo-local skills
```

## Requirements

- Go `1.26.2`
- Docker and Docker Compose
- PostgreSQL
- Redis
- Wenova API token for real SMS delivery

## Local Development

Start infrastructure:

```bash
make infra-up
```

Run the service:

```bash
make run
```

Run tests:

```bash
make test
```

Format code:

```bash
make fmt
```

Stop infrastructure:

```bash
make infra-down
```

Postman assets:

- Collection: [postman/ddone-server-auth.postman_collection.json](/home/mrbarlus/coding/DDONE/ddone-server-auth/postman/ddone-server-auth.postman_collection.json)
- Environment template: [postman/ddone-server-auth.local.postman_environment.json](/home/mrbarlus/coding/DDONE/ddone-server-auth/postman/ddone-server-auth.local.postman_environment.json)
- Usage guide: [docs/postman.md](/home/mrbarlus/coding/DDONE/ddone-server-auth/docs/postman.md)

## Configuration

Configuration is loaded from:

1. `config/config.yaml`
2. environment variables with the `DDONE_` prefix
3. optional `.env`

Common environment variables:

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
DDONE_CORS_EXPOSED_HEADERS=
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

You can also supply:

- `DDONE_DATABASE_URL`
- `DDONE_REDIS_URL`

Safe defaults:

- `database.log_sql` defaults to `false`
- `auth.session_cookie_secure` defaults to `true`
- `auth.login_session_ttl` defaults to `720h`
- cache TTLs default to short read-through values for user, session-list, and signing-key lookups

`DDONE_AUTH_SESSION_COOKIE_MAX_AGE` is optional. If omitted or set to `0`, the cookie lifetime is derived from `DDONE_AUTH_LOGIN_SESSION_TTL`. If provided, it must not exceed the login-session TTL.

For local HTTP development, set `DDONE_AUTH_SESSION_COOKIE_SECURE=false` and `DDONE_DATABASE_LOG_SQL=true` if useful. For list-based CORS environment variables, use comma-separated values. Browser clients using the session-login flow need `DDONE_CORS_ALLOW_CREDENTIALS=true` and explicit origins instead of `*`.

## API

### `GET /healthz`

Returns service health.

### `POST /registrations`

Starts phone registration and sends an OTP.

Example body:

```json
{
  "phoneNumber": "+8562012345678",
  "password": "secretpass"
}
```

### `POST /registrations/resend`

Resends the OTP for an existing registration ticket.

Example body:

```json
{
  "ticketId": "reg_abc123"
}
```

### `POST /registrations/verify`

Verifies the OTP and creates the user.

Example body:

```json
{
  "ticketId": "reg_abc123",
  "otpCode": "123456"
}
```

### `POST /tokens`

Authenticates a verified phone-number user and returns an ES256 access token plus a refresh token in the response body.

Example body:

```json
{
  "phoneNumber": "+8562012345678",
  "password": "secretpass"
}
```

### `POST /tokens/refresh`

Rotates the refresh token from the request body and returns a new access token plus a new refresh token in the response body.

Example body:

```json
{
  "refreshToken": "opaque-refresh-token"
}
```

### `POST /sessions`

Authenticates a verified phone-number user, creates a database-backed login session with a configured expiry, stores the JWT in server-side session state, and sets an `HttpOnly` session cookie. This route does not return access or session tokens in the response body.

Example body:

```json
{
  "phoneNumber": "+8562012345678",
  "password": "secretpass"
}
```

### `POST /sessions/token`

Reads the `HttpOnly` session cookie and returns the access token for that session. If the currently stored access token is still valid, the service returns it as-is. If it has expired, the service automatically issues and stores a fresh access token while the login session itself is still within its configured TTL.

### `POST /password-resets`

Starts a phone-based password reset flow and sends an OTP.

Example body:

```json
{
  "phoneNumber": "+8562012345678"
}
```

### `POST /password-resets/resend`

Resends the password-reset OTP for an existing reset ticket.

Example body:

```json
{
  "ticketId": "pwd_abc123"
}
```

### `POST /password-resets/verify`

Verifies the password-reset OTP, updates the user password, and revokes existing login sessions and raw token records.

Example body:

```json
{
  "ticketId": "pwd_abc123",
  "otpCode": "123456",
  "newPassword": "newsecretpass"
}
```

### `GET /settings`

Returns the current authenticated user profile plus change metadata, including username cooldown state.

Headers:

```text
Authorization: Bearer <access-token>
```

Response data includes `id`, `username`, `phoneNumber`, `phoneVerifiedAt`, `canChangeUsername`, optional `usernameChangedAt`, optional `usernameCanChangeAt`, optional `passwordChangedAt`, `createdAt`, and `updatedAt`.

### `GET /settings/me`

Returns the same response as `GET /settings`.

Headers:

```text
Authorization: Bearer <access-token>
```

### `GET /tokens`

Returns the current user's raw refresh-token sessions.

Headers:

```text
Authorization: Bearer <access-token>
```

### `DELETE /tokens/:tokenId`

Revokes a specific raw refresh-token session owned by the current authenticated user.

Headers:

```text
Authorization: Bearer <access-token>
```

### `POST /tokens/revoke-all`

Revokes all raw refresh-token sessions owned by the current authenticated user.

Headers:

```text
Authorization: Bearer <access-token>
```

### `GET /sessions`

Returns the current user's known login sessions.

Headers:

```text
Authorization: Bearer <access-token>
```

### `GET /sessions/current`

Returns the current login session associated with the authenticated access token.

Headers:

```text
Authorization: Bearer <access-token>
```

### `PATCH /settings/username`

Updates the username for the current authenticated user.

Headers:

```text
Authorization: Bearer <access-token>
```

Example body:

```json
{
  "username": "new_name"
}
```

### `DELETE /sessions/:sessionId`

Revokes a specific login session owned by the current authenticated user.

Headers:

```text
Authorization: Bearer <access-token>
```

### `POST /sessions/revoke-others`

Revokes all other login sessions while keeping the current session active.

Headers:

```text
Authorization: Bearer <access-token>
```

### `POST /sessions/revoke-all`

Revokes all login sessions owned by the current authenticated user.

Headers:

```text
Authorization: Bearer <access-token>
```

### `POST /settings/password`

Changes the password for the current authenticated user after verifying the current password. A successful change revokes existing login sessions and raw token records.

Headers:

```text
Authorization: Bearer <access-token>
```

Example body:

```json
{
  "currentPassword": "secretpass",
  "newPassword": "newsecretpass"
}
```

### `GET /.well-known/jwks.json`

Returns the public JWK set for access-token verification. During normal rotation this can include the current signing key, the next pre-published key, and recently retired verification keys until their retention window ends.

## Development Direction

When extending this service, prefer:

- pure domain types without framework or ORM tags
- application use cases that depend on ports
- thin HTTP handlers
- outbound adapters for Postgres, Redis, and SMS
- migrations and persistence mapping outside the domain layer
