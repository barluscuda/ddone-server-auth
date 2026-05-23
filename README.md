# ddone-server-auth

`ddone-server-auth` is a Go auth service for DDONE. It currently provides:

- `GET /healthz`
- `POST /register`
- `POST /register/resend`
- `POST /register/verify`
- `POST /login`
- `POST /login/refresh`
- `POST /login/session`
- `POST /login/session/token`
- `GET /account/me`
- `GET /account/sessions`
- `GET /.well-known/jwks.json`

The service uses:

- `gin` for HTTP delivery
- `gorm` + PostgreSQL for persistent account storage
- `redis` for pending registration state and OTP counters
- Wenova SMS for OTP delivery
- `zap` for logging

## Architecture

The project is being shaped toward a hexagonal architecture:

- `internal/application` contains use cases and orchestration
- `internal/domain` contains business concepts and rules
- `internal/adapters` contains infrastructure and delivery code
- `cmd/app` is the composition root and HTTP bootstrap

Current note: some legacy persistence concerns still live under `internal/domain/account` through GORM tags and migration helpers. New work should move the codebase further toward pure domain types and outward-facing adapters.

## Project Layout

```text
cmd/app/                       Entry point and HTTP server wiring
config/                        Config loading and default values
internal/application/register/ Registration use case
internal/application/login/    Login and refresh use case
internal/application/jwks/     Signing-key and JWKS use case
internal/domain/account/       Account and registration domain models
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
DDONE_AUTH_SIGNING_KEY_ROTATION=2160h
DDONE_AUTH_SIGNING_KEY_RETENTION=4320h
DDONE_AUTH_SESSION_COOKIE_NAME=ddone_session
DDONE_AUTH_SESSION_COOKIE_SECURE=false
DDONE_AUTH_SESSION_COOKIE_SAME_SITE=lax
DDONE_AUTH_SESSION_COOKIE_MAX_AGE=876000h

DDONE_WENOVA_TOKEN=your-token
```

You can also supply:

- `DDONE_DATABASE_URL`
- `DDONE_REDIS_URL`

Safe defaults:

- `database.log_sql` defaults to `false`
- `auth.session_cookie_secure` defaults to `true`

For local HTTP development, set `DDONE_AUTH_SESSION_COOKIE_SECURE=false` and `DDONE_DATABASE_LOG_SQL=true` if useful. For list-based CORS environment variables, use comma-separated values. Browser clients using the session-login flow need `DDONE_CORS_ALLOW_CREDENTIALS=true` and explicit origins instead of `*`.

## API

### `GET /healthz`

Returns service health.

### `POST /register`

Starts phone registration and sends an OTP.

Example body:

```json
{
  "phoneNumber": "+8562012345678",
  "password": "secretpass"
}
```

### `POST /register/resend`

Resends the OTP for an existing registration ticket.

Example body:

```json
{
  "ticketId": "reg_abc123"
}
```

### `POST /register/verify`

Verifies the OTP and creates the account.

Example body:

```json
{
  "ticketId": "reg_abc123",
  "otpCode": "123456"
}
```

### `POST /login`

Authenticates a verified phone-number account and returns an ES256 access token plus a refresh token in the response body.

Example body:

```json
{
  "phoneNumber": "+8562012345678",
  "password": "secretpass"
}
```

### `POST /login/refresh`

Rotates the refresh token from the request body and returns a new access token plus a new refresh token in the response body.

Example body:

```json
{
  "refreshToken": "opaque-refresh-token"
}
```

### `POST /login/session`

Authenticates a verified phone-number account, creates a database-backed unlimited-lifetime login session, stores the JWT in server-side session state, and sets an `HttpOnly` session cookie. This route does not return access or session tokens in the response body.

Example body:

```json
{
  "phoneNumber": "+8562012345678",
  "password": "secretpass"
}
```

### `POST /login/session/token`

Reads the `HttpOnly` session cookie and returns the access token for that session. If the currently stored access token is still valid, the service returns it as-is. If it has expired, the service automatically issues and stores a fresh access token while keeping the login session itself active indefinitely.

### `GET /account/me`

Returns the account identity for the current authenticated user.

Headers:

```text
Authorization: Bearer <access-token>
```

### `GET /account/sessions`

Returns the current account's known login sessions.

Headers:

```text
Authorization: Bearer <access-token>
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
