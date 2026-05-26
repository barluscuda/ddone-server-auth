# ddone-server-auth

`ddone-server-auth` is a Go auth service for DDONE. It currently provides:

- `GET /healthz`
- `GET /robots.txt`
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
- `redis` for pending registration state, password-reset state, OTP counters, login rate-limit counters, and read-through caches
- Wenova SMS for OTP delivery
- `zap` for logging
- optional DexBotKiller passive registration abuse signal recording

## Documentation

- [Full API reference](docs/api.md)
- [JWT integration guide](docs/jwt.md)

## Architecture

The project is being shaped toward a hexagonal architecture:

- `internal/application` contains use cases and orchestration
- `internal/domain` contains business concepts and rules
- `internal/adapters` contains infrastructure and delivery code
- `cmd/app` is the composition root and HTTP bootstrap

Domain types are kept free of transport and persistence metadata. Database row shapes, GORM tags, Redis JSON payloads, and migration helpers live in adapters.

## Project Layout

```text
cmd/app/                       Entry point and HTTP server wiring
config/                        Config loading and default values
db/init/                       Local PostgreSQL initialization scripts
internal/application/register/ Registration use case
internal/application/dexbotkiller/ Passive bot-risk scoring and HMAC keying
internal/application/login/    Login and refresh use case
internal/application/password/ Password reset and change-password use case
internal/application/settings/ Current authenticated-user settings view and username update use case
internal/application/session/  Login-session current/list/revocation use case
internal/application/tokenmanager/ Raw refresh-token listing and revocation use case
internal/application/jwks/     Signing-key and JWKS use case
internal/domain/user/       User and registration domain models
internal/domain/auth/          Auth tokens, sessions, and signing-key models
internal/adapters/cache/       Redis client, use-case stores, and DexBotKiller store
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
- PostgreSQL with the `pgcrypto` extension enabled
- Redis
- Wenova API token for real SMS delivery

Docker Compose enables `pgcrypto` through [db/init/001_pgcrypto.sql](https://github.com/barluscuda/ddone-server-auth/blob/main/db/init/001_pgcrypto.sql) when the PostgreSQL data volume is created. For an existing local volume, run the SQL manually or recreate the volume before starting the service. For external PostgreSQL instances, enable it once in the target database:

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
```

## Local Development

Start infrastructure:

```bash
make infra-up
```

Run the full stack with Docker Compose:

```bash
make compose-up
```

Build the image explicitly when needed:

```bash
make compose-build
make compose-up-build
```

`docker-compose.yml` runs the app, PostgreSQL, and Redis together. `docker-infra.yml` remains available for infra-only local development.
`make compose-up` starts the stack from the existing image and does not rebuild on each boot.
In the full-stack compose file, only `ddone-server-auth` is exposed to the host; Postgres and Redis stay on the internal `ddone-network`.
The app service explicitly imports runtime variables from `.env` through `env_file`, and Docker Compose also reads `.env` for `${...}` interpolation.

Run the service:

```bash
make run
```

Run tests:

```bash
make test
```

Build the production binary:

```bash
make build
```

Build release zip bundles for Linux `amd64`, Linux `arm64`, and Docker:

```bash
make release
```

Override the release version when needed:

```bash
make release RELEASE_VERSION=v1.0.0
```

Release artifacts are written to `dist/`:

- `ddone-server-auth_<version>_linux-x86_64.zip`
- `ddone-server-auth_<version>_linux-arm64.zip`
- `ddone-server-auth_<version>_docker.zip`

The binary release bundles include:

- `.env.example` for custom environment overrides
- `start.sh` to run the service directly from the extracted release directory
- `systemctl.sh install` to install and start the systemd service
- `systemctl.sh remove` to stop and remove the systemd service files
- `REMOVE_DATA=1 ./systemctl.sh remove` to also remove app and environment directories

The Docker release bundle includes a saved local Docker image, `docker-compose.yml`, `.env.example`, `config/config.yaml`, `db/init/`, and `docker-load.sh`, `docker-up.sh`, and `docker-down.sh`. Its compose file runs the app from the local loaded image with `pull_policy: never`; it does not build from source.

Set `DOCKER_RELEASE=0` for binary-only release builds.

Build the Docker image:

```bash
docker build -t barluscuda/ddone-server-auth .
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

- Collection: [postman/ddone-server-auth.postman_collection.json](https://github.com/barluscuda/ddone-server-auth/blob/main/postman/ddone-server-auth.postman_collection.json)
- Environment template: [postman/ddone-server-auth.local.postman_environment.json](https://github.com/barluscuda/ddone-server-auth/blob/main/postman/ddone-server-auth.local.postman_environment.json)
- Usage guide: [docs/postman.md](https://github.com/barluscuda/ddone-server-auth/blob/main/docs/postman.md)
- Full project handbook: [docs/project.md](https://github.com/barluscuda/ddone-server-auth/blob/main/docs/project.md)

## systemd

Repo-provided systemd assets:

- Unit file: [deploy/systemd/ddone-server-auth.service](https://github.com/barluscuda/ddone-server-auth/blob/main/deploy/systemd/ddone-server-auth.service)
- Environment template: [.env.example](https://github.com/barluscuda/ddone-server-auth/blob/main/.env.example)

Expected install layout:

- Binary: `/usr/local/bin/ddone-server-auth`
- Working directory: `/opt/ddone-server-auth`
- Environment file: `/etc/ddone-server-auth/ddone-server-auth.env`

Suggested install flow:

```bash
sudo useradd --system --home /opt/ddone-server-auth --shell /usr/sbin/nologin ddone
sudo mkdir -p /opt/ddone-server-auth/config /etc/ddone-server-auth
make build
sudo install -m 0755 ./ddone-server-auth /usr/local/bin/ddone-server-auth
sudo cp -R ./config/. /opt/ddone-server-auth/config/
sudo install -m 0644 ./deploy/systemd/ddone-server-auth.service /etc/systemd/system/ddone-server-auth.service
sudo install -m 0640 ./.env.example /etc/ddone-server-auth/ddone-server-auth.env
sudo chown -R ddone:ddone /opt/ddone-server-auth /etc/ddone-server-auth
sudo systemctl daemon-reload
sudo systemctl enable --now ddone-server-auth
```

Equivalent Makefile targets:

```bash
make systemd-install
make systemd-enable
make systemd-start
```

One-shot bootstrap:

```bash
make systemd-bootstrap
```

Useful commands:

```bash
make systemd-status
make systemd-logs
make systemd-restart
```

Useful overrides:

```bash
make systemd-install SERVICE_USER=authsvc SERVICE_GROUP=authsvc APP_DIR=/srv/ddone-auth
```

## Configuration

Configuration is loaded from:

1. `config/config.yaml` for service defaults
2. environment variables with the `DDONE_` prefix for custom overrides
3. optional `.env` for local custom overrides

In `config/config.yaml`, most security-related settings are grouped under `security:`. DexBotKiller uses its own top-level `dexbotkiller:` section because it has separate rollout and cookie settings.
Use `.env.example` as the custom config template. Systemd installs copy this file to `/etc/ddone-server-auth/ddone-server-auth.env` when that file does not already exist.

Common environment variables:

```bash
DDONE_APP_PORT=3000
DDONE_APP_DEBUG=true
DDONE_APP_TRUSTED_PROXIES=
DDONE_APP_MAX_REQUEST_BODY_BYTES=1048576

DDONE_DATABASE_HOST=localhost
DDONE_DATABASE_PORT=5432
DDONE_DATABASE_NAME=ddone_auth
DDONE_DATABASE_USERNAME=postgres
DDONE_DATABASE_PASSWORD=postgres
DDONE_DATABASE_SSLMODE=disable
DDONE_DATABASE_LOG_SQL=true

DDONE_REDIS_HOST=localhost
DDONE_REDIS_PORT=6380
DDONE_REDIS_DB=0

DDONE_CACHE_USER_TTL=5m
DDONE_CACHE_USER_SESSION_LIST_TTL=1m
DDONE_CACHE_SIGNING_KEYS_TTL=1m

DDONE_DEXBOTKILLER_ENABLED=false
DDONE_DEXBOTKILLER_MODE=passive
DDONE_DEXBOTKILLER_REDIS_PREFIX=dbk:v1
DDONE_DEXBOTKILLER_PEPPER=
DDONE_DEXBOTKILLER_COUNTER_WINDOW=1m
DDONE_DEXBOTKILLER_UNIQUE_WINDOW=15m
DDONE_DEXBOTKILLER_SCORE_TTL=24h
DDONE_DEXBOTKILLER_DELAY=500ms
DDONE_DEXBOTKILLER_THRESHOLDS_DELAY_SCORE=3
DDONE_DEXBOTKILLER_THRESHOLDS_CHALLENGE_SCORE=6
DDONE_DEXBOTKILLER_THRESHOLDS_BLOCK_SCORE=10
DDONE_DEXBOTKILLER_CLOUDFLARE_TURNSTILE_SITE_KEY=
DDONE_DEXBOTKILLER_CLOUDFLARE_TURNSTILE_SECRET_KEY=
DDONE_DEXBOTKILLER_CLOUDFLARE_TURNSTILE_VERIFY_URL=https://challenges.cloudflare.com/turnstile/v0/siteverify
DDONE_DEXBOTKILLER_CLOUDFLARE_TURNSTILE_TIMEOUT=3s
DDONE_DEXBOTKILLER_DEVICE_COOKIE_NAME=ddone_device
DDONE_DEXBOTKILLER_DEVICE_COOKIE_MAX_AGE=720h
DDONE_DEXBOTKILLER_DEVICE_COOKIE_SECURE=false
DDONE_DEXBOTKILLER_DEVICE_COOKIE_SAME_SITE=lax

DDONE_SECURITY_LOGIN_FAILED_ATTEMPT_WINDOW=5m
DDONE_SECURITY_LOGIN_MAX_ATTEMPTS=5
DDONE_SECURITY_LOGIN_LOCKOUT_DURATION=15m

DDONE_SECURITY_OTP_REGISTER_TTL=5m
DDONE_SECURITY_OTP_REGISTER_PHONE_WINDOW=5m
DDONE_SECURITY_OTP_REGISTER_SYSTEM_WINDOW=10m
DDONE_SECURITY_OTP_REGISTER_RESEND_COOLDOWN=60s
DDONE_SECURITY_OTP_REGISTER_VERIFY_ATTEMPT_WINDOW=5m
DDONE_SECURITY_OTP_REGISTER_MAX_PHONE_REQUESTS=1
DDONE_SECURITY_OTP_REGISTER_MAX_SYSTEM_REQUESTS=30
DDONE_SECURITY_OTP_REGISTER_MAX_RESENDS=3
DDONE_SECURITY_OTP_REGISTER_MAX_VERIFY_ATTEMPTS=5
DDONE_SECURITY_OTP_PASSWORD_RESET_TTL=5m
DDONE_SECURITY_OTP_PASSWORD_RESET_PHONE_WINDOW=5m
DDONE_SECURITY_OTP_PASSWORD_RESET_RESEND_COOLDOWN=60s
DDONE_SECURITY_OTP_PASSWORD_RESET_VERIFY_ATTEMPT_WINDOW=5m
DDONE_SECURITY_OTP_PASSWORD_RESET_MAX_PHONE_REQUESTS=1
DDONE_SECURITY_OTP_PASSWORD_RESET_MAX_RESENDS=3
DDONE_SECURITY_OTP_PASSWORD_RESET_MAX_VERIFY_ATTEMPTS=5

DDONE_CORS_ALLOWED_ORIGINS=http://localhost:5173
DDONE_CORS_ALLOWED_METHODS=GET,POST,OPTIONS
DDONE_CORS_ALLOWED_HEADERS=Origin,Content-Type,Accept,Authorization
DDONE_CORS_EXPOSED_HEADERS=
DDONE_CORS_ALLOW_CREDENTIALS=false
DDONE_CORS_MAX_AGE=12h

DDONE_SECURITY_AUTH_ISSUER=ddone-server-auth
DDONE_SECURITY_AUTH_AUDIENCE=ddone-clients
DDONE_SECURITY_AUTH_ACCESS_TOKEN_TTL=5m
DDONE_SECURITY_AUTH_REFRESH_TOKEN_TTL=720h
DDONE_SECURITY_AUTH_LOGIN_SESSION_TTL=720h
DDONE_SECURITY_AUTH_SIGNING_KEY_ROTATION=2160h
DDONE_SECURITY_AUTH_SIGNING_KEY_RETENTION=4320h
DDONE_SECURITY_AUTH_SESSION_COOKIE_NAME=ddone_session
DDONE_SECURITY_AUTH_SESSION_COOKIE_SECURE=false
DDONE_SECURITY_AUTH_SESSION_COOKIE_SAME_SITE=lax
DDONE_SECURITY_AUTH_SESSION_COOKIE_MAX_AGE=720h

DDONE_WENOVA_TOKEN=your-token
```

Safe defaults:

- `database.log_sql` defaults to `false`
- `security.auth.session_cookie_secure` defaults to `true`
- `security.auth.login_session_ttl` defaults to `720h`
- `app.trusted_proxies` defaults to empty, so forwarded client-IP headers are ignored unless explicit proxy CIDRs are configured
- `app.max_request_body_bytes` defaults to `1048576`
- `dexbotkiller.enabled` defaults to `false`; when enabled, `DDONE_DEXBOTKILLER_PEPPER` is required and passive mode records registration abuse signals without changing responses
- DexBotKiller `challenge` and `enforce` modes require Cloudflare Turnstile site and secret keys; clients resubmit challenged registration requests with `turnstileToken`
- login rate limiting defaults to `5` failed attempts per `5m` window, followed by a `15m` account lock
- OTP flow limits default to the values shown in `config/config.yaml`
- cache TTLs default to short read-through values for user, session-list, and signing-key lookups

`DDONE_SECURITY_AUTH_SESSION_COOKIE_MAX_AGE` is optional. If omitted or set to `0`, the cookie lifetime is derived from `DDONE_SECURITY_AUTH_LOGIN_SESSION_TTL`. If provided, it must not exceed the login-session TTL.

For local HTTP development, set `DDONE_SECURITY_AUTH_SESSION_COOKIE_SECURE=false` and `DDONE_DATABASE_LOG_SQL=true` if useful. For list-based CORS and trusted proxy environment variables, use comma-separated values. Browser clients using the session-login flow need `DDONE_CORS_ALLOW_CREDENTIALS=true` and explicit origins instead of `*`; unsafe session-cookie requests also reject untrusted `Origin` or `Referer` values.

## API

### `GET /healthz`

Returns service health.

### `GET /robots.txt`

Returns a restrictive robots policy for this API service.

Response:

```text
User-agent: *
Disallow: /
```

### `POST /registrations`

Starts phone registration and sends an OTP.

Example body:

```json
{
  "phoneNumber": "+8562012345678",
  "password": "secretpass",
  "turnstileToken": "optional-cloudflare-turnstile-token"
}
```

### `POST /registrations/resend`

Resends the OTP for an existing registration ticket.

Example body:

```json
{
  "ticketId": "reg_abc123",
  "turnstileToken": "optional-cloudflare-turnstile-token"
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
Failed login attempts are rate limited per normalized phone number.

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

Reads the `HttpOnly` session cookie and returns the access token for that session. If the currently stored access token is still valid, the service returns it as-is. If it has expired, the service automatically issues and stores a fresh access token while the login session itself is still within its configured TTL. Sessions are revoked by inactivity: if no fresh access token is issued within the configured session TTL, the session expires. Only when a fresh access token is issued does the endpoint extend the stored session expiry and re-send the same session cookie value so the browser cookie age is refreshed without changing the underlying session ID. It is authorized by the session cookie, not the `Authorization` header.

### `POST /password-resets`

Starts a phone-based password reset flow and sends an OTP.

This endpoint is blocked for 7 days after the last successful password reset or password change.

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

This endpoint is also blocked if the user's password was changed within the previous 7 days.

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

Response data includes `id`, `username`, `phoneNumber`, `phoneVerifiedAt`, `canChangeUsername`, `canChangePassword`, optional `usernameChangedAt`, optional `usernameCanChangeAt`, optional `passwordChangedAt`, `createdAt`, and `updatedAt`.

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
Cookie: ddone_session=<session-token>
```

### `GET /sessions/current`

Returns the current login session associated with the authenticated session cookie.

Headers:

```text
Cookie: ddone_session=<session-token>
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
Cookie: ddone_session=<session-token>
```

### `POST /sessions/revoke-others`

Revokes all other login sessions while keeping the current session active.

Headers:

```text
Cookie: ddone_session=<session-token>
```

### `POST /sessions/revoke-all`

Revokes all login sessions owned by the current authenticated user.

Headers:

```text
Cookie: ddone_session=<session-token>
```

### `POST /settings/password`

Changes the password for the current authenticated user after verifying the current password. A successful change revokes existing login sessions and raw token records.

This endpoint is blocked for 7 days after the last successful password reset or password change.

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
