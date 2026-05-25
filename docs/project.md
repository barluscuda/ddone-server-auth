# ddone-server-auth Project Handbook

Last reviewed against the repository on 2026-05-25.

This handbook is the source-of-truth engineering overview for `ddone-server-auth`. Keep it aligned with code changes that affect architecture, dependencies, routes, config, storage, security behavior, startup wiring, or business flows.

## 1. Service Summary

`ddone-server-auth` is a Go authentication service for DDONE. It owns phone-based account registration, password login, raw refresh-token rotation, server-side browser sessions, password reset, user settings, ES256 JWT access-token issuing and verification, and public JWKS publication.

The service is moving toward hexagonal architecture:

- `internal/domain` holds persistence-free business types and domain errors.
- `internal/application` holds use cases, orchestration, and ports.
- `internal/adapters` holds HTTP, PostgreSQL, Redis, SMS, DTO, middleware, and token codec adapters.
- `cmd/app` is the composition root and process entrypoint.

## 2. Runtime Responsibilities

- Serve health and robots endpoints.
- Register users by phone number with OTP verification.
- Authenticate users with phone number and password.
- Issue ES256 JWT access tokens.
- Issue, rotate, list, and revoke opaque raw refresh tokens.
- Create and manage database-backed login sessions transported by `HttpOnly` cookies.
- Return current or refreshed access tokens for active login sessions.
- Reset forgotten passwords with OTP verification.
- Change authenticated-user passwords.
- Revoke refresh tokens and login sessions after password reset or password change.
- Publish public ES256 JWK sets at `/.well-known/jwks.json`.
- Run request body limits, bot protection, OTP spam detection, CORS, request logging, panic recovery, auth, session, no-route, and no-method middleware.

## 3. Main Dependencies

- Go `1.26.2`
- Gin for HTTP delivery
- GORM for PostgreSQL persistence
- PostgreSQL 17 in local Docker, with `pgcrypto` for UUID generation
- Redis 7 for pending OTP state, counters, scores, and read-through caches
- Wenova SMS API for OTP delivery
- Zap for structured logging
- Viper and godotenv for config
- bytedance/sonic for JSON in token/cache helpers

## 4. Project Layout

```text
cmd/app/                         Process entrypoint, dependency wiring, HTTP server
config/                          Config loading, defaults, validation
db/init/                         PostgreSQL init SQL for local Docker volumes
deploy/release/                  Release helper scripts included in zip bundles
deploy/systemd/                  systemd unit and environment template
docs/                            Project, API, JWT, and Postman docs
postman/                         Postman collection and local environment
scripts/                         Release build automation
agents/                          Repo-local agent skill guidance

internal/domain/user/            User model, phone normalization, user errors
internal/domain/auth/            Access-token, refresh-token, session, signing-key, JWKS types

internal/application/register/   Registration OTP use case
internal/application/login/      Password login, refresh-token rotation, session login creation
internal/application/password/   Password reset and authenticated password change
internal/application/settings/   Current-user settings and username update
internal/application/session/    Login-session listing, current view, token refresh, revocation
internal/application/tokenmanager/ Refresh-token listing and revocation
internal/application/jwt/        Access-token issuing and verification orchestration
internal/application/jwks/       Signing-key lifecycle and public JWKS orchestration
internal/application/otp/        Shared OTP policy values

internal/adapters/handler/       Gin HTTP handlers
internal/adapters/middleware/    Body limits, bot protection, OTP spam detection, CORS, auth, session, logging, recovery, 404/405
internal/adapters/dto/           HTTP request/response DTOs
internal/adapters/repository/    GORM repositories and table row types
internal/adapters/cache/         Redis stores and read-through cache decorators
internal/adapters/token/         ES256 JWT/JWK codec
internal/adapters/sms/           Wenova SMS adapter
internal/adapters/database/      PostgreSQL connection setup

internal/bootstrap/logging/      Zap logger setup
```

## 5. Architecture Rules

Dependencies point inward:

- Domain imports no adapters, GORM, Redis, Gin, HTTP DTOs, migrations, or transport metadata.
- Application imports domain and defines use-case-owned ports.
- Adapters import application ports and domain types to implement delivery and infrastructure.
- `cmd/app` wires concrete adapters to application services.

Use-case orchestration belongs in `internal/application/<usecase>`. HTTP request parsing and response mapping belongs in handlers and DTOs. PostgreSQL rows, Redis shapes, and SMS/JWT implementation details belong in adapters.

## 6. Application Package Ownership

### `internal/application/register`

Owns phone registration:

- Normalize and validate phone numbers.
- Reject already registered phone numbers.
- Generate default usernames.
- Hash passwords and OTP codes.
- Enforce OTP phone-window, resend, cooldown, and verify-attempt flow limits.
- Store pending registrations in Redis through a port.
- Send OTP through an SMS port.
- Create users after successful OTP verification.

### `internal/application/login`

Owns password login, refresh-token rotation, and session-login creation:

- Normalize phone numbers.
- Enforce login failed-attempt counters and lockouts.
- Verify bcrypt password hashes.
- Request access tokens through `jwt.Issuer`.
- Generate opaque refresh tokens and session tokens.
- Store only token hashes.
- Detect refresh-token replay and revoke the affected token lineage.
- Create login-session records for cookie-based login.

### `internal/application/jwt`

Owns JWT access-token orchestration:

- Ensures issuance uses the active signing key supplied by `jwks.SigningKeyProvider`.
- Builds access-token claims using configured issuer, audience, and access-token TTL.
- Generates JWT IDs.
- Verifies access tokens using public signing-key material from `SigningKeyReader`.
- Delegates ES256 signing and verification mechanics to the token adapter.

Login and session use `jwt.Issuer`. Auth middleware uses `jwt.Verifier`.

### `internal/application/jwks`

Owns signing-key lifecycle and public JWKS:

- Deletes expired signing keys.
- Ensures an active signing key exists.
- Pre-generates the next scheduled key.
- Uses a PostgreSQL advisory lock through the signing-key store port to avoid duplicate key-ring creation across instances.
- Publishes only public key material for JWKS.

JWKS no longer issues or verifies access tokens. That responsibility belongs to `internal/application/jwt`.

### `internal/application/session`

Owns server-side login-session workflows:

- List a user's sessions.
- Return the current session.
- Return the stored access token if still valid.
- Issue and persist a fresh access token when the stored one expired but the login session remains active.
- Revoke one session, all other sessions, or all sessions for a user.

### `internal/application/tokenmanager`

Owns refresh-token management for authenticated users:

- List refresh-token records for the current user.
- Revoke one refresh-token record.
- Revoke all refresh-token records for the current user.

### `internal/application/password`

Owns password reset and password change:

- Start password reset by phone number.
- Resend password-reset OTP.
- Verify OTP and update password.
- Enforce password-reset OTP phone-window, resend, cooldown, and verify-attempt flow limits.
- Verify current password for authenticated password changes.
- Revoke refresh tokens and login sessions after password reset or password change.

### `internal/application/settings`

Owns current-user settings:

- Read the authenticated user's settings.
- Update username.
- Enforce username change cooldown behavior through the user domain model.

## 7. HTTP API

All JSON request and response fields use camelCase. Most responses use:

```json
{
  "success": true,
  "code": "machine_readable_code",
  "message": "human readable message",
  "data": {}
}
```

Errors use the same envelope without `data`.

### Public Routes

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Process health |
| `GET` | `/robots.txt` | Restrictive robots policy |
| `GET` | `/.well-known/jwks.json` | Public ES256 JWK set |
| `POST` | `/registrations` | Start phone registration and send OTP |
| `POST` | `/registrations/resend` | Resend registration OTP |
| `POST` | `/registrations/verify` | Verify registration OTP and create account |
| `POST` | `/tokens` | Password login with response-body access and refresh tokens |
| `POST` | `/tokens/refresh` | Rotate refresh token and return new body tokens |
| `POST` | `/sessions` | Password login with `HttpOnly` session cookie |
| `POST` | `/password-resets` | Start password-reset OTP |
| `POST` | `/password-resets/resend` | Resend password-reset OTP |
| `POST` | `/password-resets/verify` | Verify reset OTP and update password |

### Bearer Access-Token Routes

These routes require `Authorization: Bearer <accessToken>`.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/settings` | Current-user settings |
| `GET` | `/settings/me` | Current-user settings alias |
| `PATCH` | `/settings/username` | Update username |
| `POST` | `/settings/password` | Change password |
| `GET` | `/tokens` | List refresh-token records |
| `DELETE` | `/tokens/:tokenId` | Revoke one refresh-token record |
| `POST` | `/tokens/revoke-all` | Revoke all refresh-token records |

### Session Cookie Routes

These routes require the configured session cookie, default `ddone_session`.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/sessions/token` | Return current or refreshed session access token |
| `GET` | `/sessions` | List login sessions |
| `GET` | `/sessions/current` | Return current login session |
| `DELETE` | `/sessions/:sessionId` | Revoke one login session |
| `POST` | `/sessions/revoke-others` | Revoke all other login sessions |
| `POST` | `/sessions/revoke-all` | Revoke all login sessions |

Full endpoint examples and common error codes live in `docs/api.md`.

## 8. Authentication Model

### Access Tokens

- Access tokens are compact JWTs signed with ES256 on P-256.
- Access tokens are transported as bearer tokens.
- Default TTL is `5m`.
- Header includes `alg=ES256`, `kid`, and `typ=JWT`.
- Claims include `iss`, `sub`, `aud`, `jti`, `iat`, `nbf`, `exp`, `userId`, and optional `phone_number`.
- Verification rejects malformed tokens, unsupported algorithm, missing key ID, unpublished/future/retired keys, bad signatures, high-S ECDSA signatures, wrong issuer, wrong audience, missing subject, missing JWT ID, and invalid time claims.

Downstream verification guidance lives in `docs/jwt.md`.

### Refresh Tokens

- Refresh tokens are opaque random values returned by body-token login and refresh.
- Only SHA-256 hashes are stored.
- Refresh rotates on every use.
- Rotation marks the current record used and replaced, then creates a replacement record linked to the same root lineage.
- Reuse of a replaced refresh token is treated as replay and revokes the lineage.

### Login Sessions

- Session login creates an opaque random session token.
- The token is transported in an `HttpOnly` cookie.
- Only the session-token hash is stored.
- Login sessions store the current access token and its expiry.
- `/sessions/token` returns the stored access token if still valid.
- If the stored access token expired but the session is valid, `/sessions/token` issues a fresh access token, updates the session record, and refreshes the cookie max age.

## 9. Security And Policy Rules

### Passwords

- Password request fields are required to be 8 to 72 characters at the HTTP binding layer.
- Password hashes are produced with bcrypt.
- Password reset and authenticated password change revoke all refresh tokens and login sessions for the user.

### OTP

- OTPs are 6 numeric digits.
- OTPs are not stored directly.
- OTP hashes include the ticket ID.
- Registration and password reset use separate OTP policies.
- Default OTP TTL is `5m`.
- Default system-wide registration start limit is `30` requests per `10m`.
- OTP spam detection runs in middleware before OTP handlers.
- The middleware classifies OTP clients as likely user, suspicious, or likely bot from request metadata and body shape without storing raw request bodies.
- Bot-like signals such as automation user agents, missing user agents, malformed OTP fields, and unexpected content types add risk to the request's IP score.
- Likely browser traffic with normal JSON headers gets a lower request score.
- Default registration IP score budget is `20` points per `10m`.
- Pending registration and registration resend requests add `1` base IP score point before classifier risk is applied.
- Successful registration verification subtracts `1.5` IP score points, clamped at `0`.
- Invalid registration OTP verification adds `1` IP score point after the handler returns `invalid_otp_code`.
- Registration IP scores over `20` are rate-limited by middleware until the score key expires.
- Default password-reset IP score budget is `20` points per `5m`.
- Password-reset start and resend requests add `1` base IP score point before classifier risk is applied.
- Invalid password-reset OTP verification adds `1` IP score point after the handler returns `invalid_otp_code`.
- Successful password-reset verification subtracts `1.5` IP score points, clamped at `0`.
- Password-reset IP scores over `20` are rate-limited by middleware until the score key expires.
- System-wide registration start limits are configurable with `DDONE_SECURITY_OTP_REGISTER_SYSTEM_WINDOW` and `DDONE_SECURITY_OTP_REGISTER_MAX_SYSTEM_REQUESTS`.
- Registration IP score deltas are configurable with `DDONE_SECURITY_OTP_SPAM_REGISTER_PENDING_IP_SCORE`, `DDONE_SECURITY_OTP_SPAM_REGISTER_RESEND_IP_SCORE`, `DDONE_SECURITY_OTP_SPAM_REGISTER_INVALID_VERIFY_IP_SCORE`, and `DDONE_SECURITY_OTP_SPAM_REGISTER_SUCCESS_VERIFY_IP_SCORE`.
- Password-reset IP score deltas are configurable with `DDONE_SECURITY_OTP_SPAM_PASSWORD_RESET_PENDING_IP_SCORE`, `DDONE_SECURITY_OTP_SPAM_PASSWORD_RESET_RESEND_IP_SCORE`, `DDONE_SECURITY_OTP_SPAM_PASSWORD_RESET_INVALID_VERIFY_IP_SCORE`, and `DDONE_SECURITY_OTP_SPAM_PASSWORD_RESET_SUCCESS_VERIFY_IP_SCORE`.
- Default resend cooldown is `60s`.
- Default maximum resends is `3`.
- Default maximum verification attempts is `5`.
- OTP rate-limit counters and score state live in Redis.

### Bot Protection

- Public auth endpoints use an in-process per-IP fixed-window throttle before handlers run.
- Default bot protection allows `60` public auth requests per IP per `1m`.
- Exceeding the limit returns `429 bot_protection_rate_limited` with `Retry-After`.
- The default temporary block duration is `5m`.
- Bot protection is process-local. Multi-instance deployments should still keep edge or load-balancer rate limits.

### Phone Numbers

- Phone inputs are normalized by `internal/domain/user`.
- The current supported country code path is Lao phone numbers.
- Unsupported telephone codes produce application/domain errors mapped by handlers.

### Cookies And CORS

- Session cookies are `HttpOnly`.
- `session_cookie_secure` defaults to true in code defaults, but local `config/config.yaml` sets it false for HTTP development.
- `SameSite=None` requires `Secure=true`.
- Cross-origin cookie clients need explicit allowed origins and `cors.allow_credentials=true`.
- Config validation rejects `cors.allowed_origins=["*"]` when credentials are enabled.
- Unsafe cookie-session requests with `Origin` or `Referer` are accepted only from the same host or configured explicit CORS origins; wildcard origins are not trusted for this check.

### Signing Keys

- Private signing keys are stored in PostgreSQL.
- Redis caches public signing-key material only.
- Public JWKS responses include `Cache-Control` and `ETag`.
- Signing-key retention must be greater than or equal to signing-key rotation.

## 10. Data Storage

### PostgreSQL Tables

GORM auto-migration runs on startup for:

- `accounts`
- `auth_refresh_sessions`
- `auth_login_sessions`
- `auth_signing_keys`

`accounts` stores:

- UUID account ID generated by PostgreSQL `gen_random_uuid()`
- optional unique username
- password hash
- unique phone number
- phone verification timestamp
- username/password change timestamps
- created/updated timestamps

`auth_refresh_sessions` stores refresh-token history:

- token ID, account ID, root token ID, optional parent token ID
- token hash
- client IP and user agent
- expiry, last used, replaced, revoked, revoke reason, created timestamp

The table name and some column names are legacy-compatible: `account_id`, `root_session_id`, and `parent_session_id`.

`auth_login_sessions` stores server-side browser sessions:

- session ID and account ID
- session-token hash
- client IP and user agent
- current access token and access-token expiry
- session expiry
- revoked timestamp and reason
- created timestamp

`auth_signing_keys` stores ES256 signing keys:

- key ID, algorithm, curve
- public X/Y coordinates
- private key PEM
- status
- created, activation, rotation, and retirement timestamps

### PostgreSQL Extension

PostgreSQL must have `pgcrypto` enabled:

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
```

Local Docker initializes this through `db/init/001_pgcrypto.sql` only when the PostgreSQL volume is first created.

### Redis Data

Redis is used for pending state, counters, OTP risk scores, and read-through caches.

Known key families:

- `register:ticket:<ticketId>`
- `register:rate:phone:<phoneNumber>`
- `register:rate:system`
- `register:score:ip:<clientIp>`
- `register:verify:attempts:<ticketId>`
- `otp_spam:register:phone:<phoneHash>`
- `password_reset:ticket:<ticketId>`
- `password_reset:phone:<phoneNumber>`
- `password_reset:ip:<clientIp>`
- `password_reset:verify:<ticketId>`
- `otp_spam:password_reset:phone:<phoneHash>`
- `cache:user:id:<userId>`
- `cache:user:phone:<phoneNumber>`
- `cache:user:username:<username>`
- `cache:token:hash:<tokenHash>`
- `cache:token:id:<tokenId>`
- `cache:token:root:<rootTokenId>`
- `cache:login_session:token:<tokenHash>`
- `cache:login_session:id:<sessionId>`
- `cache:login_sessions:user:<userId>`
- `cache:signing_keys:public:v1`

Login and OTP flow-limit keys are generated by the corresponding application services and stored through Redis-backed ports. OTP spam score keys are generated by HTTP middleware and stored through the Redis OTP spam adapter.

## 11. Configuration

Config load order:

1. `config/config.yaml`
2. environment variables prefixed with `DDONE_`
3. optional `.env`

The local `config/config.yaml` is for development. Deployed environments should override values with environment variables.

Important config groups:

- `app`: debug mode, port, trusted proxies, request body limit
- `database`: PostgreSQL connection, pool, timeout, timezone, SQL logging
- `redis`: Redis address, auth, DB, timeout, pool settings
- `cache`: user cache, user-session-list cache, public signing-key cache TTLs
- `security.login`: failed-attempt window, max attempts, lockout duration
- `security.bot`: public auth endpoint bot-protection window, limit, and block duration
- `security.otp.register`: registration OTP flow policy
- `security.otp.password_reset`: password-reset OTP flow policy
- `security.otp_spam`: OTP middleware score policy
- `security.auth`: JWT issuer/audience, token TTLs, signing-key rotation/retention, session-cookie settings
- `cors`: allowed origins, methods, headers, exposed headers, credential mode, max age
- `wenovaapi.token`: Wenova token

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
DDONE_DATABASE_TIMEZONE=UTC
DDONE_DATABASE_CONNECT_TIMEOUT=10
DDONE_DATABASE_MAX_OPEN_CONNS=25
DDONE_DATABASE_MAX_IDLE_CONNS=5
DDONE_DATABASE_CONN_MAX_LIFETIME=30m
DDONE_DATABASE_CONN_MAX_IDLE_TIME=15m
DDONE_DATABASE_LOG_SQL=false

DDONE_REDIS_HOST=localhost
DDONE_REDIS_PORT=6380
DDONE_REDIS_USERNAME=
DDONE_REDIS_PASSWORD=
DDONE_REDIS_DB=0
DDONE_REDIS_DIAL_TIMEOUT=5s
DDONE_REDIS_READ_TIMEOUT=3s
DDONE_REDIS_WRITE_TIMEOUT=3s
DDONE_REDIS_POOL_SIZE=10
DDONE_REDIS_MIN_IDLE_CONNS=2

DDONE_CACHE_USER_TTL=5m
DDONE_CACHE_USER_SESSION_LIST_TTL=1m
DDONE_CACHE_SIGNING_KEYS_TTL=1m

DDONE_SECURITY_LOGIN_FAILED_ATTEMPT_WINDOW=5m
DDONE_SECURITY_LOGIN_MAX_ATTEMPTS=5
DDONE_SECURITY_LOGIN_LOCKOUT_DURATION=15m

DDONE_SECURITY_BOT_ENABLED=true
DDONE_SECURITY_BOT_WINDOW=1m
DDONE_SECURITY_BOT_MAX_REQUESTS=60
DDONE_SECURITY_BOT_BLOCK_DURATION=5m

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
DDONE_SECURITY_OTP_SPAM_ENABLED=true
DDONE_SECURITY_OTP_SPAM_REGISTER_PHONE_WINDOW=5m
DDONE_SECURITY_OTP_SPAM_REGISTER_IP_WINDOW=10m
DDONE_SECURITY_OTP_SPAM_REGISTER_MAX_PHONE_REQUESTS=1
DDONE_SECURITY_OTP_SPAM_REGISTER_MAX_IP_SCORE=20
DDONE_SECURITY_OTP_SPAM_REGISTER_PENDING_IP_SCORE=1
DDONE_SECURITY_OTP_SPAM_REGISTER_RESEND_IP_SCORE=1
DDONE_SECURITY_OTP_SPAM_REGISTER_INVALID_VERIFY_IP_SCORE=1
DDONE_SECURITY_OTP_SPAM_REGISTER_SUCCESS_VERIFY_IP_SCORE=-1.5
DDONE_SECURITY_OTP_SPAM_PASSWORD_RESET_PHONE_WINDOW=5m
DDONE_SECURITY_OTP_SPAM_PASSWORD_RESET_IP_WINDOW=5m
DDONE_SECURITY_OTP_SPAM_PASSWORD_RESET_MAX_PHONE_REQUESTS=1
DDONE_SECURITY_OTP_SPAM_PASSWORD_RESET_MAX_IP_SCORE=20
DDONE_SECURITY_OTP_SPAM_PASSWORD_RESET_PENDING_IP_SCORE=1
DDONE_SECURITY_OTP_SPAM_PASSWORD_RESET_RESEND_IP_SCORE=1
DDONE_SECURITY_OTP_SPAM_PASSWORD_RESET_INVALID_VERIFY_IP_SCORE=1
DDONE_SECURITY_OTP_SPAM_PASSWORD_RESET_SUCCESS_VERIFY_IP_SCORE=-1.5

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

DDONE_CORS_ALLOWED_ORIGINS=http://localhost:5173
DDONE_CORS_ALLOWED_METHODS=GET,POST,OPTIONS
DDONE_CORS_ALLOWED_HEADERS=Origin,Content-Type,Accept,Authorization
DDONE_CORS_EXPOSED_HEADERS=
DDONE_CORS_ALLOW_CREDENTIALS=false
DDONE_CORS_MAX_AGE=12h

DDONE_WENOVA_TOKEN=replace-me
```

Several legacy env aliases are still accepted for auth, OTP, login, and cache settings. See `config/config.go` for the exact bindings.

## 12. Startup Flow

`cmd/app` currently starts the service as follows:

1. Load config.
2. Build Zap logger.
3. Connect PostgreSQL.
4. Connect Redis.
5. Run GORM auto-migration.
6. Create Wenova SMS client.
7. Build repositories and Redis cache decorators.
8. Build ES256 token codec.
9. Build JWKS service and ensure an active signing key exists.
10. Build JWT service.
11. Build login, registration, password, settings, session, token-manager services.
12. Build handlers and middleware.
13. Register routes.
14. Start the HTTP server.
15. Gracefully shut down on `SIGINT` or `SIGTERM`.

The HTTP server disables Gin's trust-all proxy default unless `app.trusted_proxies` is explicitly configured. It applies request body limits and bot protection before public auth handlers, and applies OTP spam detection middleware on registration and password-reset OTP routes. It uses a 5-second read-header timeout, 10-second read timeout, 15-second write timeout, 60-second idle timeout, default 1 MiB max header size, configured request body limit, and a 10-second graceful shutdown timeout.

## 13. Local Development

Start PostgreSQL and Redis only:

```bash
make infra-up
```

Run the service directly:

```bash
make run
```

Run the full Docker Compose stack:

```bash
make compose-up
```

Build and start the full Docker Compose stack:

```bash
make compose-up-build
```

Run tests:

```bash
make test
```

Format Go code:

```bash
make fmt
```

Stop infrastructure:

```bash
make infra-down
```

Stop the full stack:

```bash
make compose-down
```

`docker-infra.yml` exposes PostgreSQL and Redis on host ports for direct local development. `docker-compose.yml` runs the app, PostgreSQL, and Redis on an internal Docker network and exposes only the app port.

## 14. Build, Release, And Deployment

Build a local binary:

```bash
make build
```

Build release zip bundles:

```bash
make release
make release RELEASE_VERSION=v1.0.0
```

Release artifacts are written to `dist/` and include:

- compiled binary
- `config/config.yaml`
- `deploy/systemd/`
- `start.sh`
- `systemctl.sh`
- `README.md`
- `RUN.txt`

Supported release architectures default to Linux `amd64` and Linux `arm64`.

Build a Docker image:

```bash
docker build -t barluscuda/ddone-server-auth .
```

systemd assets:

- `deploy/systemd/ddone-server-auth.service`
- `deploy/systemd/ddone-server-auth.env.example`

Makefile systemd helpers:

```bash
make systemd-install
make systemd-bootstrap
make systemd-enable
make systemd-start
make systemd-status
make systemd-logs
make systemd-restart
make systemd-stop
```

Default install layout:

- binary: `/usr/local/bin/ddone-server-auth`
- working directory: `/opt/ddone-server-auth`
- environment file: `/etc/ddone-server-auth/ddone-server-auth.env`

## 15. Documentation Set

- `docs/project.md`: this project handbook
- `docs/api.md`: endpoint-level API reference
- `docs/jwt.md`: downstream JWT verification guide
- `docs/postman.md`: Postman usage guide
- `README.md`: quick-start and deployment overview
- `AGENTS.md`: coding-agent rules for this repository

Keep `README.md`, `docs/api.md`, `docs/jwt.md`, Postman assets, and this file aligned when changing behavior that affects them.

## 16. Testing

Run all tests:

```bash
go test ./...
```

Current coverage includes:

- Config validation
- DTO JSON field casing
- HTTP handler behavior
- Middleware auth, session-origin checks, request body limits, bot protection, CORS, and recovery behavior
- Redis signing-key cache behavior
- ES256 signing, verification, and JWK behavior
- JWT application orchestration
- JWKS key lifecycle
- Registration OTP flow and limits
- Login, refresh-token rotation, and replay handling
- Password reset and password change
- Login-session behavior
- Settings and username update behavior
- Token manager behavior

When adding behavior:

- Prefer application-level unit tests for business rules and orchestration.
- Use handler tests for HTTP request/response mapping and status codes.
- Add adapter tests for serialization, token verification, cache-key behavior, persistence mapping, and external integration boundaries.
- Run `gofmt -w` on touched Go files.
- Run `go test ./...` after code changes.

## 17. Operational Notes

- Do not log raw tokens, OTP codes, passwords, or private key material.
- Preserve refresh-token lineage fields because replay handling depends on them.
- Preserve `auth_refresh_sessions` table compatibility unless a migration plan exists.
- Public signing-key cache must not include private key PEM.
- Startup requires PostgreSQL and Redis availability.
- Registration and password reset require a valid Wenova token in real environments.
- If signing keys are lost, existing access tokens cannot be verified and new keys must be generated.
- If private signing-key material is suspected compromised, rotate keys and consider shortening token TTLs or revoking dependent sessions/tokens.
