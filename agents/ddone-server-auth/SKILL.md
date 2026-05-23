---
name: ddone-server-auth
description: >
  Use this skill when working in the ddone-server-auth repository for auth,
  registration, startup wiring, API handlers, or architecture refactors. Apply
  the repo's hexagonal direction: put business orchestration in
  internal/application, keep domain logic framework-free when possible, keep
  HTTP/DB/cache/SMS code in adapters, and validate changes with gofmt and go
  test.
---

# ddone-server-auth Skill

Use this skill for changes inside this repository.

## What This Service Does

- Phone-based registration with OTP
- Phone-number login with access and refresh tokens
- Phone-based forgot-password with OTP verification
- Authenticated change-password
- Database-backed unlimited login sessions with access-token reuse/refresh
- OTP resend and verification flows
- Health check endpoint
- JWKS publication for ES256 access tokens
- PostgreSQL-backed account persistence
- PostgreSQL-backed refresh sessions and signing keys
- Redis-backed pending registration state
- Redis-backed pending password-reset state
- Wenova SMS delivery

## Architecture Workflow

1. Identify the seam you are changing:
   - `cmd/app` for entrypoint and composition
   - `internal/application` for use cases
   - `internal/domain` for business concepts and errors
   - `internal/adapters` for HTTP, DB, Redis, SMS, middleware, DTOs
2. Keep dependencies pointing inward.
3. Prefer small refactors over big rewrites.
4. Update docs when behavior, setup, or architecture expectations change.

## Repo Rules

- New use cases belong in `internal/application/<name>`.
- Handlers should depend on application contracts, not concrete repositories.
- Avoid importing adapter packages into application or domain code.
- Avoid adding new GORM tags, migration logic, or transport DTOs to domain packages.
- If touching `internal/domain/account`, note that it still has legacy persistence leakage. Move it toward pure domain types instead of expanding that pattern.

## Current Runtime Shape

- HTTP server: `cmd/app/server.go`
- Startup wiring: `cmd/app/main.go`
- Config loading: `config/config.go`
- Runtime config includes auth token settings and CORS settings
- Registration use case: `internal/application/register`
- Login use case: `internal/application/login`
- JWKS use case: `internal/application/jwks`
- Postgres repository: `internal/adapters/repository`
- Redis store: `internal/adapters/cache`
- SMS adapter: `internal/adapters/sms`
- ES256 token adapter: `internal/adapters/token`
- HTTP middleware includes recovery, request logging, and CORS
- Postman assets: `postman/` with usage notes in `docs/postman.md`

## Current HTTP Surface

- `GET /healthz`
- `POST /register`
- `POST /register/resend`
- `POST /register/verify`
- `POST /login`
- `POST /login/refresh`
- `POST /login/session`
- `POST /login/session/token`
- `POST /password/forgot`
- `POST /password/forgot/resend`
- `POST /password/forgot/verify`
- `GET /account/me`
- `GET /account/sessions`
- `POST /account/password`
- `GET /.well-known/jwks.json`

## Login And CORS Notes

- `POST /login` returns access and refresh tokens in JSON.
- `POST /login/refresh` rotates the refresh token from the request body and returns a new access token plus refresh token in JSON.
- `POST /login/session` stores a persistent server-side session in PostgreSQL and sets the session identifier in an `HttpOnly` cookie.
- `POST /login/session/token` reads that session cookie and returns the current access token for the session, automatically issuing a new one only after the stored token has expired.
- `POST /password/forgot`, `POST /password/forgot/resend`, and `POST /password/forgot/verify` implement the OTP-based password reset flow.
- `GET /account/me`, `GET /account/sessions`, and `POST /account/password` are self-service routes protected by a Bearer access token in the `Authorization` header.
- If clients send credentials across origins for other reasons, CORS still requires `allow_credentials=true` and explicit origins instead of `*`.

## Commands

```bash
make infra-up
make run
make test
make fmt
make infra-down
```

## Validation

After edits:

1. Run `gofmt -w` on touched Go files.
2. Run `go test ./...`.
3. If config, architecture, startup behavior, routes, request/response bodies, or CORS behavior changed, keep `README.md`, `AGENTS.md`, and this skill in sync.
4. If API routes or request payloads changed, update the checked-in Postman collection and environment templates under `postman/` and the guide in `docs/postman.md`.

## Do Not Do

- Do not split this into microservices unless explicitly asked.
- Do not make handlers call GORM or Redis directly.
- Do not add new framework dependencies to domain logic.
- Do not do big-bang rewrites when a strangler refactor will work.
