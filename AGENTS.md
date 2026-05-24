# AGENTS.md

This repository is a Go auth service moving toward hexagonal architecture. When acting as a coding agent here, optimize for small, behavior-preserving refactors that strengthen boundaries rather than large rewrites.

## Working Rules

- Keep dependencies pointing inward: delivery and infrastructure depend on application and domain, never the reverse.
- Put orchestration in `internal/application`.
- Keep HTTP concerns in `internal/adapters/handler` and `internal/adapters/middleware`.
- Keep Postgres, Redis, and SMS integrations in outbound adapters under `internal/adapters`.
- Treat `cmd/app` as the composition root only.

## Architecture Direction

Use this target shape when adding or moving code:

```text
internal/domain/          Business types, invariants, domain errors
internal/application/     Use cases and port-driven orchestration
internal/adapters/        HTTP, DB, cache, SMS, DTOs, middleware
internal/bootstrap/       Logging and startup wiring helpers
cmd/app/                  Process entrypoint
```

## Important Repo-Specific Guidance

- New business logic should go into `internal/application/<usecase>`.
- New handlers should depend on application interfaces, not concrete repositories.
- HTTP JSON request and response field names should use camelCase in DTOs and public examples.
- Do not introduce new adapter imports into application or domain code.
- Do not put migrations, GORM tags, Redis logic, or HTTP types into new domain packages.
- `internal/domain/user` should stay persistence-free. Keep table names, GORM tags, Redis JSON shapes, and migration helpers in adapters.
- `internal/ports` exists today, but avoid turning it into a dumping ground. Prefer interfaces close to the owning use case or domain.

## Commands

- `make run` runs the service
- `make test` runs `go test ./...`
- `make fmt` runs `gofmt -w`
- `make infra-up` starts PostgreSQL and Redis
- `make infra-down` stops local infrastructure

## Validation Expectations

- Run `gofmt -w` on touched Go files.
- Run `go test ./...` after code changes.
- If you change config, routes, or startup behavior, keep `README.md` and any relevant skill guidance aligned.

## Current Functional Scope

- `GET /healthz`
- `GET /robots.txt`
- `POST /register`
- `POST /register/resend`
- `POST /register/verify`
- `POST /tokens`
- `POST /tokens/refresh`
- `GET /tokens`
- `DELETE /tokens/:tokenId`
- `POST /tokens/revoke-all`
- `POST /sessions`
- `POST /sessions/token`
- `GET /sessions`
- `GET /sessions/current`
- `DELETE /sessions/:sessionId`
- `POST /sessions/revoke-others`
- `POST /sessions/revoke-all`
- `POST /password/forgot`
- `POST /password/forgot/resend`
- `POST /password/forgot/verify`
- `GET /settings`
- `GET /settings/me`
- `PATCH /settings/username`
- `POST /settings/password`
- `GET /.well-known/jwks.json`

Registration currently depends on:

- PostgreSQL for user persistence
- Redis for pending registration and OTP rate-limit state
- Wenova SMS for OTP delivery

Password reset currently depends on:

- PostgreSQL for user lookup and password updates
- Redis for pending password-reset state and OTP rate-limit state
- Wenova SMS for OTP delivery

Login currently depends on:

- PostgreSQL for user lookup, raw token records, login sessions, and signing keys
- ES256 access-token signing with JWKS publication

Session-login currently also depends on:

- `HttpOnly` cookie transport for the server-side session identifier

## Preferred Change Style

- Favor incremental refactors.
- Preserve external behavior unless the task explicitly asks for API or contract changes.
- Call out architectural violations directly when you see them.
- If a change spans domain, application, and adapters, move one seam at a time and keep the system compiling throughout.
