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
- Do not introduce new adapter imports into application or domain code.
- Do not put migrations, GORM tags, Redis logic, or HTTP types into new domain packages.
- `internal/domain/account` still contains legacy GORM tags and migration helpers. If touching that area, move it toward pure domain models instead of extending the leakage.
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
- `POST /register`
- `POST /register/resend`
- `POST /register/verify`

Registration currently depends on:

- PostgreSQL for account persistence
- Redis for pending registration and OTP rate-limit state
- Wenova SMS for OTP delivery

## Preferred Change Style

- Favor incremental refactors.
- Preserve external behavior unless the task explicitly asks for API or contract changes.
- Call out architectural violations directly when you see them.
- If a change spans domain, application, and adapters, move one seam at a time and keep the system compiling throughout.
