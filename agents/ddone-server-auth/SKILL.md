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
- OTP resend and verification flows
- Health check endpoint
- JWKS publication for ES256 access tokens
- PostgreSQL-backed account persistence
- PostgreSQL-backed refresh sessions and signing keys
- Redis-backed pending registration state
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
- Registration use case: `internal/application/register`
- Postgres repository: `internal/adapters/repository`
- Redis store: `internal/adapters/cache`
- SMS adapter: `internal/adapters/sms`

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
3. If config, architecture, or startup behavior changed, keep `README.md` and `AGENTS.md` in sync.

## Do Not Do

- Do not split this into microservices unless explicitly asked.
- Do not make handlers call GORM or Redis directly.
- Do not add new framework dependencies to domain logic.
- Do not do big-bang rewrites when a strangler refactor will work.
