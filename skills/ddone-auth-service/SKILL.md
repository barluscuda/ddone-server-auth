---
name: ddone-auth-service
description: Use when working in the DDONE auth service repository to follow its backend architecture, production bootstrap style, zap logging conventions, config patterns, and thin-handler layering. Especially relevant for adding endpoints, changing startup wiring, middleware, config, or account and auth domain models.
---

# DDONE Auth Service

Use this skill for changes in this repository.

## What To Optimize For

- Production-safe bootstrap and runtime behavior
- Thin HTTP handlers
- Centralized config and validation
- Structured logging with `zap`
- Clear separation between transport, bootstrap, and domain code

## Repository Map

- `cmd/app`: process startup, route registration, graceful shutdown
- `config`: Viper-backed config loading and validation
- `internal/adapters/handler`: Gin handlers only
- `internal/adapters/middleware`: request logging, recovery, and future cross-cutting HTTP concerns
- `internal/adapters/dto`: transport DTOs
- `internal/bootstrap`: logger and future infra wiring
- `internal/domain`: account and auth domain models

## Working Rules

1. Start by reading `AGENTS.md` and the files closest to the requested change.
2. Keep `main.go` focused on wiring, not business logic.
3. When adding config:
   - add a default
   - bind the env var
   - validate if needed for safe startup
4. When adding logs:
   - use `zap`
   - use structured fields
   - never log secrets or sensitive auth data
5. When adding HTTP behavior:
   - prefer middleware for cross-cutting concerns
   - keep handlers request and response focused
6. When changing domain models:
   - preserve business meaning
   - review uniqueness, nullability, and timestamp behavior
7. After Go changes, run `gofmt -w` and `go test ./...`.

## Common Task Patterns

### Add a new endpoint

- Register the route in `cmd/app/main.go`
- Add or extend a handler in `internal/adapters/handler`
- Put shared HTTP concerns in middleware, not the handler
- Introduce DTOs when request or response payloads grow

### Add a new config field

- Update `config/config.go`
- Add default, env binding, and validation
- Reflect the field in `config/config.yaml` if the repo uses it as an example baseline

### Improve observability

- Prefer bootstrap-managed clients and middleware
- Keep log messages stable and easy to query
- Use severity intentionally: `Debug`, `Info`, `Warn`, `Error`

## Avoid

- Putting business logic directly in Gin handlers
- Reintroducing Gin default logging
- Hidden globals for runtime dependencies
- Logging OTPs, tokens, passwords, or raw secrets
- Large rewrites when a focused change will do
