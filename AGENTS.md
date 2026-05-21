# DDONE Auth Service Agent Guide

## Mission

This repository is the authentication service for DDONE. Treat it like a production service, not a playground. Favor clear boundaries, predictable behavior, and operational safety over clever shortcuts.

## Engineering Standard

- Write code like a senior backend engineer maintaining a live service.
- Prefer small, composable changes over broad rewrites.
- Preserve existing architecture unless there is a strong reason to change it.
- Make runtime behavior explicit: startup, shutdown, logging, config, error handling.
- Keep the happy path easy to read.

## Current Architecture

- `cmd/app`: application bootstrap and process lifecycle.
- `config`: configuration loading, defaults, environment overrides, validation.
- `internal/adapters/handler`: transport-facing HTTP handlers.
- `internal/adapters/middleware`: HTTP middleware such as logging and recovery.
- `internal/adapters/dto`: transport DTOs for the HTTP layer.
- `internal/bootstrap`: bootstrap concerns shared by the app entrypoint, such as logging.
- `internal/domain`: business models and domain concepts.

## Layering Rules

- `cmd/app` wires dependencies together. Keep business logic out of `main.go`.
- Handlers should translate HTTP input and output only. Do not bury domain rules in handlers.
- Middleware should be generic, reusable, and transport-focused.
- Domain packages should not depend on Gin.
- Config loading stays centralized in `config`.
- Bootstrap packages may depend on infrastructure libraries like zap, but domain packages should stay lean.

## Logging Rules

- Use `zap` for all application logging.
- Prefer structured fields over interpolated strings.
- Log lifecycle events explicitly: startup, shutdown, unexpected failure.
- Do not re-enable Gin's default logger.
- Use `Debug` logs only for developer-oriented diagnostics.
- Avoid logging secrets, tokens, OTP codes, passwords, raw authorization headers, or unnecessary PII.

## HTTP Rules

- Register routes explicitly in the app bootstrap.
- Keep handlers thin and deterministic.
- Return stable JSON payloads.
- Use middleware for cross-cutting concerns like logging, panic recovery, auth, tracing, and request IDs.
- Add timeouts on servers and external clients.

## Config Rules

- Every new config field must have a sane default when reasonable.
- Every new config field must have an env binding.
- Validate required config for safe startup.
- Prefer fail-fast startup over partial boot with broken config.
- Keep config names consistent between YAML and env vars.

## Domain And Data Modeling

- Domain models should reflect business meaning first, storage concerns second.
- If a model is persistence-specific, keep naming clear and avoid leaking it into transport unnecessarily.
- Be deliberate about nullable fields, uniqueness, and timestamps.
- When introducing auth and account flows, think through idempotency and deletion behavior.

## Testing Expectations

- Run `go test ./...` after meaningful Go changes.
- Add focused tests for new logic when behavior is non-trivial.
- For bug fixes, prefer adding a regression test when the code shape allows it.
- If tests are still sparse, keep new code testable and avoid designs that become harder to verify later.

## Change Style

- Prefer incremental files and packages over giant utility blobs.
- Keep function names boring and obvious.
- Avoid premature abstractions.
- Add comments only when intent is not obvious from the code.
- Keep imports, formatting, and module metadata tidy.

## Safe Defaults For Future Work

- If adding new endpoints, follow the existing adapter and domain split.
- If adding auth providers, extend domain types carefully and validate uniqueness constraints.
- If adding persistence, initialize it in bootstrap or app wiring rather than inside handlers.
- If adding observability, prefer structured middleware and bootstrap-managed clients.

## Commands

- Format: `gofmt -w <files>`
- Test: `go test ./...`
- Dependency cleanup: `go mod tidy`

## Definition Of Done

A change is not done until:

- the code compiles
- the main path is readable
- logs and errors are production-appropriate
- config is safe
- tests were run, or the reason they were not is stated clearly
