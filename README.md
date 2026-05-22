# ddone-server-auth

`ddone-server-auth` is a Go auth service for DDONE. It currently provides:

- `GET /healthz`
- `POST /register`
- `POST /register/resend`
- `POST /register/verify`

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
internal/domain/account/       Account and registration domain models
internal/adapters/cache/       Redis client and registration store
internal/adapters/database/    PostgreSQL connection setup
internal/adapters/repository/  GORM-backed repositories
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

DDONE_REDIS_HOST=localhost
DDONE_REDIS_PORT=6380

DDONE_WENOVA_TOKEN=your-token
```

You can also supply:

- `DDONE_DATABASE_URL`
- `DDONE_REDIS_URL`

## API

### `GET /healthz`

Returns service health.

### `POST /register`

Starts phone registration and sends an OTP.

Example body:

```json
{
  "phone_number": "+8562012345678",
  "password": "secretpass"
}
```

### `POST /register/resend`

Resends the OTP for an existing registration ticket.

Example body:

```json
{
  "ticket_id": "reg_abc123"
}
```

### `POST /register/verify`

Verifies the OTP and creates the account.

Example body:

```json
{
  "ticket_id": "reg_abc123",
  "otp_code": "123456"
}
```

## Development Direction

When extending this service, prefer:

- pure domain types without framework or ORM tags
- application use cases that depend on ports
- thin HTTP handlers
- outbound adapters for Postgres, Redis, and SMS
- migrations and persistence mapping outside the domain layer
