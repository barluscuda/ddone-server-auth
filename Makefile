.PHONY: help run test fmt tidy infra-up infra-down infra-logs infra-ps

APP := ./cmd/app
GO_FILES := $(shell rg --files . -g'*.go')

help:
	@echo "Available targets:"
	@echo "  make run        - Run the HTTP server"
	@echo "  make test       - Run Go tests"
	@echo "  make fmt        - Format Go files"
	@echo "  make tidy       - Tidy Go modules"
	@echo "  make infra-up   - Start PostgreSQL and Redis"
	@echo "  make infra-down - Stop local infrastructure"
	@echo "  make infra-logs - Show infrastructure logs"
	@echo "  make infra-ps   - Show infrastructure status"

run:
	go run $(APP)

test:
	go test ./...

fmt:
	gofmt -w $(GO_FILES)

tidy:
	go mod tidy

infra-up:
	docker compose up -d

infra-down:
	docker compose down

infra-logs:
	docker compose logs -f

infra-ps:
	docker compose ps
