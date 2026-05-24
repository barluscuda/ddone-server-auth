SHELL := /bin/bash

.PHONY: \
	help build run test fmt tidy clean \
	infra-up infra-down infra-logs infra-ps \
	install-user install-dirs install-bin install-config install-env install-unit \
	systemd-install systemd-bootstrap \
	systemd-daemon-reload systemd-enable systemd-disable \
	systemd-start systemd-stop systemd-restart systemd-status systemd-logs

GO ?= go
GOFMT ?= gofmt
INSTALL ?= install
SUDO ?= sudo
SYSTEMCTL ?= systemctl
JOURNALCTL ?= journalctl

APP := ./cmd/app
BIN := ddone-server-auth
BUILD_DIR ?= .
BIN_PATH := $(BUILD_DIR)/$(BIN)
GO_FILES := $(shell rg --files . -g'*.go')

SERVICE_NAME ?= ddone-server-auth
SERVICE_USER ?= ddone
SERVICE_GROUP ?= ddone

APP_DIR ?= /opt/$(SERVICE_NAME)
CONFIG_SRC_DIR := config
CONFIG_DEST_DIR := $(APP_DIR)/config

BIN_DIR ?= /usr/local/bin
BIN_INSTALL_PATH := $(BIN_DIR)/$(BIN)

ENV_DIR ?= /etc/$(SERVICE_NAME)
ENV_SRC := deploy/systemd/$(SERVICE_NAME).env.example
ENV_DEST := $(ENV_DIR)/$(SERVICE_NAME).env

SYSTEMD_DIR ?= /etc/systemd/system
UNIT_SRC := deploy/systemd/$(SERVICE_NAME).service
UNIT_DEST := $(SYSTEMD_DIR)/$(SERVICE_NAME).service

help:
	@echo "Available targets:"
	@echo "  make build             - Build the service binary"
	@echo "  make run               - Run the HTTP server"
	@echo "  make test              - Run Go tests"
	@echo "  make fmt               - Format Go files"
	@echo "  make tidy              - Tidy Go modules"
	@echo "  make clean             - Remove the built binary"
	@echo "  make infra-up          - Start PostgreSQL and Redis"
	@echo "  make infra-down        - Stop local infrastructure"
	@echo "  make infra-logs        - Show infrastructure logs"
	@echo "  make infra-ps          - Show infrastructure status"
	@echo "  make systemd-install   - Install user, binary, config, env, and unit file"
	@echo "  make systemd-bootstrap - Install everything, enable, and start the service"
	@echo "  make systemd-enable    - Enable the systemd service"
	@echo "  make systemd-disable   - Disable the systemd service"
	@echo "  make systemd-start     - Start the systemd service"
	@echo "  make systemd-stop      - Stop the systemd service"
	@echo "  make systemd-restart   - Restart the systemd service"
	@echo "  make systemd-status    - Show systemd service status"
	@echo "  make systemd-logs      - Follow systemd service logs"
	@echo ""
	@echo "Overridable variables:"
	@echo "  BUILD_DIR=$(BUILD_DIR)"
	@echo "  SERVICE_NAME=$(SERVICE_NAME)"
	@echo "  SERVICE_USER=$(SERVICE_USER)"
	@echo "  SERVICE_GROUP=$(SERVICE_GROUP)"
	@echo "  APP_DIR=$(APP_DIR)"
	@echo "  BIN_DIR=$(BIN_DIR)"
	@echo "  ENV_DIR=$(ENV_DIR)"
	@echo "  SYSTEMD_DIR=$(SYSTEMD_DIR)"

build:
	$(GO) build -o $(BIN_PATH) $(APP)

run:
	$(GO) run $(APP)

test:
	$(GO) test ./...

fmt:
	$(GOFMT) -w $(GO_FILES)

tidy:
	$(GO) mod tidy

clean:
	rm -f $(BIN_PATH)

infra-up:
	docker compose -f docker-infra.yml up -d

infra-down:
	docker compose -f docker-infra.yml down

infra-logs:
	docker compose -f docker-infra.yml logs -f

infra-ps:
	docker compose -f docker-infra.yml ps

install-user:
	@if id -u "$(SERVICE_USER)" >/dev/null 2>&1; then \
		echo "User $(SERVICE_USER) already exists"; \
	else \
		$(SUDO) useradd --system --home "$(APP_DIR)" --shell /usr/sbin/nologin "$(SERVICE_USER)"; \
	fi

install-dirs:
	$(SUDO) $(INSTALL) -d -m 0755 "$(APP_DIR)" "$(CONFIG_DEST_DIR)" "$(ENV_DIR)"

install-bin: build
	$(SUDO) $(INSTALL) -m 0755 "$(BIN_PATH)" "$(BIN_INSTALL_PATH)"

install-config:
	$(SUDO) $(INSTALL) -d -m 0755 "$(CONFIG_DEST_DIR)"
	$(SUDO) cp -R "$(CONFIG_SRC_DIR)/." "$(CONFIG_DEST_DIR)/"

install-env:
	$(SUDO) $(INSTALL) -d -m 0755 "$(ENV_DIR)"
	@if [ -f "$(ENV_DEST)" ]; then \
		echo "Keeping existing $(ENV_DEST)"; \
	else \
		$(SUDO) $(INSTALL) -m 0640 "$(ENV_SRC)" "$(ENV_DEST)"; \
	fi

install-unit:
	$(SUDO) $(INSTALL) -m 0644 "$(UNIT_SRC)" "$(UNIT_DEST)"

systemd-daemon-reload:
	$(SUDO) $(SYSTEMCTL) daemon-reload

systemd-install: install-user install-dirs install-bin install-config install-env install-unit systemd-daemon-reload
	$(SUDO) chown -R "$(SERVICE_USER):$(SERVICE_GROUP)" "$(APP_DIR)" "$(ENV_DIR)"

systemd-bootstrap: systemd-install systemd-enable systemd-start

systemd-enable:
	$(SUDO) $(SYSTEMCTL) enable "$(SERVICE_NAME)"

systemd-disable:
	$(SUDO) $(SYSTEMCTL) disable "$(SERVICE_NAME)"

systemd-start:
	$(SUDO) $(SYSTEMCTL) start "$(SERVICE_NAME)"

systemd-stop:
	$(SUDO) $(SYSTEMCTL) stop "$(SERVICE_NAME)"

systemd-restart:
	$(SUDO) $(SYSTEMCTL) restart "$(SERVICE_NAME)"

systemd-status:
	$(SUDO) $(SYSTEMCTL) status "$(SERVICE_NAME)"

systemd-logs:
	$(SUDO) $(JOURNALCTL) -u "$(SERVICE_NAME)" -f
