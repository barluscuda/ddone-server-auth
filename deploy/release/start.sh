#!/usr/bin/env sh

set -eu

APP_NAME="${APP_NAME:-ddone-server-auth}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
APP_DIR="${APP_DIR:-${SCRIPT_DIR}}"
BIN_PATH="${BIN_PATH:-${APP_DIR}/${APP_NAME}}"
CONFIG_PATH="${CONFIG_PATH:-${APP_DIR}/config/config.yaml}"
ENV_FILE="${ENV_FILE:-${APP_DIR}/.env}"

if [ ! -x "${BIN_PATH}" ]; then
	echo "binary is not executable: ${BIN_PATH}" >&2
	exit 1
fi

if [ ! -f "${CONFIG_PATH}" ]; then
	echo "config file is missing: ${CONFIG_PATH}" >&2
	exit 1
fi

if [ -f "${ENV_FILE}" ]; then
	set -a
	. "${ENV_FILE}"
	set +a
fi

cd "${APP_DIR}"
exec "${BIN_PATH}"
