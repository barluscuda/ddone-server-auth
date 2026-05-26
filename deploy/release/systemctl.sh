#!/usr/bin/env sh

set -eu

APP_NAME="${APP_NAME:-ddone-server-auth}"
SERVICE_USER="${SERVICE_USER:-ddone}"
SERVICE_GROUP="${SERVICE_GROUP:-ddone}"
APP_DIR="${APP_DIR:-/opt/${APP_NAME}}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
ENV_DIR="${ENV_DIR:-/etc/${APP_NAME}}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
BIN_SRC="${BIN_SRC:-${SCRIPT_DIR}/${APP_NAME}}"
CONFIG_SRC="${CONFIG_SRC:-${SCRIPT_DIR}/config/config.yaml}"
ENV_SRC="${ENV_SRC:-${SCRIPT_DIR}/.env.example}"
UNIT_SRC="${UNIT_SRC:-${SCRIPT_DIR}/deploy/systemd/${APP_NAME}.service}"

BIN_DEST="${BIN_DIR}/${APP_NAME}"
CONFIG_DEST_DIR="${APP_DIR}/config"
CONFIG_DEST="${CONFIG_DEST_DIR}/config.yaml"
ENV_DEST="${ENV_DIR}/${APP_NAME}.env"
UNIT_DEST="${SYSTEMD_DIR}/${APP_NAME}.service"

SUDO="${SUDO:-sudo}"
SYSTEMCTL="${SYSTEMCTL:-systemctl}"
INSTALL="${INSTALL:-install}"

usage() {
	cat <<EOF
Usage: $0 install|remove

Environment overrides:
  APP_NAME=${APP_NAME}
  SERVICE_USER=${SERVICE_USER}
  SERVICE_GROUP=${SERVICE_GROUP}
  APP_DIR=${APP_DIR}
  BIN_DIR=${BIN_DIR}
  ENV_DIR=${ENV_DIR}
  SYSTEMD_DIR=${SYSTEMD_DIR}
  REMOVE_DATA=1 removes ${APP_DIR} and ${ENV_DIR} during remove
EOF
}

ensure_user() {
	if ! getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
		${SUDO} groupadd --system "${SERVICE_GROUP}"
	fi

	if id -u "${SERVICE_USER}" >/dev/null 2>&1; then
		return
	fi

	${SUDO} useradd --system --gid "${SERVICE_GROUP}" --home "${APP_DIR}" --shell /usr/sbin/nologin "${SERVICE_USER}"
}

install_service() {
	if [ ! -f "${BIN_SRC}" ]; then
		echo "missing binary: ${BIN_SRC}" >&2
		exit 1
	fi
	if [ ! -f "${CONFIG_SRC}" ]; then
		echo "missing config: ${CONFIG_SRC}" >&2
		exit 1
	fi
	if [ ! -f "${ENV_SRC}" ]; then
		echo "missing env template: ${ENV_SRC}" >&2
		exit 1
	fi
	if [ ! -f "${UNIT_SRC}" ]; then
		echo "missing systemd unit: ${UNIT_SRC}" >&2
		exit 1
	fi

	ensure_user
	${SUDO} ${INSTALL} -d -m 0755 "${APP_DIR}" "${CONFIG_DEST_DIR}" "${ENV_DIR}"
	${SUDO} ${INSTALL} -m 0755 "${BIN_SRC}" "${BIN_DEST}"
	${SUDO} ${INSTALL} -m 0644 "${CONFIG_SRC}" "${CONFIG_DEST}"
	if [ -f "${ENV_DEST}" ]; then
		echo "keeping existing ${ENV_DEST}"
	else
		${SUDO} ${INSTALL} -m 0640 "${ENV_SRC}" "${ENV_DEST}"
	fi
	${SUDO} ${INSTALL} -m 0644 "${UNIT_SRC}" "${UNIT_DEST}"
	${SUDO} chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${APP_DIR}" "${ENV_DIR}"
	${SUDO} ${SYSTEMCTL} daemon-reload
	${SUDO} ${SYSTEMCTL} enable --now "${APP_NAME}"
}

remove_service() {
	${SUDO} ${SYSTEMCTL} disable --now "${APP_NAME}" >/dev/null 2>&1 || true
	${SUDO} rm -f "${UNIT_DEST}" "${BIN_DEST}"
	if [ "${REMOVE_DATA:-0}" = "1" ]; then
		${SUDO} rm -rf "${APP_DIR}" "${ENV_DIR}"
	fi
	${SUDO} ${SYSTEMCTL} daemon-reload
}

case "${1:-}" in
install)
	install_service
	;;
remove)
	remove_service
	;;
*)
	usage >&2
	exit 2
	;;
esac
