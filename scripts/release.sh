#!/usr/bin/env bash

set -euo pipefail

APP_NAME="${APP_NAME:-ddone-server-auth}"
APP_PKG="${APP_PKG:-./cmd/app}"
GO_CMD="${GO_CMD:-go}"
DOCKER_CMD="${DOCKER_CMD:-docker}"
ZIP_CMD="${ZIP_CMD:-}"
PYTHON_CMD="${PYTHON_CMD:-python3}"

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || date +%Y%m%d%H%M%S)}"
OUT_DIR="${OUT_DIR:-dist}"
GOOS="${GOOS:-linux}"
GOARCHES="${GOARCHES:-amd64 arm64}"
DOCKER_RELEASE="${DOCKER_RELEASE:-1}"
DOCKER_PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/${OUT_DIR}"
TMP_DIR="$(mktemp -d)"

cleanup() {
	rm -rf "${TMP_DIR}"
}

trap cleanup EXIT

require_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

zip_dir() {
	local archive_path="$1"
	local source_dir="$2"

	if [[ -n "${ZIP_CMD}" ]] && command -v "${ZIP_CMD}" >/dev/null 2>&1; then
		(
			cd "$(dirname "${source_dir}")"
			"${ZIP_CMD}" -rq "${archive_path}" "$(basename "${source_dir}")"
		)
		return
	fi

	require_cmd "${PYTHON_CMD}"
	"${PYTHON_CMD}" - "${archive_path}" "${source_dir}" <<'PY'
import pathlib
import sys
import zipfile

archive = pathlib.Path(sys.argv[1])
source = pathlib.Path(sys.argv[2]).resolve()
base = source.parent

with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for path in sorted(source.rglob("*")):
        if path.is_dir():
            continue
        zf.write(path, path.relative_to(base))
PY
}

arch_label() {
	case "$1" in
	amd64)
		echo "x86_64"
		;;
	arm64)
		echo "arm64"
		;;
	*)
		echo "$1"
		;;
	esac
}

write_binary_notes() {
	local target_file="$1"
	cat >"${target_file}" <<EOF
${APP_NAME} ${VERSION}

Contents:
- ${APP_NAME}
- config/
- .env.example
- deploy/systemd/
- start.sh
- systemctl.sh

Run:
1. Copy the files to the target host.
2. Edit config/config.yaml or override with DDONE_* environment variables.
3. Start the service with:
   ./start.sh

Install systemd service:
   ./systemctl.sh install

Remove systemd service:
   ./systemctl.sh remove

systemd assets:
- deploy/systemd/${APP_NAME}.service
- .env.example
EOF
}

write_docker_compose() {
	local target_file="$1"
	local image_ref="$2"
	cat >"${target_file}" <<EOF
services:
  app:
    image: \${DDONE_DOCKER_IMAGE:-${image_ref}}
    pull_policy: never
    container_name: ${APP_NAME}
    restart: unless-stopped
    env_file:
      - .env
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    environment:
      DDONE_APP_PORT: \${DDONE_APP_PORT:-3000}
      DDONE_DATABASE_HOST: postgres
      DDONE_DATABASE_PORT: 5432
      DDONE_DATABASE_NAME: \${DDONE_DATABASE_NAME:-ddone_auth}
      DDONE_DATABASE_USERNAME: \${DDONE_DATABASE_USERNAME:-postgres}
      DDONE_DATABASE_PASSWORD: \${DDONE_DATABASE_PASSWORD:-postgres}
      DDONE_DATABASE_SSLMODE: disable
      DDONE_REDIS_HOST: redis
      DDONE_REDIS_PORT: 6379
      DDONE_REDIS_DB: \${DDONE_REDIS_DB:-0}
      DDONE_SECURITY_AUTH_SESSION_COOKIE_SECURE: \${DDONE_SECURITY_AUTH_SESSION_COOKIE_SECURE:-false}
      DDONE_WENOVA_TOKEN: \${DDONE_WENOVA_TOKEN:-}
    ports:
      - "\${DDONE_APP_PORT:-3000}:3000"
    networks:
      - ddone-network

  postgres:
    image: postgres:17-alpine
    container_name: ddone-postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: \${DDONE_DATABASE_NAME:-ddone_auth}
      POSTGRES_USER: \${DDONE_DATABASE_USERNAME:-postgres}
      POSTGRES_PASSWORD: \${DDONE_DATABASE_PASSWORD:-postgres}
      TZ: \${DDONE_DATABASE_TIMEZONE:-UTC}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./db/init:/docker-entrypoint-initdb.d:ro
    healthcheck:
      test:
        [
          "CMD-SHELL",
          "pg_isready -U \${DDONE_DATABASE_USERNAME:-postgres} -d \${DDONE_DATABASE_NAME:-ddone_auth}",
        ]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s
    networks:
      - ddone-network

  redis:
    image: redis:7-alpine
    container_name: ddone-redis
    restart: unless-stopped
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 5s
    networks:
      - ddone-network

volumes:
  postgres_data:
  redis_data:

networks:
  ddone-network:
    driver: bridge
EOF
}

write_docker_load_script() {
	local target_file="$1"
	cat >"${target_file}" <<'EOF'
#!/usr/bin/env sh

set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
IMAGE_TAR="${IMAGE_TAR:-$(find "${SCRIPT_DIR}/docker-image" -type f -name '*.tar' | sort | head -n 1)}"
DOCKER="${DOCKER:-docker}"

if [ -z "${IMAGE_TAR}" ] || [ ! -f "${IMAGE_TAR}" ]; then
	echo "missing docker image tar in ${SCRIPT_DIR}/docker-image" >&2
	exit 1
fi

"${DOCKER}" load -i "${IMAGE_TAR}"
EOF
}

write_docker_up_script() {
	local target_file="$1"
	cat >"${target_file}" <<'EOF'
#!/usr/bin/env sh

set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
DOCKER="${DOCKER:-docker}"
COMPOSE_FILE="${COMPOSE_FILE:-${SCRIPT_DIR}/docker-compose.yml}"
ENV_FILE="${ENV_FILE:-${SCRIPT_DIR}/.env}"

if [ ! -f "${ENV_FILE}" ]; then
	cp "${SCRIPT_DIR}/.env.example" "${ENV_FILE}"
	echo "created ${ENV_FILE}; edit it before exposing this service"
fi

"${SCRIPT_DIR}/docker-load.sh"
"${DOCKER}" compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" up -d
EOF
}

write_docker_down_script() {
	local target_file="$1"
	cat >"${target_file}" <<'EOF'
#!/usr/bin/env sh

set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
DOCKER="${DOCKER:-docker}"
COMPOSE_FILE="${COMPOSE_FILE:-${SCRIPT_DIR}/docker-compose.yml}"
ENV_FILE="${ENV_FILE:-${SCRIPT_DIR}/.env}"

"${DOCKER}" compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" down
EOF
}

write_docker_notes() {
	local target_file="$1"
	local image_ref="$2"
	cat >"${target_file}" <<EOF
${APP_NAME} ${VERSION} Docker release

Contents:
- docker-image/${APP_NAME}_${VERSION}.tar
- docker-compose.yml
- .env.example
- config/config.yaml
- db/init/
- docker-load.sh
- docker-up.sh
- docker-down.sh

Run:
1. Load the local Docker image:
   ./docker-load.sh
2. Create and edit custom config:
   cp .env.example .env
3. Start the stack:
   ./docker-up.sh

The compose file runs the app from the local image ${image_ref} and uses pull_policy: never.
It does not build the app from source.
EOF
}

build_binary_release() {
	local arch="$1"
	local label
	label="$(arch_label "${arch}")"
	local stage_dir="${TMP_DIR}/${APP_NAME}_${VERSION}_${GOOS}-${label}"
	local archive_path="${DIST_DIR}/${APP_NAME}_${VERSION}_${GOOS}-${label}.zip"

	mkdir -p "${stage_dir}/config" "${stage_dir}/deploy/systemd"
	echo "building ${GOOS}/${arch}"
	(
		cd "${ROOT_DIR}"
		CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${arch}" \
			"${GO_CMD}" build -o "${stage_dir}/${APP_NAME}" "${APP_PKG}"
	)

	cp "${ROOT_DIR}/config/config.yaml" "${stage_dir}/config/config.yaml"
	cp "${ROOT_DIR}/.env.example" "${stage_dir}/.env.example"
	cp "${ROOT_DIR}/deploy/systemd/${APP_NAME}.service" "${stage_dir}/deploy/systemd/"
	cp "${ROOT_DIR}/deploy/release/start.sh" "${stage_dir}/start.sh"
	cp "${ROOT_DIR}/deploy/release/systemctl.sh" "${stage_dir}/systemctl.sh"
	chmod 0755 "${stage_dir}/start.sh" "${stage_dir}/systemctl.sh"
	cp "${ROOT_DIR}/README.md" "${stage_dir}/"
	write_binary_notes "${stage_dir}/RUN.txt"

	zip_dir "${archive_path}" "${stage_dir}"
	echo "created ${archive_path}"
}

build_docker_release() {
	if [[ "${DOCKER_RELEASE}" != "1" ]]; then
		echo "skipping Docker release because DOCKER_RELEASE=${DOCKER_RELEASE}"
		return
	fi

	require_cmd "${DOCKER_CMD}"

	local image_ref="${APP_NAME}:${VERSION}"
	local image_tar_name="${APP_NAME}_${VERSION}.tar"
	local stage_dir="${TMP_DIR}/${APP_NAME}_${VERSION}_docker"
	local archive_path="${DIST_DIR}/${APP_NAME}_${VERSION}_docker.zip"

	mkdir -p "${stage_dir}/docker-image" "${stage_dir}/config" "${stage_dir}/db/init"

	echo "building Docker image ${image_ref} for ${DOCKER_PLATFORM}"
	(
		cd "${ROOT_DIR}"
		"${DOCKER_CMD}" build --platform "${DOCKER_PLATFORM}" -t "${image_ref}" .
	)
	"${DOCKER_CMD}" save "${image_ref}" -o "${stage_dir}/docker-image/${image_tar_name}"

	cp "${ROOT_DIR}/.env.example" "${stage_dir}/.env.example"
	cp "${ROOT_DIR}/config/config.yaml" "${stage_dir}/config/config.yaml"
	cp -R "${ROOT_DIR}/db/init/." "${stage_dir}/db/init/"
	write_docker_compose "${stage_dir}/docker-compose.yml" "${image_ref}"
	write_docker_load_script "${stage_dir}/docker-load.sh"
	write_docker_up_script "${stage_dir}/docker-up.sh"
	write_docker_down_script "${stage_dir}/docker-down.sh"
	write_docker_notes "${stage_dir}/RUN.txt" "${image_ref}"
	chmod 0755 "${stage_dir}/docker-load.sh" "${stage_dir}/docker-up.sh" "${stage_dir}/docker-down.sh"

	zip_dir "${archive_path}" "${stage_dir}"
	echo "created ${archive_path}"
}

main() {
	require_cmd "${GO_CMD}"
	mkdir -p "${DIST_DIR}"

	for arch in ${GOARCHES}; do
		build_binary_release "${arch}"
	done
	build_docker_release
}

main "$@"
