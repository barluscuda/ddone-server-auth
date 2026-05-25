#!/usr/bin/env bash

set -euo pipefail

APP_NAME="${APP_NAME:-ddone-server-auth}"
APP_PKG="${APP_PKG:-./cmd/app}"
GO_CMD="${GO_CMD:-go}"
ZIP_CMD="${ZIP_CMD:-}"
PYTHON_CMD="${PYTHON_CMD:-python3}"

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || date +%Y%m%d%H%M%S)}"
OUT_DIR="${OUT_DIR:-dist}"
GOOS="${GOOS:-linux}"
GOARCHES="${GOARCHES:-amd64 arm64}"

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
- deploy/systemd/

Run:
1. Copy the files to the target host.
2. Edit config/config.yaml or override with DDONE_* environment variables.
3. Start the service with:
   ./${APP_NAME}

systemd assets:
- deploy/systemd/${APP_NAME}.service
- deploy/systemd/${APP_NAME}.env.example
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
	cp "${ROOT_DIR}/deploy/systemd/${APP_NAME}.service" "${stage_dir}/deploy/systemd/"
	cp "${ROOT_DIR}/deploy/systemd/${APP_NAME}.env.example" "${stage_dir}/deploy/systemd/"
	cp "${ROOT_DIR}/README.md" "${stage_dir}/"
	write_binary_notes "${stage_dir}/RUN.txt"

	zip_dir "${archive_path}" "${stage_dir}"
	echo "created ${archive_path}"
}

main() {
	require_cmd "${GO_CMD}"
	mkdir -p "${DIST_DIR}"

	for arch in ${GOARCHES}; do
		build_binary_release "${arch}"
	done
}

main "$@"
