#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PACKAGE_NAME="porthound4"
OUTPUT_DIR="${ZIP_OUTPUT_DIR:-${REPO_ROOT}/dist/zip}"
REVISION="${ZIP_REVISION:-1}"

usage() {
  cat <<'USAGE'
Usage: packaging/zip/build.sh [options]

Options:
  --output-dir <dir>  Output directory for the .zip (default: dist/zip)
  --revision <rev>    Revision suffix (default: 1)
  -h, --help          Show this help

Environment overrides:
  ZIP_OUTPUT_DIR, ZIP_REVISION
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --revision)
      REVISION="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! command -v zip >/dev/null 2>&1; then
  echo "Missing required command: zip" >&2
  exit 1
fi

if [[ "${OUTPUT_DIR}" != /* ]]; then
  OUTPUT_DIR="${REPO_ROOT}/${OUTPUT_DIR}"
fi

VERSION="$(awk -F'"' '/^version = / { print $2; exit }' "${REPO_ROOT}/pyproject.toml")"
if [[ -z "${VERSION}" ]]; then
  echo "Unable to read version from pyproject.toml" >&2
  exit 1
fi

PKG_VERSION="${VERSION}-${REVISION}"
ROOT_DIR_NAME="${PACKAGE_NAME}_${PKG_VERSION}"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/porthound4-zip.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT
STAGE_DIR="${WORK_DIR}/${ROOT_DIR_NAME}"

mkdir -p "${STAGE_DIR}"

copy_entry() {
  local rel="$1"
  local src="${REPO_ROOT}/${rel}"
  if [[ ! -e "${src}" ]]; then
    echo "Missing runtime path: ${rel}" >&2
    exit 1
  fi
  local dst_parent="${STAGE_DIR}/$(dirname "${rel}")"
  mkdir -p "${dst_parent}"
  cp -a "${src}" "${dst_parent}/"
}

RUNTIME_ENTRIES=(
  "manage.py"
  "app.py"
  "master.py"
  "agent.py"
  "server.py"
  "framework.py"
  "settings.py"
  "ws_demo.py"
  "banner_rules.py"
  "scan_payloads.py"
  "geoip_seed.py"
  "getDBNIC.py"
  "country_centroids.py"
  "data"
  "docs"
  "README.md"
  "INSTALL.md"
  "DEPLOYMENT.md"
  "LICENSE"
  "SECURITY.md"
)

for entry in "${RUNTIME_ENTRIES[@]}"; do
  copy_entry "${entry}"
done

if [[ -d "${REPO_ROOT}/frontend/dist" ]]; then
  mkdir -p "${STAGE_DIR}/frontend"
  cp -a "${REPO_ROOT}/frontend/dist" "${STAGE_DIR}/frontend/"
fi

cat > "${STAGE_DIR}/START_HERE.txt" <<'EOF'
PortHound4 package
==================

Quick start:
  python3 manage.py

Main docs:
  README.md
  INSTALL.md
  DEPLOYMENT.md
EOF

mkdir -p "${OUTPUT_DIR}"
OUTPUT_FILE="${OUTPUT_DIR}/${ROOT_DIR_NAME}.zip"

(
  cd "${WORK_DIR}"
  zip -qr "${OUTPUT_FILE}" "${ROOT_DIR_NAME}"
)

echo "Built package: ${OUTPUT_FILE}"
