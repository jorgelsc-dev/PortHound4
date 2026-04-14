#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PACKAGE_NAME="porthound4"
ARCH="${DEB_ARCH:-all}"
REVISION="${DEB_REVISION:-1}"
OUTPUT_DIR="${DEB_OUTPUT_DIR:-${REPO_ROOT}/dist/deb}"
MAINTAINER="${DEB_MAINTAINER:-PortHound4 Authors <security@example.invalid>}"
SECTION="${DEB_SECTION:-net}"
PRIORITY="${DEB_PRIORITY:-optional}"

usage() {
  cat <<'USAGE'
Usage: packaging/deb/build.sh [options]

Options:
  --output-dir <dir>   Output directory for the .deb (default: dist/deb)
  --arch <arch>        Debian architecture (default: all)
  --revision <rev>     Debian revision suffix (default: 1)
  --maintainer <text>  Maintainer field value
  -h, --help           Show this help

Environment overrides:
  DEB_OUTPUT_DIR, DEB_ARCH, DEB_REVISION, DEB_MAINTAINER, DEB_SECTION, DEB_PRIORITY
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --arch)
      ARCH="$2"
      shift 2
      ;;
    --revision)
      REVISION="$2"
      shift 2
      ;;
    --maintainer)
      MAINTAINER="$2"
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

for cmd in dpkg-deb fakeroot; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Missing required command: ${cmd}" >&2
    exit 1
  fi
done

VERSION="$(awk -F'"' '/^version = / { print $2; exit }' "${REPO_ROOT}/pyproject.toml")"
if [[ -z "${VERSION}" ]]; then
  echo "Unable to read version from pyproject.toml" >&2
  exit 1
fi
DEB_VERSION="${VERSION}-${REVISION}"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/porthound4-deb.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT
PKG_DIR="${WORK_DIR}/${PACKAGE_NAME}_${DEB_VERSION}_${ARCH}"

mkdir -p \
  "${PKG_DIR}/DEBIAN" \
  "${PKG_DIR}/opt/porthound4" \
  "${PKG_DIR}/usr/bin" \
  "${PKG_DIR}/lib/systemd/system" \
  "${PKG_DIR}/etc/default" \
  "${PKG_DIR}/var/lib/porthound4" \
  "${PKG_DIR}/usr/share/doc/${PACKAGE_NAME}"

copy_entry() {
  local rel="$1"
  local src="${REPO_ROOT}/${rel}"
  if [[ ! -e "${src}" ]]; then
    echo "Missing runtime path: ${rel}" >&2
    exit 1
  fi
  local dst_parent="${PKG_DIR}/opt/porthound4/$(dirname "${rel}")"
  mkdir -p "${dst_parent}"
  cp -a "${src}" "${dst_parent}/"
}

# Core runtime files.
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
  "LICENSE"
  "SECURITY.md"
)

for entry in "${RUNTIME_ENTRIES[@]}"; do
  copy_entry "${entry}"
done

# Frontend static bundle is optional in repo workflows.
if [[ -d "${REPO_ROOT}/frontend/dist" ]]; then
  mkdir -p "${PKG_DIR}/opt/porthound4/frontend"
  cp -a "${REPO_ROOT}/frontend/dist" "${PKG_DIR}/opt/porthound4/frontend/"
fi

cat > "${PKG_DIR}/usr/bin/porthound4" <<'EOF'
#!/bin/sh
set -e
exec /usr/bin/python3 /opt/porthound4/manage.py "$@"
EOF
chmod 0755 "${PKG_DIR}/usr/bin/porthound4"
ln -s porthound4 "${PKG_DIR}/usr/bin/porthound"

install -m 0644 "${SCRIPT_DIR}/porthound4.service" "${PKG_DIR}/lib/systemd/system/porthound4.service"
install -m 0644 "${SCRIPT_DIR}/porthound4.default" "${PKG_DIR}/etc/default/porthound4"

cat > "${PKG_DIR}/usr/share/doc/${PACKAGE_NAME}/README.Debian" <<'EOF'
PortHound4 Debian package
=========================

Service:
  sudo systemctl enable --now porthound4
  sudo systemctl status porthound4

Configuration:
  /etc/default/porthound4

Manual CLI:
  porthound4 --help
EOF

cat > "${PKG_DIR}/DEBIAN/control" <<EOF
Package: ${PACKAGE_NAME}
Version: ${DEB_VERSION}
Section: ${SECTION}
Priority: ${PRIORITY}
Architecture: ${ARCH}
Maintainer: ${MAINTAINER}
Depends: python3 (>= 3.11), adduser
Recommends: systemd-sysv | systemd
Description: PortHound4 network scanner with master/agent orchestration
 PortHound4 is a Python network scanner with HTTP/WebSocket API, banner grabbing,
 and master/agent task orchestration.
EOF

cat > "${PKG_DIR}/DEBIAN/conffiles" <<'EOF'
/etc/default/porthound4
EOF

cat > "${PKG_DIR}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

if ! id -u porthound >/dev/null 2>&1; then
  adduser --system --group --home /var/lib/porthound4 --no-create-home porthound || true
fi

mkdir -p /var/lib/porthound4
chown porthound:porthound /var/lib/porthound4 || true
chmod 0750 /var/lib/porthound4 || true

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
EOF
chmod 0755 "${PKG_DIR}/DEBIAN/postinst"

cat > "${PKG_DIR}/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
EOF
chmod 0755 "${PKG_DIR}/DEBIAN/postrm"

find "${PKG_DIR}" -type d -print0 | xargs -0 chmod 0755
find "${PKG_DIR}" -type f -print0 | xargs -0 chmod 0644
chmod 0755 "${PKG_DIR}/usr/bin/porthound4"
chmod 0755 "${PKG_DIR}/DEBIAN/postinst" "${PKG_DIR}/DEBIAN/postrm"

mkdir -p "${OUTPUT_DIR}"
OUTPUT_FILE="${OUTPUT_DIR}/${PACKAGE_NAME}_${DEB_VERSION}_${ARCH}.deb"
fakeroot dpkg-deb --build "${PKG_DIR}" "${OUTPUT_FILE}" >/dev/null

echo "Built package: ${OUTPUT_FILE}"
