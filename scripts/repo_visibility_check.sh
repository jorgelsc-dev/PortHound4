#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

errors=0
warnings=0

ok() {
  echo "[ok] $1"
}

warn() {
  warnings=$((warnings + 1))
  echo "[warn] $1"
}

fail() {
  errors=$((errors + 1))
  echo "[fail] $1"
}

check_file() {
  local file="$1"
  if [[ -f "$file" ]]; then
    ok "found $file"
  else
    fail "missing $file"
  fi
}

echo "== PortHound4 repository visibility checks =="

check_file "README.md"
check_file "SECURITY.md"
check_file "CONTRIBUTING.md"
check_file "CODE_OF_CONDUCT.md"
check_file ".github/workflows/ci.yml"
check_file ".github/workflows/package.yml"
check_file "scripts/set_github_about.sh"

if rg -q "network-scanner" README.md && rg -q "master/agent" README.md; then
  ok "README includes core discoverability keywords"
else
  warn "README is missing one or more core keywords (network-scanner, master/agent)"
fi

tracked_db="$(git ls-files -- '*.db' '*.sqlite' '*.sqlite3' || true)"
if [[ -n "$tracked_db" ]]; then
  fail "tracked database files detected:\n$tracked_db"
else
  ok "no tracked database files"
fi

tracked_dist="$(git ls-files -- 'dist/**' 'frontend/dist/**' || true)"
if [[ -n "$tracked_dist" ]]; then
  fail "tracked build artifacts detected:\n$tracked_dist"
else
  ok "no tracked dist artifacts"
fi

if git check-ignore -q docs/screenshots/README.md; then
  warn "docs/screenshots/README.md is ignored unexpectedly"
else
  ok "screenshots docs path is tracked"
fi

echo
echo "Summary: errors=$errors warnings=$warnings"

if [[ "$errors" -gt 0 ]]; then
  exit 1
fi
