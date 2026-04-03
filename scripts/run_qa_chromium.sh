#!/usr/bin/env bash
set -euo pipefail

QA_BASE_URL="${QA_BASE_URL:-http://127.0.0.1:45678}"
CHROME_PORT="${CHROME_PORT:-9222}"
CHROME_USER_DIR="${CHROME_USER_DIR:-/tmp/chromium-mcp}"
CHROME_BIN="${CHROME_BIN:-chromium}"
QA_HEADLESS="${QA_HEADLESS:-0}"

is_cdp_up() {
  curl -s "http://127.0.0.1:${CHROME_PORT}/json/version" >/dev/null 2>&1
}

wait_for_cdp() {
  local retries=50
  while [[ $retries -gt 0 ]]; do
    if is_cdp_up; then
      return 0
    fi
    retries=$((retries - 1))
    sleep 0.2
  done
  return 1
}

CHROME_PID=""
if ! is_cdp_up; then
  echo "[QA] Starting Chromium with remote debugging on port ${CHROME_PORT}..."
  CHROME_ARGS=(
    "--remote-debugging-port=${CHROME_PORT}"
    "--remote-allow-origins=*"
    "--user-data-dir=${CHROME_USER_DIR}"
    "--no-sandbox"
    "--disable-gpu"
    "about:blank"
  )
  if [[ "${QA_HEADLESS}" != "0" ]]; then
    CHROME_ARGS=("--headless=new" "${CHROME_ARGS[@]}")
  fi

  "${CHROME_BIN}" "${CHROME_ARGS[@]}" >/tmp/chromium-qa.log 2>&1 &
  CHROME_PID=$!
  trap '[[ -n "${CHROME_PID}" ]] && kill "${CHROME_PID}" >/dev/null 2>&1 || true' EXIT

  if ! wait_for_cdp; then
    echo "[QA] Failed to start Chromium remote debugging."
    exit 1
  fi
else
  echo "[QA] Reusing existing Chromium remote debugging on port ${CHROME_PORT}."
fi

export QA_BASE_URL
node scripts/qa_ui_cdp.js

echo "[QA] Report generated at QA/report.md"
