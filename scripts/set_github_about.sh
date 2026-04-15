#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-jorgelsc-dev/PortHound4}"

if ! gh auth status -h github.com >/dev/null 2>&1; then
  echo "GitHub CLI is not authenticated for github.com."
  echo "Run: gh auth login -h github.com"
  exit 1
fi

gh repo edit "$REPO" \
  --description "Distributed Python network scanner with master/agent orchestration, TCP/UDP/ICMP/SCTP probing, banner grabbing, SQLite persistence, and HTTP/WebSocket APIs." \
  --add-topic python \
  --add-topic cybersecurity \
  --add-topic network-scanner \
  --add-topic port-scanner \
  --add-topic banner-grabbing \
  --add-topic tcp \
  --add-topic udp \
  --add-topic icmp \
  --add-topic sctp \
  --add-topic sqlite \
  --add-topic websocket \
  --add-topic api \
  --add-topic threading \
  --add-topic security-audit \
  --add-topic pentest-tools

echo "Updated About metadata for $REPO"
