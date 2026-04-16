# GitHub Publication Kit - PortHound4

## 1) Repo identity
- Name: `PortHound4`
- Suggested URL: `https://github.com/<tu-usuario>/PortHound4`
- Visibility: `Public`
- License: `MIT`

## 2) About section (copy/paste)

### Short description (EN)
Distributed Python network scanner with TCP/UDP probing, banner grabbing, SQLite persistence, and HTTP/WebSocket APIs.

### Short description (ES)
Scanner de red distribuido en Python con sondeo TCP/UDP, captura de banners, persistencia SQLite y API HTTP/WebSocket.

### Website (optional)
Leave empty, or set a docs/demo URL later.

### Apply from terminal (GitHub CLI)

```bash
gh auth login
gh repo edit jorgelsc-dev/PortHound4 \
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
```

Or run the helper script from this repo:

```bash
gh auth login
./scripts/set_github_about.sh
```

If `gh auth status` reports an invalid token, re-authenticate:

```bash
gh auth login -h github.com
```

Validate repository discoverability checks:

```bash
./scripts/repo_visibility_check.sh
```

## 3) Topics (GitHub tags)
`python`, `cybersecurity`, `network-scanner`, `port-scanner`, `banner-grabbing`, `tcp`, `udp`, `sqlite`, `websocket`, `api`, `threading`, `security-audit`, `pentest-tools`

## 4) CV-ready one-liner
PortHound4 is a Python-based distributed network scanner with resumable TCP/UDP scans, banner fingerprinting, and a lightweight HTTP/WS control plane.

## 5) Public release checklist
1. Confirm you only scan systems you own or have written authorization to test.
2. Keep repo public warning text in `README.md` (Responsible Use section).
3. Verify local secrets are ignored (`.env*`, `env/`, local certs, DB files).
4. Create the GitHub repository without auto-generating README/.gitignore/license (already present).
5. Push local code to `main`.

## 6) Commands to publish

```bash
git init
git add .
git commit -m "chore: initial public release of PortHound4"
git branch -M main
git remote add origin https://github.com/<tu-usuario>/PortHound4.git
git push -u origin main
```

SSH remote alternative:

```bash
git remote set-url origin git@github.com:<tu-usuario>/PortHound4.git
git push -u origin main
```

## 7) Recommended repo settings
1. Enable Issues and Discussions.
2. Keep Wiki disabled unless you will maintain it.
3. Add `SECURITY.md` and `CODE_OF_CONDUCT.md` badges/links in README (optional).
4. Pin this repo on your GitHub profile.
5. Add 1-3 screenshots or GIFs in the README for stronger CV impact.
