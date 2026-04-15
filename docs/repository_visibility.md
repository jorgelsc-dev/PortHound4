# Repository Visibility Playbook

This checklist improves GitHub discoverability and helps code search indexing for PortHound4.

## 1) Set About metadata (GitHub UI/CLI)

Use this description:

`Distributed Python network scanner with master/agent orchestration, TCP/UDP/ICMP/SCTP probing, banner grabbing, SQLite persistence, and HTTP/WebSocket APIs.`

Use these topics:

`python`, `cybersecurity`, `network-scanner`, `port-scanner`, `banner-grabbing`, `tcp`, `udp`, `icmp`, `sctp`, `sqlite`, `websocket`, `api`, `threading`, `security-audit`, `pentest-tools`

CLI path:

```bash
gh auth login
./scripts/set_github_about.sh
```

## 2) Keep repo index-friendly

- Keep generated files out of git (`*.db`, `dist/`, `frontend/dist/`, virtualenvs).
- Keep the README opening section explicit about protocols, architecture, and use case.
- Keep CI green so the repo signals maintenance activity.

Run local verification:

```bash
./scripts/repo_visibility_check.sh
```

## 3) Maintain public-facing quality

- Add 1-3 screenshots in `docs/screenshots/`.
- Keep `SECURITY.md`, `CONTRIBUTING.md`, and `CODE_OF_CONDUCT.md` updated.
- Keep `CHANGELOG.md` and `ROADMAP.md` aligned with real progress.

## 4) If code search still shows "indexing"

- Wait a few minutes and retry.
- Push a small commit to the default branch.
- If it persists for an unusual amount of time, open a GitHub Support ticket.
