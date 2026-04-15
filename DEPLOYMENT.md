# Deployment

## Minimal (local)
```bash
python manage.py
```

## Debian / APT package (`.deb`)

Build:

```bash
./packaging/deb/build.sh
```

Install:

```bash
sudo apt install ./dist/deb/porthound4_<version>-1_all.deb
```

Run interactively:

```bash
porthound4
# stop with Ctrl+C
```

Master mode (explicit):

```bash
porthound4 --role master --host 0.0.0.0 --port 45678 --db-path ./Master.db
```

Agent mode:

```bash
porthound4 --role agent --master http://127.0.0.1:45678 --agent-id <id> --agent-token <token>
```

Legacy migration (only if an older service install is still active):

```bash
sudo systemctl disable --now porthound4.service
```

## Portable ZIP package

Build:

```bash
./packaging/zip/build.sh
```

Use:

```bash
unzip dist/zip/porthound4_<version>-1.zip
cd porthound4_<version>-1
python3 manage.py
```

## GitHub Release automatico (main)

- Workflow: `.github/workflows/package.yml`
- Trigger: push a `main` (o `workflow_dispatch`)
- Resultado: crea release y publica 2 assets:
  - `porthound4_<version>-<rev>_all.deb`
  - `porthound4_<version>-<rev>.zip`
- Tag automatico en `main`: `main-<run>.<attempt>-<sha7>`

## Reverse proxy (optional)

Place Nginx or Caddy in front if you need TLS, auth, or rate limits.

## Notes

- Ensure the process has write access to the role DB path (`PORTHOUND_DB_PATH`).
- Default role DB names:
  - `master` -> `Master.db`
  - `agent` -> `Agent.db`
  - `standalone` -> `Standalone.db`
- Keep the service in a trusted environment and with explicit authorization.
