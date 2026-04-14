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

Service defaults:

```text
/etc/default/porthound4
```

Enable/start service:

```bash
sudo systemctl enable --now porthound4
sudo systemctl status porthound4
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
