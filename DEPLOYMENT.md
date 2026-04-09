# Deployment

## Minimal (local)
```bash
python manage.py
```

For a quick GHCR-based `master + agent` deployment, see `FAST_DOCKER.md`.

## Docker image by branch (GitHub Actions)
- Workflow: `.github/workflows/docker-branches.yml`
- Trigger: push to `develop` or `production`
- Image registry: `ghcr.io`
- Generated tags:
  - `develop` branch -> `ghcr.io/<owner>/porthound4:develop`
  - `production` branch -> `ghcr.io/<owner>/porthound4:production`

### Commands to trigger from git
```bash
# develop
git checkout develop
git push origin develop

# production
git checkout production
git push origin production
```

### Equivalent local Docker commands
```bash
IMAGE=ghcr.io/<owner>/porthound4

docker build -t ${IMAGE}:develop .
docker build -t ${IMAGE}:production .
```

### Push manually to GHCR (optional)
Use a token with `write:packages`.

```bash
IMAGE=ghcr.io/<owner>/porthound4
echo "<GHCR_TOKEN>" | docker login ghcr.io -u "<owner>" --password-stdin

docker push ${IMAGE}:develop
docker push ${IMAGE}:production
```

## GitHub Release automatico (main)
- Workflow: `.github/workflows/package.yml`
- Trigger: push a `main` (o tag con prefijo `v`)
- Resultado: compila artefactos y crea un GitHub Release con assets adjuntos.
- En `main` se genera un tag automatico con formato `main-<run>.<attempt>-<sha7>`.

### Comandos para release estable (main, automatico)
```bash
git checkout main
git pull origin main
git push origin main
```

### Comandos opcionales para release por version (tag)
```bash
# ejemplo release versionada
git checkout main
git pull origin main
git tag v1.2.0
git push origin v1.2.0
```

## Systemd (Linux)
Create a service file at `/etc/systemd/system/porthound.service`:

```
[Unit]
Description=PortHound
After=network.target

[Service]
WorkingDirectory=/opt/porthound
ExecStart=/usr/bin/python3 /opt/porthound/manage.py
Restart=always
User=porthound
Group=porthound
Environment=PORTHOUND_API_TOKEN=change-me
Environment=PORTHOUND_CORS_ALLOW_ORIGIN=https://your-ui.example

[Install]
WantedBy=multi-user.target
```

Then:
```bash
sudo systemctl daemon-reload
sudo systemctl enable porthound
sudo systemctl start porthound
```

## Reverse proxy (optional)
Place Nginx or Caddy in front if you need TLS, auth, or rate limits.

## Notes
- Ensure the process has write access to the role DB path (`PORTHOUND_DB_PATH`).
- Default role DB names:
  - `master` -> `Master.db`
  - `agent` -> `Agent.db`
  - `standalone` -> `Standalone.db`
- Keep the service in a trusted environment and with explicit authorization.
