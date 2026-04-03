# Deployment

## Minimal (local)
```bash
python manage.py
```

## Docker image by branch (GitHub Actions)
- Workflow: `.github/workflows/docker-branches.yml`
- Trigger: push to `develop`, `production`, or `main`
- Image registry: `ghcr.io`
- Generated tags:
  - `develop` branch -> `ghcr.io/<owner>/porthound4:develop`
  - `production` branch -> `ghcr.io/<owner>/porthound4:production`
  - `main` branch -> `ghcr.io/<owner>/porthound4:main`

### Commands to trigger from git
```bash
# develop
git checkout develop
git push origin develop

# production
git checkout production
git push origin production

# main
git checkout main
git push origin main
```

### Equivalent local Docker commands
```bash
IMAGE=ghcr.io/<owner>/porthound4

docker build -t ${IMAGE}:develop .
docker build -t ${IMAGE}:production .
docker build -t ${IMAGE}:main .
```

### Push manually to GHCR (optional)
Use a token with `write:packages`.

```bash
IMAGE=ghcr.io/<owner>/porthound4
echo "<GHCR_TOKEN>" | docker login ghcr.io -u "<owner>" --password-stdin

docker push ${IMAGE}:develop
docker push ${IMAGE}:production
docker push ${IMAGE}:main
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
- Ensure the process has write access to `Database.db`.
- Keep the service in a trusted environment and with explicit authorization.
