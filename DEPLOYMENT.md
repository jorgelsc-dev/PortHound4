# Deployment

## Minimal (local)
```bash
python manage.py
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
