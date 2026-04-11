# Getting Started

## Quick start
```bash
python manage.py
```
Open `http://localhost:45678/`.

For `master + agent` mode, create agent credentials from:
`http://localhost:45678/cluster/agents/`

## Create a target
```bash
curl -X POST http://localhost:45678/target/ \
  -H "Content-Type: application/json" \
  -d '{"network":"10.0.0.0/24","type":"common","proto":"tcp","timesleep":1.0}'
```

## Read results
```bash
curl http://localhost:45678/ports/tcp/
```

## If API token is enabled

When `PORTHOUND_API_TOKEN` is configured, include it in admin/mutating requests:

```bash
curl -X POST http://localhost:45678/target/ \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"network":"10.0.0.0/24","type":"common","proto":"tcp","timesleep":1.0}'
```
