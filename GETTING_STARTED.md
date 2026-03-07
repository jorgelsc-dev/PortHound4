# Getting Started

## Quick start
```bash
python manage.py --tls-enabled 0
```
Open `http://localhost:45678/`.

For secure cluster mode (recommended), use the PKI flow from `README.md`.

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
