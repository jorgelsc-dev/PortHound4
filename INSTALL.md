# Install

## Requirements
- Python 3.10+
- Node.js 18+ (only for frontend)

## Backend
```bash
python -m venv .venv
source .venv/bin/activate
python manage.py --tls-enabled 0
```

For TLS/mTLS deployment, configure certificates as documented in `README.md`.

## Frontend
```bash
cd frontend
npm install
npm run serve
```
