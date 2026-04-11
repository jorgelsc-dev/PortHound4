# Install

## Requirements
- Python 3.11+
- Node.js 18+ (only for frontend)

## Backend
```bash
python3 -m venv env
env/bin/python -m pip install --upgrade pip
env/bin/python manage.py
```

Default run mode is `master` on `0.0.0.0:45678` with role DB (`Master.db` by default).

For distributed mode (`master + agent`), follow `README.md` or `FAST_DOCKER.md`.

## Frontend
```bash
cd frontend
npm install
npm run serve
```
