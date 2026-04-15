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

For distributed mode (`master + agent`), follow `README.md`.

## Frontend
```bash
cd frontend
npm install
npm run serve
```

## Debian / APT package (`.deb`)

Build package:

```bash
./packaging/deb/build.sh
```

Install with `apt`:

```bash
sudo apt install ./dist/deb/porthound4_<version>-1_all.deb
```

Run interactively:

```bash
porthound4
# stop with Ctrl+C
```

Explicit master example:

```bash
porthound4 --role master --host 0.0.0.0 --port 45678 --db-path ./Master.db
```

Agent example:

```bash
porthound4 --role agent --master http://127.0.0.1:45678 --agent-id <id> --agent-token <token>
```

If you are upgrading from an old service-based install:

```bash
sudo systemctl disable --now porthound4.service
```

## Portable ZIP package

Build package:

```bash
./packaging/zip/build.sh
```

Extract and run:

```bash
unzip dist/zip/porthound4_<version>-1.zip
cd porthound4_<version>-1
python3 manage.py
```
