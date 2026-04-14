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

Start service:

```bash
sudo systemctl enable --now porthound4
sudo systemctl status porthound4
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
