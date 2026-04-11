# Contributing

Thanks for your interest in PortHound.

## Ground rules

- Use this tool only for authorized security work.
- Keep changes focused and small when possible.
- Avoid adding heavy dependencies without prior discussion.
- Update docs whenever behavior changes.

## Branching and pull requests

1. Fork the repository and branch from `develop` using `feat/<name>` or `fix/<name>`.
2. Write clear commits with one logical change per commit.
3. Open a pull request to `develop` with a short summary and risk notes.
4. Include validation output for backend and frontend checks.

## Local development

- Backend: `python manage.py`
- Frontend: `cd frontend && npm install && npm run serve`

## Local validation before opening PR

Run from repo root:

```bash
python -m compileall -q .
python -m unittest discover -s tests -q
```

Run frontend checks:

```bash
cd frontend
npm ci
npm run lint
npm run build
```

## Reporting issues

Use issue templates and include:

- OS / Python / Node versions
- Steps to reproduce
- Expected behavior and actual behavior
- Relevant logs or screenshots

## Security

Please do not open public issues for vulnerabilities.
See `SECURITY.md` for private reporting.

## Optional financial support

If you want to support project maintenance, donation details are in `SUPPORT.md`.
