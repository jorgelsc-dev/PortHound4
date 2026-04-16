# Debian packaging

Build a local `.deb` package:

```bash
./packaging/deb/build.sh
```

Custom output dir:

```bash
./packaging/deb/build.sh --output-dir /tmp/deb
```

Install using `apt`:

```bash
sudo apt install ./dist/deb/porthound4_<version>-1_all.deb
```

Runtime paths after install:

- App code: `/opt/porthound4`
- CLI: `/usr/bin/porthound4` (alias `/usr/bin/porthound`)

Run in terminal (interactive):

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

If you are upgrading from an older service-based package, stop and disable legacy service mode once:

```bash
sudo systemctl disable --now porthound4.service
```
