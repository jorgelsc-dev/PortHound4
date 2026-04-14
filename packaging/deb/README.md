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
- Service: `/lib/systemd/system/porthound4.service`
- Service env: `/etc/default/porthound4`
- Data dir: `/var/lib/porthound4`
