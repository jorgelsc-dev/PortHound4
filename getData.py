#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

import banner_rules
import getDBNIC
from server import DB, DEFAULT_BANNER_RULES_FILE, DEFAULT_BANNER_REQUESTS_FILE, DEFAULT_IP_PRESETS_FILE


def _write_json(path: Path, payload: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp_path.replace(path)


def _ensure_banner_rules_file(force=False):
    path = Path(DEFAULT_BANNER_RULES_FILE)
    if path.exists() and not force:
        return False
    rules = []
    for row in banner_rules.BANNER_REGEX_RULES:
        if not isinstance(row, dict):
            continue
        rule_id = str(row.get("id", "")).strip()
        if not rule_id:
            continue
        entry = dict(row)
        entry["rule_key"] = str(row.get("rule_key", "") or rule_id)
        rules.append(entry)
    _write_json(path, {"version": 1, "rules": rules})
    return True


def _ensure_banner_requests_file(force=False):
    path = Path(DEFAULT_BANNER_REQUESTS_FILE)
    if path.exists() and not force:
        return False
    db = DB(path=":memory:")
    requests = []
    for row in db._iter_builtin_probe_requests():
        requests.append(
            {
                "request_key": str(row.get("request_key", "") or ""),
                "name": str(row.get("name", "") or ""),
                "proto": str(row.get("proto", "") or ""),
                "scope": str(row.get("scope", "") or ""),
                "port": int(row.get("port", 0) or 0),
                "payload_format": str(row.get("payload_format", "base64") or "base64"),
                "payload_encoded": str(row.get("payload_encoded", "") or ""),
                "description": str(row.get("description", "") or ""),
                "active": bool(int(row.get("active", 1) or 1)),
            }
        )
    _write_json(path, {"version": 1, "requests": requests})
    return True


def _ensure_ip_presets_file(force=False):
    path = Path(DEFAULT_IP_PRESETS_FILE)
    if path.exists() and not force:
        return False
    defaults = [
        {
            "value": "127.0.0.1",
            "label": "Localhost",
            "description": "Loopback host for local scanner tests.",
        },
        {
            "value": "10.0.0.0/24",
            "label": "Private Net A",
            "description": "Private CIDR preset for lab scanning.",
        },
        {
            "value": "192.168.1.0/24",
            "label": "Home LAN preset",
            "description": "Typical local network preset.",
        },
    ]
    _write_json(path, {"version": 1, "ips": defaults})
    return True


def ensure_catalog_files(force=False):
    changed = []
    if _ensure_banner_rules_file(force=force):
        changed.append(str(DEFAULT_BANNER_RULES_FILE))
    if _ensure_banner_requests_file(force=force):
        changed.append(str(DEFAULT_BANNER_REQUESTS_FILE))
    if _ensure_ip_presets_file(force=force):
        changed.append(str(DEFAULT_IP_PRESETS_FILE))
    return changed


def sync_geoip_seed():
    getDBNIC.main()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Fetch external data and build seed files for PortHound.")
    parser.add_argument("--geoip", action="store_true", help="Download NIC allocations and build GeoIP seed file.")
    parser.add_argument("--catalog", action="store_true", help="Ensure catalog seed files exist.")
    parser.add_argument("--all", action="store_true", help="Run both catalog and geoip tasks.")
    parser.add_argument("--force", action="store_true", help="Overwrite existing catalog files.")
    args = parser.parse_args(argv)

    if not (args.geoip or args.catalog or args.all):
        parser.print_help()
        return 1

    if args.all or args.catalog:
        changed = ensure_catalog_files(force=args.force)
        if changed:
            print("catalog files updated:")
            for item in changed:
                print(f"- {item}")
        else:
            print("catalog files already present")

    if args.all or args.geoip:
        print("building geoip seed...")
        sync_geoip_seed()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
