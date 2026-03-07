#!/usr/bin/env python3
import gzip
import json
import time
from ipaddress import IPv4Address
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
GEOIP_SEED_FORMAT = "porthound.geoip.seed.v1"
GEOIP_SEED_PATH = PROJECT_ROOT / "data" / "geoip_blocks.seed.jsonl.gz"


def resolve_geoip_seed_path(path=None):
    if path:
        return Path(path).expanduser().resolve()
    return GEOIP_SEED_PATH


def ensure_geoip_seed_parent(path=None):
    seed_path = resolve_geoip_seed_path(path)
    seed_path.parent.mkdir(parents=True, exist_ok=True)
    return seed_path


def open_geoip_seed(path=None, mode="rt"):
    seed_path = resolve_geoip_seed_path(path)
    if str(seed_path).lower().endswith(".gz"):
        if "b" in mode:
            return gzip.open(seed_path, mode)
        return gzip.open(seed_path, mode, encoding="utf-8", newline="")
    if "b" in mode:
        return open(seed_path, mode)
    return open(seed_path, mode, encoding="utf-8", newline="")


def normalize_geoip_seed_meta(payload, path=None):
    if not isinstance(payload, dict):
        return None
    if str(payload.get("kind", "")).strip().lower() != "meta":
        return None
    meta = dict(payload)
    meta["format"] = str(meta.get("format", "") or "").strip()
    meta["generated_at"] = str(meta.get("generated_at", "") or "").strip()
    meta["source_path"] = str(resolve_geoip_seed_path(path))
    try:
        meta["rows"] = max(0, int(meta.get("rows", 0) or 0))
    except Exception:
        meta["rows"] = 0
    meta["partial"] = bool(meta.get("partial"))
    if not isinstance(meta.get("selected_rirs"), list):
        meta["selected_rirs"] = []
    if not isinstance(meta.get("failed_rirs"), list):
        meta["failed_rirs"] = []
    return meta


def read_geoip_seed_meta(path=None):
    seed_path = resolve_geoip_seed_path(path)
    if not seed_path.exists() or not seed_path.is_file():
        return None
    try:
        with open_geoip_seed(seed_path, "rt") as handle:
            for raw_line in handle:
                line = str(raw_line or "").strip()
                if not line:
                    continue
                payload = json.loads(line)
                return normalize_geoip_seed_meta(payload, seed_path)
    except Exception:
        return None
    return None


def iter_geoip_seed_blocks(path=None):
    seed_path = resolve_geoip_seed_path(path)
    with open_geoip_seed(seed_path, "rt") as handle:
        meta_seen = False
        for raw_line in handle:
            line = str(raw_line or "").strip()
            if not line:
                continue
            payload = json.loads(line)
            kind = str(payload.get("kind", "") or "").strip().lower()
            if not meta_seen:
                if kind != "meta":
                    raise ValueError(f"invalid GeoIP seed header in {seed_path}")
                meta_seen = True
                continue
            if kind != "block":
                continue
            yield payload


def ensure_geoip_schema(cursor):
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS geoip_blocks ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "start_int INTEGER NOT NULL,"
        "end_int INTEGER NOT NULL,"
        "cidr TEXT NOT NULL,"
        "rir TEXT NOT NULL,"
        "area TEXT NOT NULL,"
        "country TEXT NOT NULL,"
        "lat REAL NOT NULL,"
        "lon REAL NOT NULL,"
        "UNIQUE(cidr)"
        ");"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_geoip_range ON geoip_blocks(start_int, end_int);"
    )
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS geoip_import_meta ("
        "k TEXT PRIMARY KEY,"
        "v TEXT NOT NULL"
        ");"
    )


def read_geoip_meta_from_db(cursor):
    meta = {}
    cursor.execute("SELECT k, v FROM geoip_import_meta;")
    for key, value in cursor.fetchall():
        meta[str(key)] = str(value)
    return meta


def _serialize_geoip_meta_value(value):
    if isinstance(value, (dict, list, bool, int, float)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if value is None:
        return ""
    return str(value)


def write_geoip_meta_to_db(cursor, meta):
    rows = []
    for key, value in dict(meta or {}).items():
        rows.append((str(key), _serialize_geoip_meta_value(value)))
    if rows:
        cursor.executemany(
            "INSERT OR REPLACE INTO geoip_import_meta (k, v) VALUES (?, ?);",
            rows,
        )


def _parse_geoip_meta_list(value):
    if isinstance(value, list):
        return value
    try:
        payload = json.loads(str(value or "[]"))
    except Exception:
        return []
    if isinstance(payload, list):
        return payload
    return []


def _parse_geoip_meta_bool(value):
    if isinstance(value, bool):
        return value
    try:
        payload = json.loads(str(value or "false"))
        return bool(payload)
    except Exception:
        return False


def geoip_seed_refresh_required(existing_rows, current_meta, seed_meta):
    if int(existing_rows or 0) <= 0:
        return True
    if str(current_meta.get("source_kind", "") or "").strip() != "repo-seed-file":
        return True
    if str(current_meta.get("seed_format", "") or "").strip() != str(
        seed_meta.get("format", "") or ""
    ).strip():
        return True
    if str(current_meta.get("seed_generated_at", "") or "").strip() != str(
        seed_meta.get("generated_at", "") or ""
    ).strip():
        return True
    try:
        current_rows = max(0, int(current_meta.get("seed_rows", "0") or 0))
    except Exception:
        current_rows = 0
    return current_rows != max(0, int(seed_meta.get("rows", 0) or 0))


def geoip_status_from_meta(meta, row_count, seed_path=None):
    info = dict(meta or {})
    rows = max(0, int(row_count or 0))
    source = str(info.get("source_kind", "") or "").strip()
    if not source:
        source = "empty" if rows <= 0 else "external-db"
    return {
        "source": source,
        "format": str(info.get("seed_format", "") or GEOIP_SEED_FORMAT),
        "rows": rows,
        "seed_path": str(resolve_geoip_seed_path(seed_path)),
        "generated_at": str(info.get("seed_generated_at", "") or ""),
        "imported_at": str(info.get("last_import_utc", "") or ""),
        "partial": _parse_geoip_meta_bool(info.get("seed_partial")),
        "selected_rirs": _parse_geoip_meta_list(info.get("seed_selected_rirs")),
        "failed_rirs": _parse_geoip_meta_list(info.get("seed_failed_rirs")),
    }


def sync_geoip_seed_into_db(conn, seed_path=None):
    seed_path = resolve_geoip_seed_path(seed_path)
    cursor = conn.cursor()
    try:
        ensure_geoip_schema(cursor)
        cursor.execute("SELECT COUNT(id) FROM geoip_blocks;")
        row = cursor.fetchone()
        existing_rows = int(row[0] if row else 0)
        current_meta = read_geoip_meta_from_db(cursor)
        seed_meta = read_geoip_seed_meta(seed_path)
        if not seed_meta:
            conn.commit()
            return geoip_status_from_meta(current_meta, existing_rows, seed_path)
        if not geoip_seed_refresh_required(existing_rows, current_meta, seed_meta):
            conn.commit()
            return geoip_status_from_meta(current_meta, existing_rows, seed_path)

        cursor.execute("DELETE FROM geoip_blocks;")
        batch = []
        imported_rows = 0
        for item in iter_geoip_seed_blocks(seed_path):
            try:
                batch.append(
                    (
                        int(item["start_int"]),
                        int(item["end_int"]),
                        str(item["cidr"]),
                        str(item["rir"]),
                        str(item["area"]),
                        str(item["country"]),
                        float(item["lat"]),
                        float(item["lon"]),
                    )
                )
            except Exception:
                continue
            if len(batch) >= 5000:
                cursor.executemany(
                    "INSERT OR REPLACE INTO geoip_blocks "
                    "(start_int, end_int, cidr, rir, area, country, lat, lon) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                    batch,
                )
                imported_rows += len(batch)
                batch = []
        if batch:
            cursor.executemany(
                "INSERT OR REPLACE INTO geoip_blocks "
                "(start_int, end_int, cidr, rir, area, country, lat, lon) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                batch,
            )
            imported_rows += len(batch)

        meta = {
            "source_kind": "repo-seed-file",
            "seed_path": str(seed_path),
            "seed_format": str(seed_meta.get("format", "") or GEOIP_SEED_FORMAT),
            "seed_generated_at": str(seed_meta.get("generated_at", "") or ""),
            "seed_rows": int(imported_rows),
            "seed_partial": bool(seed_meta.get("partial")),
            "seed_selected_rirs": list(seed_meta.get("selected_rirs", [])),
            "seed_failed_rirs": list(seed_meta.get("failed_rirs", [])),
            "last_import_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        write_geoip_meta_to_db(cursor, meta)
        conn.commit()
        return geoip_status_from_meta(meta, imported_rows, seed_path)
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()


def read_geoip_status_from_db(conn, seed_path=None):
    seed_path = resolve_geoip_seed_path(seed_path)
    cursor = conn.cursor()
    try:
        ensure_geoip_schema(cursor)
        cursor.execute("SELECT COUNT(id) FROM geoip_blocks;")
        row = cursor.fetchone()
        row_count = int(row[0] if row else 0)
        meta = read_geoip_meta_from_db(cursor)
        return geoip_status_from_meta(meta, row_count, seed_path)
    finally:
        cursor.close()


def lookup_geoip_ipv4_in_db(conn, ip_value):
    try:
        ip_int = int(IPv4Address(str(ip_value).strip()))
    except Exception:
        return None

    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT cidr, rir, area, country, lat, lon "
            "FROM geoip_blocks "
            "WHERE ? BETWEEN start_int AND end_int "
            "ORDER BY (end_int - start_int) ASC "
            "LIMIT 1;",
            (ip_int,),
        )
        row = cursor.fetchone()
    finally:
        cursor.close()

    if not row:
        return None
    return {
        "cidr": row[0],
        "rir": row[1],
        "area": row[2],
        "country": row[3],
        "lat": float(row[4]),
        "lon": float(row[5]),
    }
