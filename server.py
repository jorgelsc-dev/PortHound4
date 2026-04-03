import re
import socket
import threading
import json
import sqlite3
import hashlib
import hmac
import base64
import errno
import secrets
from os import getenv
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, UTC
import time
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit

from geoip_seed import (
    GEOIP_SEED_PATH as DEFAULT_GEOIP_SEED_PATH,
    lookup_geoip_ipv4_in_db,
    read_geoip_status_from_db,
    resolve_geoip_seed_path,
    sync_geoip_seed_into_db,
)
from scan_payloads import (
    BANNER_TCP_PROBES,
    BANNER_UDP_PROBES,
    TCP_HTTP_PORTS,
    TCP_HTTP_PROBES,
    TCP_PORT_PROBE_OVERRIDES,
    UDP_PORT_PROBE_OVERRIDES,
)
from banner_rules import (
    BANNER_REGEX_RULES,
    build_banner_rule_tags,
    review_banner_payload,
    set_runtime_banner_rules,
)


class BreakLoop(Exception):
    pass


def _resolve_scan_source_ip():
    raw_value = str(getenv("PORTHOUND_IP", "")).strip()
    if not raw_value:
        return ""
    try:
        ipaddress.IPv4Address(raw_value)
        return raw_value
    except Exception:
        print(f"[scan] ignoring invalid PORTHOUND_IP={raw_value!r}")
        return ""


SCAN_SOURCE_IP = _resolve_scan_source_ip()
_SOURCE_BIND_WARNING_EMITTED = False


def bind_source_ip(sock, strict=False):
    global _SOURCE_BIND_WARNING_EMITTED
    source_ip = SCAN_SOURCE_IP
    if not source_ip or not sock:
        return
    try:
        sock.bind((source_ip, 0))
    except Exception as exc:
        if strict:
            raise
        if not _SOURCE_BIND_WARNING_EMITTED:
            print(f"[scan] source bind warning ({source_ip}): {exc}")
            _SOURCE_BIND_WARNING_EMITTED = True


def dedupe_probe_payloads(payloads):
    unique = []
    seen = set()
    for payload in payloads:
        if isinstance(payload, str):
            payload = payload.encode("utf-8", errors="ignore")
        if not isinstance(payload, (bytes, bytearray)):
            continue
        payload = bytes(payload)
        if payload in seen:
            continue
        seen.add(payload)
        unique.append(payload)
    return unique


def icmp_checksum(packet):
    if len(packet) % 2:
        packet += b"\x00"
    checksum = 0
    for i in range(0, len(packet), 2):
        checksum += (packet[i] << 8) + packet[i + 1]
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += checksum >> 16
    return (~checksum) & 0xFFFF


def supports_sctp():
    proto = getattr(socket, "IPPROTO_SCTP", None)
    if proto is None:
        return False

    socket_types = [socket.SOCK_STREAM]
    sock_seqpacket = getattr(socket, "SOCK_SEQPACKET", None)
    if sock_seqpacket is not None:
        socket_types.append(sock_seqpacket)

    for socket_type in socket_types:
        probe = None
        try:
            probe = socket.socket(socket.AF_INET, socket_type, proto)
            return True
        except Exception:
            continue
        finally:
            try:
                if probe:
                    probe.close()
            except Exception:
                pass
    return False


def detect_target_protocols():
    # Always expose SCTP target type. When native SCTP sockets are unavailable,
    # the SCTP worker falls back to host-discovery mode.
    return {"tcp", "udp", "icmp", "sctp"}


def tcp_reachability_probe(host, timeout=1.0, ports=None):
    result = {
        "state": "FILTERED",
        "tiempo_ms": None,
        "method": "tcp_connect_fallback",
        "probe_port": None,
    }
    candidate_ports = tuple(ports or (22, 80, 443, 445, 3389, 53))
    timeout = max(0.2, float(timeout))
    start = time.time()

    reachable_codes = {0}
    for code_name in ("ECONNREFUSED", "ECONNRESET"):
        code_value = getattr(errno, code_name, None)
        if isinstance(code_value, int):
            reachable_codes.add(code_value)
    # Common Windows socket error codes for "refused/reset".
    reachable_codes.update({10061, 10054})

    for port in candidate_ports:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            bind_source_ip(sock)
            sock.settimeout(timeout)
            code = sock.connect_ex((host, int(port)))
            result["probe_port"] = int(port)
            if code in reachable_codes:
                end = time.time()
                result["state"] = "OPEN"
                result["tiempo_ms"] = round((end - start) * 1000, 2)
                return result
        except socket.timeout:
            result["probe_port"] = int(port)
        except Exception:
            result["probe_port"] = int(port)
        finally:
            try:
                if sock:
                    sock.close()
            except Exception:
                pass

    end = time.time()
    result["tiempo_ms"] = round((end - start) * 1000, 2)
    return result


TARGET_TYPES = {"common", "not_common", "full"}
TARGET_PROTOS = detect_target_protocols()
TARGET_STATUSES = {"active", "stopped", "restarting"}
TARGET_PORT_MODES = {"preset", "single", "range"}
PORT_SCAN_STATUSES = {"active", "stopped", "restarting"}
PORT_MIN = 1
PORT_MAX = 65535


def parse_port_number(value, field_name: str) -> int:
    try:
        port = int(value)
    except Exception:
        raise ValueError(f"Invalid {field_name}")
    if port < PORT_MIN or port > PORT_MAX:
        raise ValueError(f"{field_name} must be between {PORT_MIN} and {PORT_MAX}")
    return port


def normalize_target_port_config(item: dict, proto: str) -> dict:
    mode_raw = item.get("port_mode", item.get("scan_mode", "preset"))
    mode = str(mode_raw or "preset").strip().lower()
    if proto == "icmp":
        # ICMP host discovery does not use transport-layer ports.
        return {"port_mode": "preset", "port_start": 0, "port_end": 0}
    if mode not in TARGET_PORT_MODES:
        allowed = ", ".join(sorted(TARGET_PORT_MODES))
        raise ValueError(f"Invalid port_mode. Use {allowed}")

    output = {"port_mode": mode, "port_start": 0, "port_end": 0}
    if mode == "single":
        single_value = item.get("port")
        if single_value is None:
            single_value = item.get("port_start", item.get("port_end"))
        if single_value is None:
            raise ValueError("port is required when port_mode is single")
        single_port = parse_port_number(single_value, "port")
        output["port_start"] = single_port
        output["port_end"] = single_port
        return output

    if mode == "range":
        start_value = item.get("port_start", item.get("start_port"))
        end_value = item.get("port_end", item.get("end_port"))
        if start_value is None or end_value is None:
            raise ValueError("port_start and port_end are required when port_mode is range")
        start_port = parse_port_number(start_value, "port_start")
        end_port = parse_port_number(end_value, "port_end")
        if start_port > end_port:
            raise ValueError("port_start must be <= port_end")
        output["port_start"] = start_port
        output["port_end"] = end_port
        return output

    return output


def resolve_target_ports(type_scan: str, port_mode="preset", port_start=None, port_end=None):
    mode = str(port_mode or "preset").strip().lower()
    if mode == "single":
        try:
            single_port = int(port_start if port_start is not None else port_end)
        except Exception:
            return range(0)
        if single_port < PORT_MIN or single_port > PORT_MAX:
            return range(0)
        return range(single_port, single_port + 1)

    if mode == "range":
        try:
            start_port = int(port_start)
            end_port = int(port_end)
        except Exception:
            return range(0)
        if (
            start_port < PORT_MIN
            or start_port > PORT_MAX
            or end_port < PORT_MIN
            or end_port > PORT_MAX
            or start_port > end_port
        ):
            return range(0)
        return range(start_port, end_port + 1)

    if type_scan == "common":
        return range(1, 1024)
    if type_scan == "not_common":
        return range(1024, 65535)
    if type_scan == "full":
        return range(1, 65535)
    return range(0)


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_BANNER_RULES_FILE = PROJECT_ROOT / "data" / "banner_regex_rules.json"
DEFAULT_BANNER_REQUESTS_FILE = PROJECT_ROOT / "data" / "banner_probe_requests.json"
DEFAULT_IP_PRESETS_FILE = PROJECT_ROOT / "data" / "ip_presets.json"

PROBE_PAYLOAD_FORMATS = {"text", "hex", "base64"}
PROBE_REQUEST_SCOPES = {"generic", "http", "port_override"}
AGENT_ID_SAFE_RE = re.compile(r"^[A-Za-z0-9._-]{3,80}$")


def _parse_bool(value, default=False):
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(int(value))
    raw = str(value).strip().lower()
    if raw in {"1", "true", "yes", "on", "y"}:
        return True
    if raw in {"0", "false", "no", "off", "n"}:
        return False
    return bool(default)


def _safe_read_json_array(file_path: Path, key: str):
    try:
        payload = json.loads(Path(file_path).read_text(encoding="utf-8"))
    except Exception:
        return []
    rows = payload.get(key, [])
    if not isinstance(rows, list):
        return []
    return rows


def _decode_probe_payload(payload_encoded, payload_format):
    fmt = str(payload_format or "text").strip().lower()
    raw_text = str(payload_encoded or "")
    if fmt not in PROBE_PAYLOAD_FORMATS:
        raise ValueError("Invalid payload_format. Use text, hex or base64")
    if fmt == "text":
        return raw_text.encode("utf-8", errors="ignore")
    if fmt == "hex":
        cleaned = "".join(raw_text.split())
        if cleaned.lower().startswith("0x"):
            cleaned = cleaned[2:]
        if len(cleaned) % 2 != 0:
            raise ValueError("hex payload must contain an even number of characters")
        try:
            return bytes.fromhex(cleaned)
        except Exception as exc:
            raise ValueError(f"Invalid hex payload: {exc}") from exc
    try:
        return base64.b64decode(raw_text.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError(f"Invalid base64 payload: {exc}") from exc


def _payload_preview(payload: bytes, max_len=180):
    data = bytes(payload or b"")
    if not data:
        return ""
    text = data.decode("utf-8", errors="replace")
    text = "".join(
        ch if ch.isprintable() or ch in {"\r", "\n", "\t"} else "?"
        for ch in text
    )
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def _normalize_ip_value(value: str):
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("ip value is required")
    if "/" in raw:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except Exception:
            raise ValueError("Invalid IPv4 CIDR value")
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError("Only IPv4 CIDR values are supported")
        return network.with_prefixlen
    try:
        addr = ipaddress.ip_address(raw)
    except Exception:
        raise ValueError("Invalid IPv4 value")
    if not isinstance(addr, ipaddress.IPv4Address):
        raise ValueError("Only IPv4 addresses are supported")
    return str(addr)


def _normalize_agent_id(value, generate_if_missing=True):
    candidate = str(value or "").strip()
    if not candidate:
        if not generate_if_missing:
            raise ValueError("agent_id is required")
        candidate = f"agent-{secrets.token_hex(4)}"
    if not AGENT_ID_SAFE_RE.fullmatch(candidate):
        raise ValueError(
            "Invalid agent_id. Use 3-80 chars: letters, numbers, '.', '_' or '-'"
        )
    return candidate


def _hash_agent_shared_key(value):
    raw = str(value or "").strip()
    if len(raw) < 16:
        raise ValueError("token must be at least 16 characters")
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class DB(object):
    def __init__(self, path="Database.db", geoip_seed_path=None):
        self.path = str(path)
        self.geoip_seed_path = str(
            resolve_geoip_seed_path(geoip_seed_path or DEFAULT_GEOIP_SEED_PATH)
        )
        self.banner_rules_file = Path(DEFAULT_BANNER_RULES_FILE)
        self.banner_requests_file = Path(DEFAULT_BANNER_REQUESTS_FILE)
        self.ip_presets_file = Path(DEFAULT_IP_PRESETS_FILE)
        self.conn = sqlite3.connect(
            self.path, check_same_thread=False, timeout=10.0
        )
        self.lock = threading.Lock()
        self.geoip_status_cache = None
        self.catalog_bootstrap_done = False

    def config(self):
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA locking_mode=EXCLUSIVE;")
        self.conn.execute("PRAGMA optimize;")
        self.conn.execute("PRAGMA mmap_size=1073741824;")
        self.conn.commit()

    def create_tables(self):
        self.lock.acquire()
        cursor = None
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "CREATE TABLE IF NOT EXISTS targets ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "network TEXT NOT NULL,"
                "type TEXT NOT NULL,"
                "proto TEXT NOT NULL,"
                "port_mode TEXT NOT NULL DEFAULT 'preset',"
                "port_start INTEGER NOT NULL DEFAULT 0,"
                "port_end INTEGER NOT NULL DEFAULT 0,"
                "timesleep REAL DEFAULT 1.0,"
                "progress REAL DEFAULT 0.0,"
                "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "UNIQUE(network, type, proto, timesleep, port_mode, port_start, port_end)"
                ");"
            )
            cursor.execute(
                "CREATE TABLE IF NOT EXISTS banners ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "ip TEXT NOT NULL,"
                "port INTEGER NOT NULL,"
                "proto TEXT NOT NULL,"
                "response BLOB NOT NULL,"
                "response_plain TEXT NOT NULL,"
                "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "UNIQUE(ip,port,proto,response)"
                ");"
            )
            cursor.execute(
                "CREATE TABLE IF NOT EXISTS favicons ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "ip TEXT NOT NULL,"
                "port INTEGER NOT NULL,"
                "proto TEXT NOT NULL,"
                "icon_url TEXT NOT NULL,"
                "mime_type TEXT NOT NULL,"
                "icon_blob BLOB NOT NULL,"
                "size INTEGER NOT NULL,"
                "sha256 TEXT NOT NULL,"
                "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "UNIQUE(ip, port, proto, sha256)"
                ");"
            )
            cursor.execute(
                "CREATE TABLE IF NOT EXISTS tags ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "ip TEXT NOT NULL,"
                "port INTEGER NOT NULL,"
                "proto TEXT NOT NULL,"
                "key TEXT NOT NULL,"
                "value TEXT NOT NULL,"
                "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "UNIQUE(ip, port, proto, key)"
                ");"
            )
            cursor.execute(
                "CREATE TABLE IF NOT EXISTS ports ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "ip TEXT NOT NULL,"
                "port INTEGER NOT NULL,"
                "proto TEXT NOT NULL,"
                "state TEXT NOT NULL,"  # OPEN FILTERED
                "scan_state TEXT NOT NULL DEFAULT 'active',"
                "progress REAL DEFAULT 0.0,"
                "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "UNIQUE(ip, port, proto)"
                ");"
            )
            cursor.execute("PRAGMA table_info(targets);")
            target_columns = {row[1] for row in cursor.fetchall()}
            if "port_mode" not in target_columns:
                cursor.execute(
                    "ALTER TABLE targets "
                    "ADD COLUMN port_mode TEXT NOT NULL DEFAULT 'preset';"
                )
            if "port_start" not in target_columns:
                cursor.execute(
                    "ALTER TABLE targets "
                    "ADD COLUMN port_start INTEGER DEFAULT 0;"
                )
            if "port_end" not in target_columns:
                cursor.execute(
                    "ALTER TABLE targets "
                    "ADD COLUMN port_end INTEGER DEFAULT 0;"
                )
            if "status" not in target_columns:
                cursor.execute(
                    "ALTER TABLE targets "
                    "ADD COLUMN status TEXT NOT NULL DEFAULT 'active';"
                )
            cursor.execute(
                "UPDATE targets "
                "SET port_mode = 'preset' "
                "WHERE port_mode IS NULL OR trim(port_mode) = '' "
                "OR lower(port_mode) NOT IN ('preset', 'single', 'range');"
            )
            cursor.execute(
                "UPDATE targets "
                "SET port_start = 0, port_end = 0 "
                "WHERE lower(port_mode) = 'preset';"
            )
            cursor.execute(
                "UPDATE targets "
                "SET port_end = port_start "
                "WHERE lower(port_mode) = 'single' "
                "AND port_start IS NOT NULL "
                "AND (port_end IS NULL OR port_end <> port_start);"
            )
            cursor.execute(
                "UPDATE targets "
                "SET port_mode = 'preset', port_start = 0, port_end = 0 "
                "WHERE port_start IS NOT NULL "
                "AND (port_start < 1 OR port_start > 65535);"
            )
            cursor.execute(
                "UPDATE targets "
                "SET port_mode = 'preset', port_start = 0, port_end = 0 "
                "WHERE port_end IS NOT NULL "
                "AND (port_end < 1 OR port_end > 65535);"
            )
            cursor.execute(
                "UPDATE targets "
                "SET port_mode = 'preset', port_start = 0, port_end = 0 "
                "WHERE lower(port_mode) = 'range' "
                "AND port_start IS NOT NULL AND port_end IS NOT NULL "
                "AND port_start > port_end;"
            )
            cursor.execute(
                "UPDATE targets "
                "SET status = 'active' "
                "WHERE status IS NULL OR trim(status) = '' "
                "OR lower(status) NOT IN ('active', 'stopped', 'restarting');"
            )
            cursor.execute("PRAGMA table_info(ports);")
            port_columns = {row[1] for row in cursor.fetchall()}
            if "scan_state" not in port_columns:
                cursor.execute(
                    "ALTER TABLE ports "
                    "ADD COLUMN scan_state TEXT NOT NULL DEFAULT 'active';"
                )
            cursor.execute(
                "UPDATE ports "
                "SET scan_state = 'active' "
                "WHERE scan_state IS NULL OR trim(scan_state) = '' "
                "OR lower(scan_state) NOT IN ('active', 'stopped', 'restarting');"
            )
            self._ensure_catalog_tables(cursor)
            self._bootstrap_catalog_from_files(cursor)
            self.conn.commit()
            self._refresh_runtime_banner_rules_locked(cursor=cursor)
            cursor.close()
            cursor = None
            self.geoip_status_cache = sync_geoip_seed_into_db(
                self.conn, self.geoip_seed_path
            )
        except Exception as e:
            self.conn.rollback()
            print("DB() -> create_tables():", e)
        finally:
            if cursor is not None:
                cursor.close()
            self.lock.release()

    def _ensure_catalog_tables(self, cursor):
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS banner_regex_catalog ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "rule_key TEXT NOT NULL UNIQUE,"
            "rule_id TEXT NOT NULL,"
            "label TEXT NOT NULL,"
            "pattern TEXT NOT NULL,"
            "flags INTEGER NOT NULL DEFAULT 0,"
            "category TEXT NOT NULL DEFAULT '',"
            "service TEXT NOT NULL DEFAULT '',"
            "protocol TEXT NOT NULL DEFAULT '',"
            "product TEXT NOT NULL DEFAULT '',"
            "server TEXT NOT NULL DEFAULT '',"
            "os TEXT NOT NULL DEFAULT '',"
            "version TEXT NOT NULL DEFAULT '',"
            "runtime TEXT NOT NULL DEFAULT '',"
            "framework TEXT NOT NULL DEFAULT '',"
            "vendor TEXT NOT NULL DEFAULT '',"
            "powered_by TEXT NOT NULL DEFAULT '',"
            "source TEXT NOT NULL DEFAULT 'user',"
            "mutable INTEGER NOT NULL DEFAULT 1,"
            "active INTEGER NOT NULL DEFAULT 1,"
            "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
            ");"
        )
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS banner_probe_catalog ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "request_key TEXT NOT NULL UNIQUE,"
            "name TEXT NOT NULL,"
            "proto TEXT NOT NULL,"
            "scope TEXT NOT NULL,"
            "port INTEGER NOT NULL DEFAULT 0,"
            "payload_format TEXT NOT NULL DEFAULT 'text',"
            "payload_encoded TEXT NOT NULL,"
            "payload BLOB NOT NULL,"
            "description TEXT NOT NULL DEFAULT '',"
            "source TEXT NOT NULL DEFAULT 'user',"
            "mutable INTEGER NOT NULL DEFAULT 1,"
            "active INTEGER NOT NULL DEFAULT 1,"
            "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
            ");"
        )
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS ip_catalog ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "value TEXT NOT NULL UNIQUE,"
            "label TEXT NOT NULL DEFAULT '',"
            "description TEXT NOT NULL DEFAULT '',"
            "source TEXT NOT NULL DEFAULT 'user',"
            "mutable INTEGER NOT NULL DEFAULT 1,"
            "active INTEGER NOT NULL DEFAULT 1,"
            "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
            ");"
        )
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS cluster_agent_credentials ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "agent_id TEXT NOT NULL UNIQUE,"
            "key_hash TEXT NOT NULL,"
            "active INTEGER NOT NULL DEFAULT 1,"
            "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "last_used_at TEXT"
            ");"
        )

    def _iter_builtin_banner_rules(self):
        rows = _safe_read_json_array(self.banner_rules_file, "rules")
        if not rows:
            rows = list(BANNER_REGEX_RULES)
        output = []
        for index, row in enumerate(rows, start=1):
            if not isinstance(row, dict):
                continue
            rule_id = str(row.get("id", "") or row.get("rule_id", "")).strip()
            if not rule_id:
                rule_id = f"builtin_rule_{index:04d}"
            rule_key = str(row.get("rule_key", "")).strip() or rule_id
            pattern = str(row.get("pattern", "") or "")
            if not pattern:
                continue
            try:
                flags = int(row.get("flags", 0) or 0)
            except Exception:
                flags = 0
            output.append(
                {
                    "rule_key": rule_key,
                    "rule_id": rule_id,
                    "label": str(row.get("label", "") or rule_id),
                    "pattern": pattern,
                    "flags": flags,
                    "category": str(row.get("category", "") or ""),
                    "service": str(row.get("service", "") or ""),
                    "protocol": str(row.get("protocol", "") or ""),
                    "product": str(row.get("product", "") or ""),
                    "server": str(row.get("server", "") or ""),
                    "os": str(row.get("os", "") or ""),
                    "version": str(row.get("version", "") or ""),
                    "runtime": str(row.get("runtime", "") or ""),
                    "framework": str(row.get("framework", "") or ""),
                    "vendor": str(row.get("vendor", "") or ""),
                    "powered_by": str(row.get("powered_by", "") or ""),
                    "active": 1 if _parse_bool(row.get("active", True), default=True) else 0,
                }
            )
        return output

    def _append_probe_request(
        self,
        bucket,
        seen_keys,
        proto,
        scope,
        port,
        payload,
        payload_format="base64",
        payload_encoded=None,
        name_prefix="Builtin probe",
        request_key="",
        description="",
        active=True,
    ):
        proto = str(proto or "").strip().lower()
        scope = str(scope or "").strip().lower()
        if proto not in {"tcp", "udp"} or scope not in PROBE_REQUEST_SCOPES:
            return
        port_value = int(port or 0)
        raw_payload = bytes(payload or b"")
        key = str(request_key or "").strip()
        if not key:
            digest = hashlib.sha256(
                f"{proto}|{scope}|{port_value}|".encode("utf-8") + raw_payload
            ).hexdigest()
            key = f"{proto}_{scope}_{port_value}_{digest[:16]}"
        if key in seen_keys:
            return
        seen_keys.add(key)
        fmt = str(payload_format or "base64").strip().lower()
        encoded = payload_encoded
        if encoded is None:
            if fmt == "text":
                encoded = raw_payload.decode("utf-8", errors="ignore")
            elif fmt == "hex":
                encoded = raw_payload.hex()
            else:
                fmt = "base64"
                encoded = base64.b64encode(raw_payload).decode("ascii")
        bucket.append(
            {
                "request_key": key,
                "name": str(name_prefix or "Builtin probe"),
                "proto": proto,
                "scope": scope,
                "port": port_value,
                "payload_format": fmt,
                "payload_encoded": str(encoded or ""),
                "payload": raw_payload,
                "description": str(description or ""),
                "active": 1 if _parse_bool(active, default=True) else 0,
            }
        )

    def _iter_builtin_probe_requests(self):
        rows = _safe_read_json_array(self.banner_requests_file, "requests")
        output = []
        seen_keys = set()
        if rows:
            for row in rows:
                if not isinstance(row, dict):
                    continue
                proto = str(row.get("proto", "")).strip().lower()
                scope = str(row.get("scope", "")).strip().lower()
                if proto not in {"tcp", "udp"} or scope not in PROBE_REQUEST_SCOPES:
                    continue
                try:
                    port = int(row.get("port", 0) or 0)
                except Exception:
                    port = 0
                fmt = str(row.get("payload_format", "base64") or "base64").strip().lower()
                encoded = str(row.get("payload_encoded", "") or "")
                try:
                    payload = _decode_probe_payload(encoded, fmt)
                except Exception:
                    continue
                self._append_probe_request(
                    bucket=output,
                    seen_keys=seen_keys,
                    proto=proto,
                    scope=scope,
                    port=port,
                    payload=payload,
                    payload_format=fmt,
                    payload_encoded=encoded,
                    name_prefix=str(row.get("name", "Builtin probe") or "Builtin probe"),
                    request_key=str(row.get("request_key", "") or ""),
                    description=str(row.get("description", "") or ""),
                    active=row.get("active", True),
                )
            return output

        for payload in TCP_HTTP_PROBES:
            self._append_probe_request(
                bucket=output,
                seen_keys=seen_keys,
                proto="tcp",
                scope="http",
                port=0,
                payload=payload,
                name_prefix="Builtin TCP HTTP probe",
            )
        for port, payloads in sorted(TCP_PORT_PROBE_OVERRIDES.items()):
            for payload in payloads:
                self._append_probe_request(
                    bucket=output,
                    seen_keys=seen_keys,
                    proto="tcp",
                    scope="port_override",
                    port=port,
                    payload=payload,
                    name_prefix="Builtin TCP override probe",
                )
        for payload in BANNER_TCP_PROBES:
            self._append_probe_request(
                bucket=output,
                seen_keys=seen_keys,
                proto="tcp",
                scope="generic",
                port=0,
                payload=payload,
                name_prefix="Builtin TCP generic probe",
            )
        for port, payloads in sorted(UDP_PORT_PROBE_OVERRIDES.items()):
            for payload in payloads:
                self._append_probe_request(
                    bucket=output,
                    seen_keys=seen_keys,
                    proto="udp",
                    scope="port_override",
                    port=port,
                    payload=payload,
                    name_prefix="Builtin UDP override probe",
                )
        for payload in BANNER_UDP_PROBES:
            self._append_probe_request(
                bucket=output,
                seen_keys=seen_keys,
                proto="udp",
                scope="generic",
                port=0,
                payload=payload,
                name_prefix="Builtin UDP generic probe",
            )
        return output

    def _iter_builtin_ip_presets(self):
        rows = _safe_read_json_array(self.ip_presets_file, "ips")
        output = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            try:
                value = _normalize_ip_value(row.get("value", ""))
            except Exception:
                continue
            output.append(
                {
                    "value": value,
                    "label": str(row.get("label", "") or ""),
                    "description": str(row.get("description", "") or ""),
                    "active": 1 if _parse_bool(row.get("active", True), default=True) else 0,
                }
            )
        return output

    def _bootstrap_catalog_from_files(self, cursor):
        if self.catalog_bootstrap_done:
            return
        for row in self._iter_builtin_banner_rules():
            cursor.execute(
                "INSERT OR IGNORE INTO banner_regex_catalog ("
                "rule_key, rule_id, label, pattern, flags, category, service, protocol, "
                "product, server, os, version, runtime, framework, vendor, powered_by, "
                "source, mutable, active"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'builtin', 0, ?);",
                (
                    row["rule_key"],
                    row["rule_id"],
                    row["label"],
                    row["pattern"],
                    int(row["flags"]),
                    row["category"],
                    row["service"],
                    row["protocol"],
                    row["product"],
                    row["server"],
                    row["os"],
                    row["version"],
                    row["runtime"],
                    row["framework"],
                    row["vendor"],
                    row["powered_by"],
                    int(row["active"]),
                ),
            )

        for row in self._iter_builtin_probe_requests():
            cursor.execute(
                "INSERT OR IGNORE INTO banner_probe_catalog ("
                "request_key, name, proto, scope, port, payload_format, payload_encoded, payload, "
                "description, source, mutable, active"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'builtin', 0, ?);",
                (
                    row["request_key"],
                    row["name"],
                    row["proto"],
                    row["scope"],
                    int(row["port"]),
                    row["payload_format"],
                    row["payload_encoded"],
                    row["payload"],
                    row["description"],
                    int(row["active"]),
                ),
            )

        for row in self._iter_builtin_ip_presets():
            cursor.execute(
                "INSERT OR IGNORE INTO ip_catalog ("
                "value, label, description, source, mutable, active"
                ") VALUES (?, ?, ?, 'builtin', 0, ?);",
                (
                    row["value"],
                    row["label"],
                    row["description"],
                    int(row["active"]),
                ),
            )
        self.catalog_bootstrap_done = True

    def _refresh_runtime_banner_rules_locked(self, cursor=None):
        local_cursor = cursor or self.conn.cursor()
        close_cursor = cursor is None
        try:
            local_cursor.execute(
                "SELECT rule_id, label, pattern, flags, category, service, protocol, "
                "product, server, os, version, runtime, framework, vendor, powered_by "
                "FROM banner_regex_catalog "
                "WHERE active = 1 "
                "ORDER BY source DESC, id ASC;"
            )
            rows = []
            for row in local_cursor.fetchall():
                rows.append(
                    {
                        "id": str(row[0] or "").strip(),
                        "label": str(row[1] or "").strip(),
                        "pattern": str(row[2] or ""),
                        "flags": int(row[3] or 0),
                        "category": str(row[4] or ""),
                        "service": str(row[5] or ""),
                        "protocol": str(row[6] or ""),
                        "product": str(row[7] or ""),
                        "server": str(row[8] or ""),
                        "os": str(row[9] or ""),
                        "version": str(row[10] or ""),
                        "runtime": str(row[11] or ""),
                        "framework": str(row[12] or ""),
                        "vendor": str(row[13] or ""),
                        "powered_by": str(row[14] or ""),
                    }
                )
            set_runtime_banner_rules(rows)
        except Exception as exc:
            print("DB() -> _refresh_runtime_banner_rules_locked():", exc)
        finally:
            if close_cursor:
                local_cursor.close()

    def _apply_runtime_banner_rules(self):
        self.lock.acquire()
        try:
            self._refresh_runtime_banner_rules_locked()
        finally:
            self.lock.release()

    def select_banner_regex_rules(self, include_inactive=True):
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            where_sql = "" if include_inactive else "WHERE active = 1"
            cursor.execute(
                "SELECT id, rule_key, rule_id, label, pattern, flags, category, service, "
                "protocol, product, server, os, version, runtime, framework, vendor, "
                "powered_by, source, mutable, active, created_at, updated_at "
                f"FROM banner_regex_catalog {where_sql} "
                "ORDER BY source DESC, id ASC;"
            )
            for row in cursor.fetchall():
                output.append(
                    {
                        "id": int(row[0]),
                        "rule_key": str(row[1] or ""),
                        "rule_id": str(row[2] or ""),
                        "label": str(row[3] or ""),
                        "pattern": str(row[4] or ""),
                        "flags": int(row[5] or 0),
                        "category": str(row[6] or ""),
                        "service": str(row[7] or ""),
                        "protocol": str(row[8] or ""),
                        "product": str(row[9] or ""),
                        "server": str(row[10] or ""),
                        "os": str(row[11] or ""),
                        "version": str(row[12] or ""),
                        "runtime": str(row[13] or ""),
                        "framework": str(row[14] or ""),
                        "vendor": str(row[15] or ""),
                        "powered_by": str(row[16] or ""),
                        "source": str(row[17] or ""),
                        "mutable": bool(int(row[18] or 0)),
                        "active": bool(int(row[19] or 0)),
                        "created_at": str(row[20] or ""),
                        "updated_at": str(row[21] or ""),
                    }
                )
        except Exception as e:
            print("DB() -> select_banner_regex_rules():", e)
        finally:
            cursor.close()
            self.lock.release()
            return output

    def _normalize_banner_regex_row(self, data, require_id=False):
        payload = dict(data or {})
        if require_id:
            try:
                payload["id"] = int(payload.get("id"))
            except Exception:
                raise ValueError("Invalid regex rule id")
        rule_id = str(
            payload.get("rule_id", payload.get("id_name", payload.get("id_alias", "")))
            or ""
        ).strip()
        if not require_id and not rule_id:
            rule_id = f"custom_rule_{int(time.time() * 1000)}"
        label = str(payload.get("label", "") or "").strip() or rule_id
        pattern = str(payload.get("pattern", "") or "")
        if not pattern:
            raise ValueError("pattern is required")
        try:
            flags = int(payload.get("flags", 0) or 0)
        except Exception:
            raise ValueError("Invalid flags value")
        try:
            re.compile(pattern, flags)
        except Exception as exc:
            raise ValueError(f"Invalid regex pattern: {exc}") from exc
        output = {
            "id": payload.get("id"),
            "rule_key": str(payload.get("rule_key", "") or "").strip(),
            "rule_id": rule_id,
            "label": label,
            "pattern": pattern,
            "flags": flags,
            "category": str(payload.get("category", "") or ""),
            "service": str(payload.get("service", "") or ""),
            "protocol": str(payload.get("protocol", "") or ""),
            "product": str(payload.get("product", "") or ""),
            "server": str(payload.get("server", "") or ""),
            "os": str(payload.get("os", "") or ""),
            "version": str(payload.get("version", "") or ""),
            "runtime": str(payload.get("runtime", "") or ""),
            "framework": str(payload.get("framework", "") or ""),
            "vendor": str(payload.get("vendor", "") or ""),
            "powered_by": str(payload.get("powered_by", "") or ""),
            "active": 1 if _parse_bool(payload.get("active", True), default=True) else 0,
        }
        if not output["rule_key"]:
            seed = hashlib.sha1(
                f"{output['rule_id']}|{output['pattern']}".encode("utf-8")
            ).hexdigest()[:16]
            output["rule_key"] = f"user_{seed}"
        return output

    def insert_banner_regex_rule(self, data):
        output = {}
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            item = self._normalize_banner_regex_row(data, require_id=False)
            cursor.execute(
                "INSERT INTO banner_regex_catalog ("
                "rule_key, rule_id, label, pattern, flags, category, service, protocol, "
                "product, server, os, version, runtime, framework, vendor, powered_by, "
                "source, mutable, active"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'user', 1, ?);",
                (
                    item["rule_key"],
                    item["rule_id"],
                    item["label"],
                    item["pattern"],
                    int(item["flags"]),
                    item["category"],
                    item["service"],
                    item["protocol"],
                    item["product"],
                    item["server"],
                    item["os"],
                    item["version"],
                    item["runtime"],
                    item["framework"],
                    item["vendor"],
                    item["powered_by"],
                    int(item["active"]),
                ),
            )
            output_id = int(cursor.lastrowid)
            self.conn.commit()
            self._refresh_runtime_banner_rules_locked(cursor=cursor)
            cursor.execute(
                "SELECT id, rule_key, rule_id, label, pattern, flags, category, service, protocol, "
                "product, server, os, version, runtime, framework, vendor, powered_by, "
                "source, mutable, active, created_at, updated_at "
                "FROM banner_regex_catalog WHERE id = ? LIMIT 1;",
                (output_id,),
            )
            row = cursor.fetchone()
            if row:
                output = {
                    "id": int(row[0]),
                    "rule_key": str(row[1] or ""),
                    "rule_id": str(row[2] or ""),
                    "label": str(row[3] or ""),
                    "pattern": str(row[4] or ""),
                    "flags": int(row[5] or 0),
                    "category": str(row[6] or ""),
                    "service": str(row[7] or ""),
                    "protocol": str(row[8] or ""),
                    "product": str(row[9] or ""),
                    "server": str(row[10] or ""),
                    "os": str(row[11] or ""),
                    "version": str(row[12] or ""),
                    "runtime": str(row[13] or ""),
                    "framework": str(row[14] or ""),
                    "vendor": str(row[15] or ""),
                    "powered_by": str(row[16] or ""),
                    "source": str(row[17] or ""),
                    "mutable": bool(int(row[18] or 0)),
                    "active": bool(int(row[19] or 0)),
                    "created_at": str(row[20] or ""),
                    "updated_at": str(row[21] or ""),
                }
        except Exception as e:
            self.conn.rollback()
            print("DB() -> insert_banner_regex_rule():", e)
            raise
        finally:
            cursor.close()
            self.lock.release()
        return output

    def update_banner_regex_rule(self, data):
        output = {}
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            item = self._normalize_banner_regex_row(data, require_id=True)
            cursor.execute(
                "SELECT mutable, rule_id FROM banner_regex_catalog WHERE id = ? LIMIT 1;",
                (int(item["id"]),),
            )
            row = cursor.fetchone()
            if not row:
                raise ValueError("Regex rule not found")
            if int(row[0] or 0) == 0:
                raise PermissionError("Built-in regex rules cannot be modified")
            if not item["rule_id"]:
                item["rule_id"] = str(row[1] or "")
            cursor.execute(
                "UPDATE banner_regex_catalog SET "
                "rule_id = ?, label = ?, pattern = ?, flags = ?, category = ?, service = ?, "
                "protocol = ?, product = ?, server = ?, os = ?, version = ?, runtime = ?, "
                "framework = ?, vendor = ?, powered_by = ?, active = ?, "
                "updated_at = CURRENT_TIMESTAMP "
                "WHERE id = ?;",
                (
                    item["rule_id"],
                    item["label"],
                    item["pattern"],
                    int(item["flags"]),
                    item["category"],
                    item["service"],
                    item["protocol"],
                    item["product"],
                    item["server"],
                    item["os"],
                    item["version"],
                    item["runtime"],
                    item["framework"],
                    item["vendor"],
                    item["powered_by"],
                    int(item["active"]),
                    int(item["id"]),
                ),
            )
            self.conn.commit()
            self._refresh_runtime_banner_rules_locked(cursor=cursor)
            cursor.execute(
                "SELECT id, rule_key, rule_id, label, pattern, flags, category, service, protocol, "
                "product, server, os, version, runtime, framework, vendor, powered_by, "
                "source, mutable, active, created_at, updated_at "
                "FROM banner_regex_catalog WHERE id = ? LIMIT 1;",
                (int(item["id"]),),
            )
            row = cursor.fetchone()
            if row:
                output = {
                    "id": int(row[0]),
                    "rule_key": str(row[1] or ""),
                    "rule_id": str(row[2] or ""),
                    "label": str(row[3] or ""),
                    "pattern": str(row[4] or ""),
                    "flags": int(row[5] or 0),
                    "category": str(row[6] or ""),
                    "service": str(row[7] or ""),
                    "protocol": str(row[8] or ""),
                    "product": str(row[9] or ""),
                    "server": str(row[10] or ""),
                    "os": str(row[11] or ""),
                    "version": str(row[12] or ""),
                    "runtime": str(row[13] or ""),
                    "framework": str(row[14] or ""),
                    "vendor": str(row[15] or ""),
                    "powered_by": str(row[16] or ""),
                    "source": str(row[17] or ""),
                    "mutable": bool(int(row[18] or 0)),
                    "active": bool(int(row[19] or 0)),
                    "created_at": str(row[20] or ""),
                    "updated_at": str(row[21] or ""),
                }
        except Exception as e:
            self.conn.rollback()
            print("DB() -> update_banner_regex_rule():", e)
            raise
        finally:
            cursor.close()
            self.lock.release()
        return output

    def delete_banner_regex_rule(self, data):
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            rule_id = int((data or {}).get("id"))
            cursor.execute(
                "SELECT mutable FROM banner_regex_catalog WHERE id = ? LIMIT 1;",
                (rule_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise ValueError("Regex rule not found")
            if int(row[0] or 0) == 0:
                raise PermissionError("Built-in regex rules cannot be deleted")
            cursor.execute("DELETE FROM banner_regex_catalog WHERE id = ?;", (rule_id,))
            self.conn.commit()
            self._refresh_runtime_banner_rules_locked(cursor=cursor)
        except Exception as e:
            self.conn.rollback()
            print("DB() -> delete_banner_regex_rule():", e)
            raise
        finally:
            cursor.close()
            self.lock.release()

    def select_banner_probe_requests(self, proto="", include_inactive=True):
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            proto_value = str(proto or "").strip().lower()
            params = []
            where = []
            if proto_value:
                where.append("proto = ?")
                params.append(proto_value)
            if not include_inactive:
                where.append("active = 1")
            where_sql = f"WHERE {' AND '.join(where)}" if where else ""
            cursor.execute(
                "SELECT id, request_key, name, proto, scope, port, payload_format, payload_encoded, "
                "payload, description, source, mutable, active, created_at, updated_at "
                f"FROM banner_probe_catalog {where_sql} "
                "ORDER BY source DESC, id ASC;",
                tuple(params),
            )
            for row in cursor.fetchall():
                payload_blob = bytes(row[8] or b"")
                output.append(
                    {
                        "id": int(row[0]),
                        "request_key": str(row[1] or ""),
                        "name": str(row[2] or ""),
                        "proto": str(row[3] or ""),
                        "scope": str(row[4] or ""),
                        "port": int(row[5] or 0),
                        "payload_format": str(row[6] or "text"),
                        "payload_encoded": str(row[7] or ""),
                        "payload_len": len(payload_blob),
                        "payload_preview": _payload_preview(payload_blob),
                        "description": str(row[9] or ""),
                        "source": str(row[10] or ""),
                        "mutable": bool(int(row[11] or 0)),
                        "active": bool(int(row[12] or 0)),
                        "created_at": str(row[13] or ""),
                        "updated_at": str(row[14] or ""),
                    }
                )
        except Exception as e:
            print("DB() -> select_banner_probe_requests():", e)
        finally:
            cursor.close()
            self.lock.release()
            return output

    def _normalize_banner_probe_row(self, data, require_id=False):
        payload = dict(data or {})
        if require_id:
            try:
                payload["id"] = int(payload.get("id"))
            except Exception:
                raise ValueError("Invalid banner request id")
        proto = str(payload.get("proto", "") or "").strip().lower()
        if proto not in {"tcp", "udp"}:
            raise ValueError("Invalid proto. Use tcp or udp")
        scope = str(payload.get("scope", "generic") or "generic").strip().lower()
        if scope not in PROBE_REQUEST_SCOPES:
            raise ValueError("Invalid scope. Use generic, http or port_override")
        if proto == "udp" and scope == "http":
            raise ValueError("scope=http is only supported for proto=tcp")
        try:
            port = int(payload.get("port", 0) or 0)
        except Exception:
            raise ValueError("Invalid port value")
        if scope == "port_override":
            if port < 1 or port > 65535:
                raise ValueError("port must be between 1 and 65535 for port_override")
        else:
            port = 0
        fmt = str(payload.get("payload_format", "text") or "text").strip().lower()
        encoded = str(payload.get("payload_encoded", "") or "")
        if not encoded and payload.get("payload") is not None:
            encoded = str(payload.get("payload"))
        if not encoded:
            raise ValueError("payload_encoded is required")
        raw_payload = _decode_probe_payload(encoded, fmt)
        if not raw_payload:
            raise ValueError("payload must not be empty")
        name = str(payload.get("name", "") or "").strip() or "Custom probe request"
        description = str(payload.get("description", "") or "")
        request_key = str(payload.get("request_key", "") or "").strip()
        if not request_key:
            digest = hashlib.sha256(
                f"{proto}|{scope}|{port}|".encode("utf-8") + raw_payload
            ).hexdigest()[:16]
            request_key = f"user_{proto}_{scope}_{port}_{digest}"
        return {
            "id": payload.get("id"),
            "request_key": request_key,
            "name": name,
            "proto": proto,
            "scope": scope,
            "port": port,
            "payload_format": fmt,
            "payload_encoded": encoded,
            "payload": raw_payload,
            "description": description,
            "active": 1 if _parse_bool(payload.get("active", True), default=True) else 0,
        }

    def insert_banner_probe_request(self, data):
        output = {}
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            item = self._normalize_banner_probe_row(data, require_id=False)
            cursor.execute(
                "INSERT INTO banner_probe_catalog ("
                "request_key, name, proto, scope, port, payload_format, payload_encoded, "
                "payload, description, source, mutable, active"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'user', 1, ?);",
                (
                    item["request_key"],
                    item["name"],
                    item["proto"],
                    item["scope"],
                    int(item["port"]),
                    item["payload_format"],
                    item["payload_encoded"],
                    item["payload"],
                    item["description"],
                    int(item["active"]),
                ),
            )
            output_id = int(cursor.lastrowid)
            self.conn.commit()
            cursor.execute(
                "SELECT id, request_key, name, proto, scope, port, payload_format, payload_encoded, payload, "
                "description, source, mutable, active, created_at, updated_at "
                "FROM banner_probe_catalog WHERE id = ? LIMIT 1;",
                (output_id,),
            )
            row = cursor.fetchone()
            if row:
                payload_blob = bytes(row[8] or b"")
                output = {
                    "id": int(row[0]),
                    "request_key": str(row[1] or ""),
                    "name": str(row[2] or ""),
                    "proto": str(row[3] or ""),
                    "scope": str(row[4] or ""),
                    "port": int(row[5] or 0),
                    "payload_format": str(row[6] or "text"),
                    "payload_encoded": str(row[7] or ""),
                    "payload_len": len(payload_blob),
                    "payload_preview": _payload_preview(payload_blob),
                    "description": str(row[9] or ""),
                    "source": str(row[10] or ""),
                    "mutable": bool(int(row[11] or 0)),
                    "active": bool(int(row[12] or 0)),
                    "created_at": str(row[13] or ""),
                    "updated_at": str(row[14] or ""),
                }
        except Exception as e:
            self.conn.rollback()
            print("DB() -> insert_banner_probe_request():", e)
            raise
        finally:
            cursor.close()
            self.lock.release()
        return output

    def update_banner_probe_request(self, data):
        output = {}
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            item = self._normalize_banner_probe_row(data, require_id=True)
            cursor.execute(
                "SELECT mutable FROM banner_probe_catalog WHERE id = ? LIMIT 1;",
                (int(item["id"]),),
            )
            row = cursor.fetchone()
            if not row:
                raise ValueError("Banner request not found")
            if int(row[0] or 0) == 0:
                raise PermissionError("Built-in banner requests cannot be modified")
            cursor.execute(
                "UPDATE banner_probe_catalog SET "
                "name = ?, proto = ?, scope = ?, port = ?, payload_format = ?, "
                "payload_encoded = ?, payload = ?, description = ?, active = ?, "
                "updated_at = CURRENT_TIMESTAMP "
                "WHERE id = ?;",
                (
                    item["name"],
                    item["proto"],
                    item["scope"],
                    int(item["port"]),
                    item["payload_format"],
                    item["payload_encoded"],
                    item["payload"],
                    item["description"],
                    int(item["active"]),
                    int(item["id"]),
                ),
            )
            self.conn.commit()
            cursor.execute(
                "SELECT id, request_key, name, proto, scope, port, payload_format, payload_encoded, payload, "
                "description, source, mutable, active, created_at, updated_at "
                "FROM banner_probe_catalog WHERE id = ? LIMIT 1;",
                (int(item["id"]),),
            )
            row = cursor.fetchone()
            if row:
                payload_blob = bytes(row[8] or b"")
                output = {
                    "id": int(row[0]),
                    "request_key": str(row[1] or ""),
                    "name": str(row[2] or ""),
                    "proto": str(row[3] or ""),
                    "scope": str(row[4] or ""),
                    "port": int(row[5] or 0),
                    "payload_format": str(row[6] or "text"),
                    "payload_encoded": str(row[7] or ""),
                    "payload_len": len(payload_blob),
                    "payload_preview": _payload_preview(payload_blob),
                    "description": str(row[9] or ""),
                    "source": str(row[10] or ""),
                    "mutable": bool(int(row[11] or 0)),
                    "active": bool(int(row[12] or 0)),
                    "created_at": str(row[13] or ""),
                    "updated_at": str(row[14] or ""),
                }
        except Exception as e:
            self.conn.rollback()
            print("DB() -> update_banner_probe_request():", e)
            raise
        finally:
            cursor.close()
            self.lock.release()
        return output

    def delete_banner_probe_request(self, data):
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            request_id = int((data or {}).get("id"))
            cursor.execute(
                "SELECT mutable FROM banner_probe_catalog WHERE id = ? LIMIT 1;",
                (request_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise ValueError("Banner request not found")
            if int(row[0] or 0) == 0:
                raise PermissionError("Built-in banner requests cannot be deleted")
            cursor.execute("DELETE FROM banner_probe_catalog WHERE id = ?;", (request_id,))
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> delete_banner_probe_request():", e)
            raise
        finally:
            cursor.close()
            self.lock.release()

    def load_probe_payloads(self, proto):
        output = {"generic": [], "http": [], "overrides": {}}
        proto_value = str(proto or "").strip().lower()
        if proto_value not in {"tcp", "udp"}:
            return output
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "SELECT scope, port, payload FROM banner_probe_catalog "
                "WHERE proto = ? AND active = 1 "
                "ORDER BY source DESC, id ASC;",
                (proto_value,),
            )
            for scope, port, payload in cursor.fetchall():
                scope_value = str(scope or "").strip().lower()
                if scope_value not in PROBE_REQUEST_SCOPES:
                    continue
                raw_payload = bytes(payload or b"")
                if not raw_payload:
                    continue
                if scope_value == "port_override":
                    try:
                        port_value = int(port or 0)
                    except Exception:
                        continue
                    if port_value < 1 or port_value > 65535:
                        continue
                    output["overrides"].setdefault(port_value, []).append(raw_payload)
                elif scope_value == "http":
                    if proto_value != "tcp":
                        continue
                    output["http"].append(raw_payload)
                else:
                    output["generic"].append(raw_payload)
        except Exception as e:
            print("DB() -> load_probe_payloads():", e)
        finally:
            cursor.close()
            self.lock.release()
            return output

    def select_ip_presets(self, include_inactive=True):
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            where_sql = "" if include_inactive else "WHERE active = 1"
            cursor.execute(
                "SELECT id, value, label, description, source, mutable, active, created_at, updated_at "
                f"FROM ip_catalog {where_sql} "
                "ORDER BY source DESC, id ASC;"
            )
            for row in cursor.fetchall():
                output.append(
                    {
                        "id": int(row[0]),
                        "value": str(row[1] or ""),
                        "label": str(row[2] or ""),
                        "description": str(row[3] or ""),
                        "source": str(row[4] or ""),
                        "mutable": bool(int(row[5] or 0)),
                        "active": bool(int(row[6] or 0)),
                        "created_at": str(row[7] or ""),
                        "updated_at": str(row[8] or ""),
                    }
                )
        except Exception as e:
            print("DB() -> select_ip_presets():", e)
        finally:
            cursor.close()
            self.lock.release()
            return output

    def insert_ip_preset(self, data):
        output = {}
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            value = _normalize_ip_value((data or {}).get("value", ""))
            label = str((data or {}).get("label", "") or "").strip()
            description = str((data or {}).get("description", "") or "")
            active = 1 if _parse_bool((data or {}).get("active", True), default=True) else 0
            cursor.execute(
                "INSERT INTO ip_catalog (value, label, description, source, mutable, active) "
                "VALUES (?, ?, ?, 'user', 1, ?);",
                (value, label, description, active),
            )
            output_id = int(cursor.lastrowid)
            self.conn.commit()
            cursor.execute(
                "SELECT id, value, label, description, source, mutable, active, created_at, updated_at "
                "FROM ip_catalog WHERE id = ? LIMIT 1;",
                (output_id,),
            )
            row = cursor.fetchone()
            if row:
                output = {
                    "id": int(row[0]),
                    "value": str(row[1] or ""),
                    "label": str(row[2] or ""),
                    "description": str(row[3] or ""),
                    "source": str(row[4] or ""),
                    "mutable": bool(int(row[5] or 0)),
                    "active": bool(int(row[6] or 0)),
                    "created_at": str(row[7] or ""),
                    "updated_at": str(row[8] or ""),
                }
        except Exception as e:
            self.conn.rollback()
            print("DB() -> insert_ip_preset():", e)
            raise
        finally:
            cursor.close()
            self.lock.release()
        return output

    def update_ip_preset(self, data):
        output = {}
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            item_id = int((data or {}).get("id"))
            cursor.execute(
                "SELECT mutable FROM ip_catalog WHERE id = ? LIMIT 1;",
                (item_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise ValueError("IP preset not found")
            if int(row[0] or 0) == 0:
                raise PermissionError("Built-in IP presets cannot be modified")
            value = _normalize_ip_value((data or {}).get("value", ""))
            label = str((data or {}).get("label", "") or "").strip()
            description = str((data or {}).get("description", "") or "")
            active = 1 if _parse_bool((data or {}).get("active", True), default=True) else 0
            cursor.execute(
                "UPDATE ip_catalog SET value = ?, label = ?, description = ?, active = ?, "
                "updated_at = CURRENT_TIMESTAMP WHERE id = ?;",
                (value, label, description, active, item_id),
            )
            self.conn.commit()
            cursor.execute(
                "SELECT id, value, label, description, source, mutable, active, created_at, updated_at "
                "FROM ip_catalog WHERE id = ? LIMIT 1;",
                (item_id,),
            )
            row = cursor.fetchone()
            if row:
                output = {
                    "id": int(row[0]),
                    "value": str(row[1] or ""),
                    "label": str(row[2] or ""),
                    "description": str(row[3] or ""),
                    "source": str(row[4] or ""),
                    "mutable": bool(int(row[5] or 0)),
                    "active": bool(int(row[6] or 0)),
                    "created_at": str(row[7] or ""),
                    "updated_at": str(row[8] or ""),
                }
        except Exception as e:
            self.conn.rollback()
            print("DB() -> update_ip_preset():", e)
            raise
        finally:
            cursor.close()
            self.lock.release()
        return output

    def delete_ip_preset(self, data):
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            item_id = int((data or {}).get("id"))
            cursor.execute(
                "SELECT mutable FROM ip_catalog WHERE id = ? LIMIT 1;",
                (item_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise ValueError("IP preset not found")
            if int(row[0] or 0) == 0:
                raise PermissionError("Built-in IP presets cannot be deleted")
            cursor.execute("DELETE FROM ip_catalog WHERE id = ?;", (item_id,))
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> delete_ip_preset():", e)
            raise
        finally:
            cursor.close()
            self.lock.release()

    def _serialize_cluster_agent_credential_row(self, row):
        if not row:
            return {}
        return {
            "id": int(row[0]),
            "agent_id": str(row[1] or ""),
            "active": bool(int(row[2] or 0)),
            "created_at": str(row[3] or ""),
            "updated_at": str(row[4] or ""),
            "last_used_at": str(row[5] or ""),
        }

    def select_cluster_agent_credentials(self, include_inactive=True):
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            where_sql = "" if include_inactive else "WHERE active = 1"
            cursor.execute(
                "SELECT id, agent_id, active, created_at, updated_at, last_used_at "
                f"FROM cluster_agent_credentials {where_sql} "
                "ORDER BY id ASC;"
            )
            output = [
                self._serialize_cluster_agent_credential_row(row)
                for row in cursor.fetchall()
            ]
        except Exception as e:
            print("DB() -> select_cluster_agent_credentials():", e)
        finally:
            cursor.close()
            self.lock.release()
            return output

    def create_cluster_agent_credential(self, data):
        output = {}
        payload = dict(data or {})
        agent_id = _normalize_agent_id(payload.get("agent_id", ""), generate_if_missing=True)
        provided_token = ""
        for key in ("token", "agent_token", "agent_key", "shared_key", "key"):
            candidate = str(payload.get(key, "") or "").strip()
            if candidate:
                provided_token = candidate
                break
        if provided_token:
            agent_key = provided_token
        else:
            # URL-safe token is easy to copy in terminal and web onboarding.
            agent_key = secrets.token_urlsafe(24)
        key_hash = _hash_agent_shared_key(agent_key)

        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "SELECT id FROM cluster_agent_credentials WHERE agent_id = ? LIMIT 1;",
                (agent_id,),
            )
            existing = cursor.fetchone()
            if existing:
                row_id = int(existing[0])
                cursor.execute(
                    "UPDATE cluster_agent_credentials SET "
                    "key_hash = ?, active = 1, updated_at = CURRENT_TIMESTAMP "
                    "WHERE id = ?;",
                    (key_hash, row_id),
                )
            else:
                cursor.execute(
                    "INSERT INTO cluster_agent_credentials (agent_id, key_hash, active) "
                    "VALUES (?, ?, 1);",
                    (agent_id, key_hash),
                )
                row_id = int(cursor.lastrowid)
            self.conn.commit()
            cursor.execute(
                "SELECT id, agent_id, active, created_at, updated_at, last_used_at "
                "FROM cluster_agent_credentials WHERE id = ? LIMIT 1;",
                (row_id,),
            )
            output = self._serialize_cluster_agent_credential_row(cursor.fetchone())
            output["agent_key"] = agent_key
            output["token"] = agent_key
        except Exception as e:
            self.conn.rollback()
            print("DB() -> create_cluster_agent_credential():", e)
            raise
        finally:
            cursor.close()
            self.lock.release()
        return output

    def revoke_cluster_agent_credential(self, data):
        output = {}
        payload = dict(data or {})
        row_id = payload.get("id")
        agent_id_raw = str(payload.get("agent_id", "") or "").strip()
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            query = ""
            params = ()
            if row_id is not None:
                try:
                    row_id = int(row_id)
                except Exception:
                    raise ValueError("Invalid credential id")
                query = (
                    "SELECT id FROM cluster_agent_credentials "
                    "WHERE id = ? LIMIT 1;"
                )
                params = (row_id,)
            elif agent_id_raw:
                agent_id = _normalize_agent_id(agent_id_raw, generate_if_missing=False)
                query = (
                    "SELECT id FROM cluster_agent_credentials "
                    "WHERE agent_id = ? LIMIT 1;"
                )
                params = (agent_id,)
            else:
                raise ValueError("id or agent_id is required")
            cursor.execute(query, params)
            row = cursor.fetchone()
            if not row:
                raise ValueError("Agent credential not found")
            resolved_id = int(row[0])
            cursor.execute(
                "UPDATE cluster_agent_credentials SET "
                "active = 0, updated_at = CURRENT_TIMESTAMP "
                "WHERE id = ?;",
                (resolved_id,),
            )
            self.conn.commit()
            cursor.execute(
                "SELECT id, agent_id, active, created_at, updated_at, last_used_at "
                "FROM cluster_agent_credentials WHERE id = ? LIMIT 1;",
                (resolved_id,),
            )
            output = self._serialize_cluster_agent_credential_row(cursor.fetchone())
        except Exception as e:
            self.conn.rollback()
            print("DB() -> revoke_cluster_agent_credential():", e)
            raise
        finally:
            cursor.close()
            self.lock.release()
        return output

    def delete_cluster_agent_credential(self, data):
        output = {}
        payload = dict(data or {})
        row_id = payload.get("id")
        agent_id_raw = str(payload.get("agent_id", "") or "").strip()
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            query = ""
            params = ()
            if row_id is not None:
                try:
                    row_id = int(row_id)
                except Exception:
                    raise ValueError("Invalid credential id")
                query = (
                    "SELECT id, agent_id, active, created_at, updated_at, last_used_at "
                    "FROM cluster_agent_credentials WHERE id = ? LIMIT 1;"
                )
                params = (row_id,)
            elif agent_id_raw:
                agent_id = _normalize_agent_id(agent_id_raw, generate_if_missing=False)
                query = (
                    "SELECT id, agent_id, active, created_at, updated_at, last_used_at "
                    "FROM cluster_agent_credentials WHERE agent_id = ? LIMIT 1;"
                )
                params = (agent_id,)
            else:
                raise ValueError("id or agent_id is required")
            cursor.execute(query, params)
            row = cursor.fetchone()
            if not row:
                raise ValueError("Agent credential not found")
            output = self._serialize_cluster_agent_credential_row(row)
            resolved_id = int(row[0])
            cursor.execute(
                "DELETE FROM cluster_agent_credentials WHERE id = ?;",
                (resolved_id,),
            )
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> delete_cluster_agent_credential():", e)
            raise
        finally:
            cursor.close()
            self.lock.release()
        return output

    def verify_cluster_agent_shared_key(self, agent_id, agent_key, touch_last_used=True):
        valid = False
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            normalized_agent_id = _normalize_agent_id(
                agent_id,
                generate_if_missing=False,
            )
            provided_token = str(agent_key or "").strip()
            expected_hash = _hash_agent_shared_key(provided_token)
            cursor.execute(
                "SELECT key_hash, active FROM cluster_agent_credentials "
                "WHERE agent_id = ? LIMIT 1;",
                (normalized_agent_id,),
            )
            row = cursor.fetchone()
            if not row:
                return False
            if int(row[1] or 0) != 1:
                return False
            valid = hmac.compare_digest(str(row[0] or ""), expected_hash)
            if valid and touch_last_used:
                cursor.execute(
                    "UPDATE cluster_agent_credentials SET "
                    "last_used_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP "
                    "WHERE agent_id = ?;",
                    (normalized_agent_id,),
                )
                self.conn.commit()
        except Exception as e:
            print("DB() -> verify_cluster_agent_shared_key():", e)
            valid = False
        finally:
            cursor.close()
            self.lock.release()
            return bool(valid)

    def geoip_status(self):
        output = {}
        self.lock.acquire()
        try:
            output = read_geoip_status_from_db(self.conn, self.geoip_seed_path)
            self.geoip_status_cache = dict(output)
        except Exception as e:
            print("DB() -> geoip_status():", e)
            output = dict(self.geoip_status_cache or {})
        finally:
            self.lock.release()
            return output

    def lookup_geoip_ipv4(self, ip_value):
        output = None
        self.lock.acquire()
        try:
            output = lookup_geoip_ipv4_in_db(self.conn, ip_value)
        except Exception as e:
            print("DB() -> lookup_geoip_ipv4():", e)
            output = None
        finally:
            self.lock.release()
            return output

    def insert_targets(self, data: dict) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "INSERT OR IGNORE INTO targets ("
                "network, type, proto, port_mode, port_start, port_end, timesleep, status"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                (
                    data["network"],
                    data["type"],
                    data["proto"],
                    data.get("port_mode", "preset"),
                    data.get("port_start"),
                    data.get("port_end"),
                    data["timesleep"],
                    data.get("status", "active"),
                ),
            )
            self.conn.commit()
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> insert_targets():", e)
        finally:
            self.lock.release()
            return output

    def update_targets(self, data: dict) -> None:
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "SELECT id FROM targets WHERE id = ?;",
                (data["id"],),
            )
            row = cursor.fetchone()
            if row:
                cursor.execute(
                    "UPDATE targets "
                    "SET network = ?, "
                    " type = ?,"
                    " proto = ?,"
                    " port_mode = ?,"
                    " port_start = ?,"
                    " port_end = ?,"
                    " progress = ?,"
                    " timesleep = ?,"
                    " status = ? "
                    "WHERE id = ?;",
                    (
                        data["network"],
                        data["type"],
                        data["proto"],
                        data.get("port_mode", "preset"),
                        data.get("port_start"),
                        data.get("port_end"),
                        0.0,
                        data["timesleep"],
                        data.get("status", "active"),
                        data["id"],
                    ),
                )
                self.conn.commit()
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> update_targets():", e)
        finally:
            self.lock.release()

    def select_target_by_id(self, identifier: int):
        output = None
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "SELECT * FROM targets WHERE id = ? LIMIT 1;",
                (int(identifier),),
            )
            row = cursor.fetchone()
            if row:
                column_names = [col[0] for col in cursor.description]
                output = dict(zip(column_names, row))
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> select_target_by_id():", e)
        finally:
            self.lock.release()
            return output

    def set_target_status(self, data: dict) -> None:
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            status = str(data.get("status", "")).strip().lower()
            if status not in TARGET_STATUSES:
                raise ValueError("Invalid target status")
            cursor.execute(
                "UPDATE targets "
                "SET status = ?, "
                " updated_at = CURRENT_TIMESTAMP "
                "WHERE id = ?;",
                (status, int(data["id"])),
            )
            self.conn.commit()
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> set_target_status():", e)
        finally:
            self.lock.release()

    def set_target_progress(self, data: dict) -> None:
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "UPDATE targets "
                "SET progress = ?, "
                " updated_at = CURRENT_TIMESTAMP "
                "WHERE id = ?;",
                (float(data["progress"]), int(data["id"])),
            )
            self.conn.commit()
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> set_target_progress():", e)
        finally:
            self.lock.release()

    def clear_target_artifacts(self, data: dict) -> None:
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "SELECT network, proto FROM targets WHERE id = ? LIMIT 1;",
                (int(data["id"]),),
            )
            row = cursor.fetchone()
            if not row:
                cursor.close()
                return
            network = ipaddress.ip_network(str(row[0]), strict=False)
            proto = str(row[1])

            def _collect_ids(table_name: str):
                cursor.execute(
                    f"SELECT id, ip FROM {table_name} WHERE proto = ?;",
                    (proto,),
                )
                matched = []
                for result_id, ip_value in cursor.fetchall():
                    try:
                        ip_addr = ipaddress.ip_address(str(ip_value))
                    except Exception:
                        continue
                    if ip_addr in network:
                        matched.append((result_id,))
                return matched

            ports_ids = _collect_ids("ports")
            tags_ids = _collect_ids("tags")
            banners_ids = _collect_ids("banners")
            favicons_ids = _collect_ids("favicons")

            if ports_ids:
                cursor.executemany("DELETE FROM ports WHERE id = ?;", ports_ids)
            if tags_ids:
                cursor.executemany("DELETE FROM tags WHERE id = ?;", tags_ids)
            if banners_ids:
                cursor.executemany("DELETE FROM banners WHERE id = ?;", banners_ids)
            if favicons_ids:
                cursor.executemany("DELETE FROM favicons WHERE id = ?;", favicons_ids)
            self.conn.commit()
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> clear_target_artifacts():", e)
        finally:
            self.lock.release()

    def delete_target(self, data: dict) -> None:
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "DELETE FROM targets WHERE id = ?;",
                (data["id"],),
            )
            self.conn.commit()
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> delete_target():", e)
        finally:
            self.lock.release()

    def delete_banners(self) -> None:
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("DELETE FROM banners;")
            self.conn.commit()
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> delete_banners():", e)
        finally:
            self.lock.release()

    def delete_favicons(self) -> None:
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("DELETE FROM favicons;")
            self.conn.commit()
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> delete_favicons():", e)
        finally:
            self.lock.release()

    def delete_ports_where_tcp(self) -> None:
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("DELETE FROM ports WHERE proto = ?;", ("tcp",))
            self.conn.commit()
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> delete_ports_where_tcp():", e)
        finally:
            self.lock.release()

    def delete_ports_where_udp(self) -> None:
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("DELETE FROM ports WHERE proto = ?;", ("udp",))
            self.conn.commit()
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> delete_ports_where_udp():", e)
        finally:
            self.lock.release()

    def delete_ports_where_icmp(self) -> None:
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("DELETE FROM ports WHERE proto = ?;", ("icmp",))
            self.conn.commit()
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> delete_ports_where_icmp():", e)
        finally:
            self.lock.release()

    def delete_ports_where_sctp(self) -> None:
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("DELETE FROM ports WHERE proto = ?;", ("sctp",))
            self.conn.commit()
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> delete_ports_where_sctp():", e)
        finally:
            self.lock.release()

    def select_targets(self) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT * FROM targets;")
            column_names = [col[0] for col in cursor.description]
            output = [dict(zip(column_names, row)) for row in cursor.fetchall()]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> select_targets():", e)
        finally:
            self.lock.release()
            return output

    def select_targets_where_tcp(self) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "SELECT * FROM targets "
                "WHERE proto = ? "
                "AND status IN ('active', 'restarting');",
                ("tcp",),
            )
            column_names = [col[0] for col in cursor.description]
            output = [dict(zip(column_names, row)) for row in cursor.fetchall()]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> select_targets_where_tcp():", e)
        finally:
            self.lock.release()
            return output

    def select_targets_where_udp(self) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "SELECT * FROM targets "
                "WHERE proto = ? "
                "AND status IN ('active', 'restarting');",
                ("udp",),
            )
            column_names = [col[0] for col in cursor.description]
            output = [dict(zip(column_names, row)) for row in cursor.fetchall()]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> select_targets_where_udp():", e)
        finally:
            self.lock.release()
            return output

    def select_targets_where_icmp(self) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "SELECT * FROM targets "
                "WHERE proto = ? "
                "AND status IN ('active', 'restarting');",
                ("icmp",),
            )
            column_names = [col[0] for col in cursor.description]
            output = [dict(zip(column_names, row)) for row in cursor.fetchall()]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> select_targets_where_icmp():", e)
        finally:
            self.lock.release()
            return output

    def select_targets_where_sctp(self) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "SELECT * FROM targets "
                "WHERE proto IN (?, ?) "
                "AND status IN ('active', 'restarting');",
                ("sctp", "stcp"),
            )
            column_names = [col[0] for col in cursor.description]
            output = [dict(zip(column_names, row)) for row in cursor.fetchall()]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> select_targets_where_sctp():", e)
        finally:
            self.lock.release()
            return output

    def exists_targets(self, data: dict) -> bool:
        exists = False
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "SELECT * FROM targets "
                "WHERE network = ? AND "
                "type = ? AND "
                "proto = ? AND "
                "COALESCE(port_mode, 'preset') = ? AND "
                "COALESCE(port_start, -1) = COALESCE(?, -1) AND "
                "COALESCE(port_end, -1) = COALESCE(?, -1) AND "
                "timesleep = ?;",
                (
                    data["network"],
                    data["type"],
                    data["proto"],
                    data.get("port_mode", "preset"),
                    data.get("port_start"),
                    data.get("port_end"),
                    data["timesleep"],
                ),
            )
            row = cursor.fetchone()
            if row:
                exists = True
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> exists_targets():", e)
        finally:
            self.lock.release()
            return exists

    def select_ports(self) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT * FROM ports;")
            column_names = [col[0] for col in cursor.description]
            output = [dict(zip(column_names, row)) for row in cursor.fetchall()]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> select_ports():", e)
        finally:
            self.lock.release()
            return output

    def select_port_by_id(self, identifier: int):
        output = None
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT * FROM ports WHERE id = ? LIMIT 1;", (int(identifier),))
            row = cursor.fetchone()
            if row:
                column_names = [col[0] for col in cursor.description]
                output = dict(zip(column_names, row))
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> select_port_by_id():", e)
        finally:
            self.lock.release()
            return output

    def set_port_scan_state(self, data: dict) -> None:
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            status = str(data.get("scan_state", "")).strip().lower()
            if status not in PORT_SCAN_STATUSES:
                raise ValueError("Invalid port scan state")
            cursor.execute(
                "UPDATE ports "
                "SET scan_state = ?, "
                " updated_at = CURRENT_TIMESTAMP "
                "WHERE id = ?;",
                (status, int(data["id"])),
            )
            self.conn.commit()
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> set_port_scan_state():", e)
        finally:
            self.lock.release()

    def clear_port_artifacts(self, data: dict) -> None:
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "SELECT ip, port, proto FROM ports WHERE id = ? LIMIT 1;",
                (int(data["id"]),),
            )
            row = cursor.fetchone()
            if not row:
                cursor.close()
                return
            ip_value, port_value, proto_value = str(row[0]), int(row[1]), str(row[2])
            cursor.execute(
                "DELETE FROM banners WHERE ip = ? AND port = ? AND proto = ?;",
                (ip_value, port_value, proto_value),
            )
            cursor.execute(
                "DELETE FROM favicons WHERE ip = ? AND port = ? AND proto = ?;",
                (ip_value, port_value, proto_value),
            )
            cursor.execute(
                "DELETE FROM tags WHERE ip = ? AND port = ? AND proto = ?;",
                (ip_value, port_value, proto_value),
            )
            self.conn.commit()
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> clear_port_artifacts():", e)
        finally:
            self.lock.release()

    def select_ports_where_tcp(self) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT * FROM ports WHERE proto='tcp';")
            column_names = [col[0] for col in cursor.description]
            output = [dict(zip(column_names, row)) for row in cursor.fetchall()]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> select_ports_where_tcp():", e)
        finally:
            self.lock.release()
            return output

    def select_ports_where_udp(self) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT * FROM ports WHERE proto='udp';")
            column_names = [col[0] for col in cursor.description]
            output = [dict(zip(column_names, row)) for row in cursor.fetchall()]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> select_ports_where_udp():", e)
        finally:
            self.lock.release()
            return output

    def select_ports_where_icmp(self) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT * FROM ports WHERE proto='icmp';")
            column_names = [col[0] for col in cursor.description]
            output = [dict(zip(column_names, row)) for row in cursor.fetchall()]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> select_ports_where_icmp():", e)
        finally:
            self.lock.release()
            return output

    def select_ports_where_sctp(self) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT * FROM ports WHERE proto='sctp';")
            column_names = [col[0] for col in cursor.description]
            output = [dict(zip(column_names, row)) for row in cursor.fetchall()]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> select_ports_where_sctp():", e)
        finally:
            self.lock.release()
            return output

    def select_tags(self) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT * FROM tags;")
            column_names = [col[0] for col in cursor.description]
            output = [dict(zip(column_names, row)) for row in cursor.fetchall()]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> select_tags():", e)
        finally:
            self.lock.release()
            return output

    def select_tags_tcp(self) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT * FROM tags WHERE " "proto = ?;", ("tcp",))
            column_names = [col[0] for col in cursor.description]
            output = [dict(zip(column_names, row)) for row in cursor.fetchall()]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> select_tags_tcp():", e)
        finally:
            self.lock.release()
            return output

    def select_tags_udp(self) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT * FROM tags WHERE " "proto = ?;", ("udp",))
            column_names = [col[0] for col in cursor.description]
            output = [dict(zip(column_names, row)) for row in cursor.fetchall()]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> select_tags_udp():", e)
        finally:
            self.lock.release()
            return output

    def select_tags_icmp(self) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT * FROM tags WHERE " "proto = ?;", ("icmp",))
            column_names = [col[0] for col in cursor.description]
            output = [dict(zip(column_names, row)) for row in cursor.fetchall()]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> select_tags_icmp():", e)
        finally:
            self.lock.release()
            return output

    def select_tags_sctp(self) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT * FROM tags WHERE " "proto = ?;", ("sctp",))
            column_names = [col[0] for col in cursor.description]
            output = [dict(zip(column_names, row)) for row in cursor.fetchall()]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> select_tags_sctp():", e)
        finally:
            self.lock.release()
            return output

    def select_banners(self) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "SELECT "
                "b.id, b.ip, b.port, b.proto, b.response_plain, b.created_at, b.updated_at, "
                "p.id AS port_id, p.progress AS scan_progress, p.scan_state AS scan_state "
                "FROM banners b "
                "LEFT JOIN ports p "
                "ON p.ip = b.ip AND p.port = b.port AND p.proto = b.proto;"
            )
            output = [
                {
                    "id": row[0],
                    "ip": row[1],
                    "port": row[2],
                    "proto": row[3],
                    "response_plain": row[4],
                    "created_at": row[5],
                    "updated_at": row[6],
                    "port_id": row[7],
                    "scan_progress": row[8],
                    "scan_state": row[9],
                }
                for row in cursor.fetchall()
            ]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> select_banners():", e)
        finally:
            self.lock.release()
            return output

    def banner_exists(self, ip: str, port: int, proto: str) -> bool:
        exists = False
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "SELECT 1 FROM banners WHERE ip = ? AND port = ? AND proto = ? LIMIT 1;",
                (str(ip), int(port), str(proto)),
            )
            exists = cursor.fetchone() is not None
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> banner_exists():", e)
        finally:
            self.lock.release()
            return exists

    def select_favicons(self) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "SELECT id, ip, port, proto, icon_url, mime_type, size, sha256, created_at, updated_at "
                "FROM favicons "
                "ORDER BY id DESC;"
            )
            output = [
                {
                    "id": row[0],
                    "ip": row[1],
                    "port": row[2],
                    "proto": row[3],
                    "icon_url": row[4],
                    "mime_type": row[5],
                    "size": row[6],
                    "sha256": row[7],
                    "created_at": row[8],
                    "updated_at": row[9],
                }
                for row in cursor.fetchall()
            ]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> select_favicons():", e)
        finally:
            self.lock.release()
            return output

    def get_favicon_by_id(self, icon_id: int):
        output = None
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "SELECT id, ip, port, proto, icon_url, mime_type, icon_blob, size, sha256, created_at, updated_at "
                "FROM favicons "
                "WHERE id = ?;",
                (int(icon_id),),
            )
            row = cursor.fetchone()
            if row:
                output = {
                    "id": row[0],
                    "ip": row[1],
                    "port": row[2],
                    "proto": row[3],
                    "icon_url": row[4],
                    "mime_type": row[5],
                    "icon_blob": row[6],
                    "size": row[7],
                    "sha256": row[8],
                    "created_at": row[9],
                    "updated_at": row[10],
                }
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> get_favicon_by_id():", e)
        finally:
            self.lock.release()
            return output

    def insert_banners(self, data: dict) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "INSERT OR IGNORE INTO banners (ip, port, proto, response, response_plain) VALUES (?, ?, ?, ?, ?);",
                (
                    data["ip"],
                    data["port"],
                    data["proto"],
                    data["response"],
                    data["response_plain"],
                ),
            )
            self.conn.commit()
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> insert_banners():", e)
        finally:
            self.lock.release()
            return output

    def insert_favicon(self, data: dict) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "INSERT OR IGNORE INTO favicons "
                "(ip, port, proto, icon_url, mime_type, icon_blob, size, sha256) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                (
                    data["ip"],
                    data["port"],
                    data["proto"],
                    data["icon_url"],
                    data["mime_type"],
                    data["icon_blob"],
                    data["size"],
                    data["sha256"],
                ),
            )
            self.conn.commit()
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> insert_favicon():", e)
        finally:
            self.lock.release()
            return output

    def favicon_exists(self, ip: str, port: int, proto: str) -> bool:
        exists = False
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "SELECT 1 FROM favicons WHERE ip = ? AND port = ? AND proto = ? LIMIT 1;",
                (ip, int(port), proto),
            )
            exists = cursor.fetchone() is not None
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> favicon_exists():", e)
        finally:
            self.lock.release()
            return exists

    def insert_port(self, data: dict) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO ports (ip, port, proto, state) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(ip, port, proto) DO UPDATE SET "
                "state = excluded.state, "
                "progress = CASE "
                "WHEN COALESCE(scan_state, 'active') = 'stopped' THEN progress "
                "ELSE 0.0 END, "
                "scan_state = CASE "
                "WHEN COALESCE(scan_state, 'active') = 'stopped' THEN 'stopped' "
                "ELSE 'active' END, "
                "updated_at = CURRENT_TIMESTAMP;",
                (
                    data["ip"],
                    data["port"],
                    data["proto"],
                    data["state"],
                ),
            )
            self.conn.commit()
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> insert_port():", e)
        finally:
            self.lock.release()
            return output

    def insert_tags(self, data: dict) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO tags (ip, port, proto, key, value) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(ip, port, proto, key) DO UPDATE SET "
                "value = excluded.value, "
                "updated_at = CURRENT_TIMESTAMP;",
                (
                    data["ip"],
                    data["port"],
                    data["proto"],
                    data["key"],
                    data["value"],
                ),
            )
            self.conn.commit()
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> insert_tags():", e)
        finally:
            self.lock.release()
            return output

    def targets_progress(self, data: dict) -> None:
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "SELECT id FROM targets WHERE id = ?;",
                (data["id"],),
            )
            row = cursor.fetchone()
            if row:
                cursor.execute(
                    "UPDATE targets "
                    "SET progress = ? "
                    "WHERE id = ? "
                    "AND proto = ?;",
                    (data["progress"], data["id"], data["proto"]),
                )
                self.conn.commit()
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> targets_progress():", e)
        finally:
            self.lock.release()

    def ports_progress(self, data: dict) -> None:
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "SELECT id FROM ports WHERE id = ?;",
                (data["id"],),
            )
            row = cursor.fetchone()
            if row:
                cursor.execute(
                    "UPDATE ports " "SET progress = ? " "WHERE id = ?;",
                    (data["progress"], data["id"]),
                )
                self.conn.commit()
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> ports_progress():", e)
        finally:
            self.lock.release()

    def is_port_scan_runnable(self, identifier: int) -> bool:
        runnable = False
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "SELECT scan_state FROM ports WHERE id = ? LIMIT 1;",
                (int(identifier),),
            )
            row = cursor.fetchone()
            runnable = bool(
                row and str(row[0] or "").strip().lower() in {"active", "restarting"}
            )
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> is_port_scan_runnable():", e)
        finally:
            self.lock.release()
            return runnable

    def select_ports_where_udp_for_scan(self) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "SELECT * FROM ports "
                "WHERE proto = 'udp' "
                "AND scan_state IN ('active', 'restarting');"
            )
            column_names = [col[0] for col in cursor.description]
            output = [dict(zip(column_names, row)) for row in cursor.fetchall()]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> select_ports_where_udp_for_scan():", e)
        finally:
            self.lock.release()
            return output

    def select_ports_where_tcp_for_scan(self) -> list:
        output = []
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                "SELECT * FROM ports "
                "WHERE proto = 'tcp' "
                "AND scan_state IN ('active', 'restarting');"
            )
            column_names = [col[0] for col in cursor.description]
            output = [dict(zip(column_names, row)) for row in cursor.fetchall()]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> select_ports_where_tcp_for_scan():", e)
        finally:
            self.lock.release()
            return output

    def count_ports(self) -> None:
        count = 0
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT COUNT(id) FROM ports;")
            count = cursor.fetchone()[0]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> count_ports():", e)
        finally:
            self.lock.release()
            return count

    def count_ports_where_udp(self) -> None:
        count = 0
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT COUNT(id) FROM ports WHERE proto = ?;", ("udp",))
            count = cursor.fetchone()[0]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> count_ports_where_udp():", e)
        finally:
            self.lock.release()
            return count

    def count_ports_where_tcp(self) -> None:
        count = 0
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT COUNT(id) FROM ports WHERE proto = ?;", ("tcp",))
            count = cursor.fetchone()[0]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> count_ports_where_tcp():", e)
        finally:
            self.lock.release()
            return count

    def count_ports_where_icmp(self) -> None:
        count = 0
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT COUNT(id) FROM ports WHERE proto = ?;", ("icmp",))
            count = cursor.fetchone()[0]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> count_ports_where_icmp():", e)
        finally:
            self.lock.release()
            return count

    def count_ports_where_sctp(self) -> None:
        count = 0
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT COUNT(id) FROM ports WHERE proto = ?;", ("sctp",))
            count = cursor.fetchone()[0]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> count_ports_where_sctp():", e)
        finally:
            self.lock.release()
            return count

    def count_banners(self) -> None:
        count = 0
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT COUNT(id) FROM banners;")
            count = cursor.fetchone()[0]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> count_banners():", e)
        finally:
            self.lock.release()
            return count

    def count_favicons(self) -> None:
        count = 0
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT COUNT(id) FROM favicons;")
            count = cursor.fetchone()[0]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> count_favicons():", e)
        finally:
            self.lock.release()
            return count

    def count_targets(self) -> None:
        count = 0
        self.lock.acquire()
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT COUNT(id) FROM targets;")
            count = cursor.fetchone()[0]
            cursor.close()
        except Exception as e:
            self.conn.rollback()
            print("DB() -> count_targets():", e)
        finally:
            self.lock.release()
            return count


class API(threading.Thread):
    STATUS_MESSAGES = {
        # Respuestas informativas (1xx)
        100: "Continue",
        101: "Switching Protocols",
        102: "Processing",
        103: "Early Hints",
        # Respuestas satisfactorias (2xx)
        200: "OK",
        201: "Created",
        202: "Accepted",
        203: "Non-Authoritative Information",
        204: "No Content",
        205: "Reset Content",
        206: "Partial Content",
        207: "Multi-Status",
        208: "Already Reported",
        226: "IM Used",
        # Redirecciones (3xx)
        300: "Multiple Choices",
        301: "Moved Permanently",
        302: "Found",
        303: "See Other",
        304: "Not Modified",
        305: "Use Proxy",
        307: "Temporary Redirect",
        308: "Permanent Redirect",
        # Errores del cliente (4xx)
        400: "Bad Request",
        401: "Unauthorized",
        402: "Payment Required",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        406: "Not Acceptable",
        407: "Proxy Authentication Required",
        408: "Request Timeout",
        409: "Conflict",
        410: "Gone",
        411: "Length Required",
        412: "Precondition Failed",
        413: "Payload Too Large",
        414: "URI Too Long",
        415: "Unsupported Media Type",
        416: "Range Not Satisfiable",
        417: "Expectation Failed",
        418: "I'm a teapot",
        421: "Misdirected Request",
        422: "Unprocessable Entity",
        423: "Locked",
        424: "Failed Dependency",
        425: "Too Early",
        426: "Upgrade Required",
        428: "Precondition Required",
        429: "Too Many Requests",
        431: "Request Header Fields Too Large",
        451: "Unavailable For Legal Reasons",
        # Errores del servidor (5xx)
        500: "Internal Server Error",
        501: "Not Implemented",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout",
        505: "HTTP Version Not Supported",
        506: "Variant Also Negotiates",
        507: "Insufficient Storage",
        508: "Loop Detected",
        510: "Not Extended",
        511: "Network Authentication Required",
    }
    REGEX_IPV4_CIDR = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
    VALID_TARGET_TYPES = TARGET_TYPES
    VALID_TARGET_PROTOS = TARGET_PROTOS
    VALID_TARGET_STATUSES = TARGET_STATUSES
    VALID_TARGET_PORT_MODES = TARGET_PORT_MODES
    MAX_CONNECTION_WORKERS = 32
    MAX_REQUEST_HEADER_BYTES = 64 * 1024
    MAX_REQUEST_BODY_BYTES = 2 * 1024 * 1024
    REQUEST_RECV_CHUNK_SIZE = 4096
    REQUEST_SOCKET_TIMEOUT = 10.0

    def __init__(self, db: DB, host="127.0.0.1", port=45678):
        threading.Thread.__init__(self)
        self.host = host
        self.port = port
        self.db = db
        self.stop_event = threading.Event()

    def run(self):
        self.db.create_tables()
        threading.Thread(target=self.task, daemon=True).start()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            print(f"Server running on {self.host}:{self.port}")
            with ThreadPoolExecutor(
                max_workers=self.MAX_CONNECTION_WORKERS,
                thread_name_prefix="legacy-api",
            ) as pool:
                while True:
                    conn, addr = s.accept()
                    pool.submit(self.handle_client, conn, addr)

    def _recv_http_request(self, conn):
        conn.settimeout(self.REQUEST_SOCKET_TIMEOUT)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(self.REQUEST_RECV_CHUNK_SIZE)
            if not chunk:
                break
            data += chunk
            if len(data) > self.MAX_REQUEST_HEADER_BYTES:
                raise ValueError("Request headers too large")

        if not data:
            return ""

        header_blob, separator, remainder = data.partition(b"\r\n\r\n")
        if not separator:
            # No body marker, parse what we got.
            return data.decode("utf-8", errors="ignore")

        header_text = header_blob.decode("iso-8859-1", errors="ignore")
        content_length = 0
        for line in header_text.split("\r\n")[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            if key.strip().lower() == "content-length":
                try:
                    content_length = int(value.strip())
                except Exception:
                    raise ValueError("Invalid Content-Length")
                break

        if content_length < 0:
            raise ValueError("Invalid Content-Length")
        if content_length > self.MAX_REQUEST_BODY_BYTES:
            raise ValueError("Payload Too Large")

        while len(remainder) < content_length:
            chunk = conn.recv(
                min(
                    self.REQUEST_RECV_CHUNK_SIZE,
                    content_length - len(remainder),
                )
            )
            if not chunk:
                break
            remainder += chunk

        if len(remainder) < content_length:
            raise ValueError("Incomplete request body")

        body_blob = remainder[:content_length] if content_length else remainder
        request_blob = header_blob + b"\r\n\r\n" + body_blob
        return request_blob.decode("utf-8", errors="ignore")

    def handle_client(self, conn, addr):
        with conn:
            try:
                request = self._recv_http_request(conn)
                if not request:
                    return
                response = self.process_request(request)
                conn.sendall(response)
            except ValueError as e:
                error_response = self.build_response(
                    400, json.dumps({"status": "error", "message": str(e)})
                )
                conn.sendall(error_response)
            except Exception as e:
                error_response = self.build_response(
                    500, json.dumps({"status": "error", "message": str(e)})
                )
                conn.sendall(error_response)

    def task(self):
        while not self.stop_event.is_set():
            try:
                pass
            except Exception as e:
                print("API() -> task()", e)
            finally:
                self.stop_event.wait(5)

    def parse_request(self, request):
        lines = request.split("\r\n")
        method, full_path, _ = lines[0].split()
        path = full_path.split("?", 1)[0]
        body = request.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in request else ""
        return method, path, body

    def build_response(self, status_code, body, headers=None):
        status_message = self.STATUS_MESSAGES.get(status_code, "Unknown")
        response_headers = (
            f"HTTP/1.1 {status_code} {status_message}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body.encode())}\r\n"
            "Access-Control-Allow-Origin: *\r\n"
        )
        if headers:
            for key, value in headers.items():
                response_headers += f"{key}: {value}\r\n"
        response_headers += "\r\n"
        return (response_headers + body).encode()

    def normalize_target_item(self, item, require_id=False):
        if not isinstance(item, dict):
            raise ValueError("Invalid target body")
        output = dict(item)

        if require_id:
            try:
                output["id"] = int(output.get("id"))
            except Exception:
                raise ValueError("Invalid target id")

        network = str(output.get("network", "")).strip()
        if not self.REGEX_IPV4_CIDR.match(network):
            raise ValueError("Invalid CIDR format")
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
        except Exception:
            raise ValueError("Invalid CIDR format")
        if not isinstance(network_obj, ipaddress.IPv4Network):
            raise ValueError("Only IPv4 CIDR is supported")
        output["network"] = str(network_obj)

        target_type = str(output.get("type", "")).strip().lower()
        if target_type not in self.VALID_TARGET_TYPES:
            raise ValueError("Invalid type. Use common, not_common or full")
        output["type"] = target_type

        proto = str(output.get("proto", "")).strip().lower()
        if proto == "stcp":
            proto = "sctp"
        if proto not in self.VALID_TARGET_PROTOS:
            allowed = ", ".join(sorted(self.VALID_TARGET_PROTOS))
            raise ValueError(f"Invalid proto. Use {allowed}")
        output["proto"] = proto

        try:
            timesleep = float(output.get("timesleep", 1.0))
        except Exception:
            raise ValueError("Invalid timesleep")
        if timesleep < 0:
            raise ValueError("timesleep must be >= 0")
        output["timesleep"] = timesleep

        target_status = str(output.get("status", "active")).strip().lower()
        if target_status not in self.VALID_TARGET_STATUSES:
            allowed = ", ".join(sorted(self.VALID_TARGET_STATUSES))
            raise ValueError(f"Invalid status. Use {allowed}")
        output["status"] = target_status

        port_config = normalize_target_port_config(output, proto=proto)
        output["port_mode"] = port_config["port_mode"]
        output["port_start"] = port_config["port_start"]
        output["port_end"] = port_config["port_end"]

        return output

    def normalize_target_action(self, item):
        if not isinstance(item, dict):
            raise ValueError("Invalid target action body")
        output = dict(item)

        try:
            output["id"] = int(output.get("id"))
        except Exception:
            raise ValueError("Invalid target id")

        action = str(output.get("action", "")).strip().lower()
        if action not in {"start", "restart", "stop", "delete"}:
            raise ValueError("Invalid action. Use start, restart, stop or delete")
        output["action"] = action

        output["clean_results"] = bool(output.get("clean_results", True))
        return output

    def process_request(self, request):
        method, path, body = self.parse_request(request)
        response = self.build_response(500, json.dumps({"status": "none"}))
        try:
            if path == "/":
                if method == "GET":
                    response = self.build_response(
                        200,
                        json.dumps(
                            {
                                "count_ports": self.db.count_ports(),
                                "count_banners": self.db.count_banners(),
                                "count_targets": self.db.count_targets(),
                            }
                        ),
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/protocols/":
                if method == "GET":
                    response = self.build_response(
                        200, json.dumps({"datas": sorted(self.VALID_TARGET_PROTOS)})
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/count/targets/":
                if method == "GET":
                    response = self.build_response(
                        200, json.dumps({"count": self.db.count_targets()})
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/count/ports/":
                if method == "GET":
                    response = self.build_response(
                        200, json.dumps({"count": self.db.count_ports()})
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/count/ports/udp/":
                if method == "GET":
                    response = self.build_response(
                        200, json.dumps({"count": self.db.count_ports_where_udp()})
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/count/ports/tcp/":
                if method == "GET":
                    response = self.build_response(
                        200, json.dumps({"count": self.db.count_ports_where_tcp()})
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/count/ports/icmp/":
                if method == "GET":
                    response = self.build_response(
                        200, json.dumps({"count": self.db.count_ports_where_icmp()})
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/count/ports/sctp/" or path == "/count/ports/stcp/":
                if method == "GET":
                    response = self.build_response(
                        200, json.dumps({"count": self.db.count_ports_where_sctp()})
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/count/banners/":
                if method == "GET":
                    response = self.build_response(
                        200, json.dumps({"count": self.db.count_banners()})
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/targets/":
                if method == "GET":
                    response = self.build_response(
                        200, json.dumps({"datas": self.db.select_targets()})
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/target/":
                if method == "POST":
                    item = self.normalize_target_item(json.loads(body))
                    self.db.insert_targets(data=item)
                    response = self.build_response(200, json.dumps(item))
                elif method == "PUT":
                    item = self.normalize_target_item(json.loads(body), require_id=True)
                    self.db.update_targets(data=item)
                    response = self.build_response(200, json.dumps(item))
                elif method == "DELETE":
                    item = json.loads(body)
                    item["id"] = int(item["id"])
                    self.db.delete_target(data=item)
                    response = self.build_response(200, json.dumps(item))
                elif method == "OPTIONS":
                    response = self.build_response(
                        200,
                        "",
                        headers={
                            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                            "Access-Control-Allow-Headers": "Content-Type, Authorization",
                        },
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/target/action/":
                if method == "POST":
                    item = self.normalize_target_action(json.loads(body))
                    current_target = self.db.select_target_by_id(item["id"])
                    if not current_target:
                        response = self.build_response(
                            404, json.dumps({"status": "Target not found"})
                        )
                    else:
                        action = item["action"]
                        target_id = item["id"]
                        clean_results = bool(item.get("clean_results", True))
                        try:
                            current_progress = float(
                                current_target.get("progress", 0.0) or 0.0
                            )
                        except Exception:
                            current_progress = 0.0
                        if action == "start":
                            if current_progress >= 100.0:
                                self.db.set_target_progress(
                                    data={"id": target_id, "progress": 0.0}
                                )
                                self.db.set_target_status(
                                    data={"id": target_id, "status": "restarting"}
                                )
                            else:
                                self.db.set_target_status(
                                    data={"id": target_id, "status": "active"}
                                )
                        elif action == "restart":
                            if clean_results:
                                self.db.clear_target_artifacts(data={"id": target_id})
                            self.db.set_target_progress(
                                data={"id": target_id, "progress": 0.0}
                            )
                            self.db.set_target_status(
                                data={"id": target_id, "status": "restarting"}
                            )
                        elif action == "stop":
                            self.db.set_target_status(
                                data={"id": target_id, "status": "stopped"}
                            )
                        elif action == "delete":
                            self.db.set_target_status(
                                data={"id": target_id, "status": "stopped"}
                            )
                            if clean_results:
                                self.db.clear_target_artifacts(data={"id": target_id})
                            self.db.delete_target(data={"id": target_id})
                        response = self.build_response(
                            200,
                            json.dumps(
                                {
                                    "status": "200",
                                    "action": action,
                                    "id": target_id,
                                    "target": self.db.select_target_by_id(target_id),
                                }
                            ),
                        )
                elif method == "OPTIONS":
                    response = self.build_response(
                        200,
                        "",
                        headers={
                            "Access-Control-Allow-Methods": "POST, OPTIONS",
                            "Access-Control-Allow-Headers": "Content-Type, Authorization",
                        },
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/ports/":
                if method == "GET":
                    response = self.build_response(
                        200,
                        json.dumps({"datas": self.db.select_ports()}),
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/ports/udp/":
                if method == "GET":
                    response = self.build_response(
                        200,
                        json.dumps({"datas": self.db.select_ports_where_udp()}),
                    )
                elif method == "DELETE":
                    self.db.delete_ports_where_udp()
                    response = self.build_response(200, json.dumps({"status": "200"}))
                elif method == "OPTIONS":
                    response = self.build_response(
                        200,
                        "",
                        headers={
                            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                            "Access-Control-Allow-Headers": "Content-Type, Authorization",
                        },
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/ports/tcp/":
                if method == "GET":
                    response = self.build_response(
                        200,
                        json.dumps({"datas": self.db.select_ports_where_tcp()}),
                    )
                elif method == "DELETE":
                    self.db.delete_ports_where_tcp()
                    response = self.build_response(200, json.dumps({"status": "200"}))
                elif method == "OPTIONS":
                    response = self.build_response(
                        200,
                        "",
                        headers={
                            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                            "Access-Control-Allow-Headers": "Content-Type, Authorization",
                        },
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/ports/icmp/":
                if method == "GET":
                    response = self.build_response(
                        200,
                        json.dumps({"datas": self.db.select_ports_where_icmp()}),
                    )
                elif method == "DELETE":
                    self.db.delete_ports_where_icmp()
                    response = self.build_response(200, json.dumps({"status": "200"}))
                elif method == "OPTIONS":
                    response = self.build_response(
                        200,
                        "",
                        headers={
                            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                            "Access-Control-Allow-Headers": "Content-Type, Authorization",
                        },
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/ports/sctp/" or path == "/ports/stcp/":
                if method == "GET":
                    response = self.build_response(
                        200,
                        json.dumps({"datas": self.db.select_ports_where_sctp()}),
                    )
                elif method == "DELETE":
                    self.db.delete_ports_where_sctp()
                    response = self.build_response(200, json.dumps({"status": "200"}))
                elif method == "OPTIONS":
                    response = self.build_response(
                        200,
                        "",
                        headers={
                            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                            "Access-Control-Allow-Headers": "Content-Type, Authorization",
                        },
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/tags/":
                if method == "GET":
                    response = self.build_response(
                        200, json.dumps({"datas": self.db.select_tags()})
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/tags/tcp/":
                if method == "GET":
                    response = self.build_response(
                        200, json.dumps({"datas": self.db.select_tags_tcp()})
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/tags/udp/":
                if method == "GET":
                    response = self.build_response(
                        200, json.dumps({"datas": self.db.select_tags_udp()})
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/tags/icmp/":
                if method == "GET":
                    response = self.build_response(
                        200, json.dumps({"datas": self.db.select_tags_icmp()})
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/tags/sctp/" or path == "/tags/stcp/":
                if method == "GET":
                    response = self.build_response(
                        200, json.dumps({"datas": self.db.select_tags_sctp()})
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/api/catalog/banner-rules/":
                if method == "GET":
                    response = self.build_response(
                        200,
                        json.dumps(
                            {"datas": self.db.select_banner_regex_rules(include_inactive=True)}
                        ),
                    )
                elif method == "POST":
                    item = self.db.insert_banner_regex_rule(json.loads(body or "{}"))
                    response = self.build_response(
                        200, json.dumps({"status": "ok", "data": item})
                    )
                elif method == "PUT":
                    item = self.db.update_banner_regex_rule(json.loads(body or "{}"))
                    response = self.build_response(
                        200, json.dumps({"status": "ok", "data": item})
                    )
                elif method == "DELETE":
                    self.db.delete_banner_regex_rule(json.loads(body or "{}"))
                    response = self.build_response(200, json.dumps({"status": "ok"}))
                elif method == "OPTIONS":
                    response = self.build_response(
                        200,
                        "",
                        headers={
                            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                            "Access-Control-Allow-Headers": "Content-Type, Authorization",
                        },
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/api/catalog/banner-requests/":
                if method == "GET":
                    response = self.build_response(
                        200,
                        json.dumps(
                            {
                                "datas": self.db.select_banner_probe_requests(
                                    include_inactive=True
                                )
                            }
                        ),
                    )
                elif method == "POST":
                    item = self.db.insert_banner_probe_request(json.loads(body or "{}"))
                    response = self.build_response(
                        200, json.dumps({"status": "ok", "data": item})
                    )
                elif method == "PUT":
                    item = self.db.update_banner_probe_request(json.loads(body or "{}"))
                    response = self.build_response(
                        200, json.dumps({"status": "ok", "data": item})
                    )
                elif method == "DELETE":
                    self.db.delete_banner_probe_request(json.loads(body or "{}"))
                    response = self.build_response(200, json.dumps({"status": "ok"}))
                elif method == "OPTIONS":
                    response = self.build_response(
                        200,
                        "",
                        headers={
                            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                            "Access-Control-Allow-Headers": "Content-Type, Authorization",
                        },
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/api/catalog/ip-presets/":
                if method == "GET":
                    response = self.build_response(
                        200,
                        json.dumps({"datas": self.db.select_ip_presets(include_inactive=True)}),
                    )
                elif method == "POST":
                    item = self.db.insert_ip_preset(json.loads(body or "{}"))
                    response = self.build_response(
                        200, json.dumps({"status": "ok", "data": item})
                    )
                elif method == "PUT":
                    item = self.db.update_ip_preset(json.loads(body or "{}"))
                    response = self.build_response(
                        200, json.dumps({"status": "ok", "data": item})
                    )
                elif method == "DELETE":
                    self.db.delete_ip_preset(json.loads(body or "{}"))
                    response = self.build_response(200, json.dumps({"status": "ok"}))
                elif method == "OPTIONS":
                    response = self.build_response(
                        200,
                        "",
                        headers={
                            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                            "Access-Control-Allow-Headers": "Content-Type, Authorization",
                        },
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            elif path == "/banners/":
                if method == "GET":
                    response = self.build_response(
                        200, json.dumps({"datas": self.db.select_banners()})
                    )
                elif method == "DELETE":
                    self.db.delete_banners()
                    response = self.build_response(200, json.dumps({"status": "200"}))
                elif method == "OPTIONS":
                    response = self.build_response(
                        200,
                        "",
                        headers={
                            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                            "Access-Control-Allow-Headers": "Content-Type, Authorization",
                        },
                    )
                else:
                    response = self.build_response(405, json.dumps({"status": "405"}))
            else:
                response = self.build_response(404, json.dumps({"status": "404"}))
        except Exception as e:
            response = self.build_response(500, json.dumps({"status": str(e)}))
        finally:
            return response


class TCP(threading.Thread):
    def __init__(self, db: DB):
        threading.Thread.__init__(self)
        self.db = db
        self.stop_event = threading.Event()
        self.threads = {}

    def stop(self):
        self.stop_event.set()
        for identifier, (thread, stop_evt) in self.threads.items():
            stop_evt.set()
            thread.join(timeout=2)
        self.threads.clear()

    def run(self):
        while not self.stop_event.is_set():
            try:
                current_targets = self.db.select_targets_where_tcp()
                finished_ids = [
                    identifier
                    for identifier, (thread, _stop_evt) in list(self.threads.items())
                    if not thread.is_alive()
                ]
                for finished_id in finished_ids:
                    _thread, stop_evt = self.threads.pop(finished_id)
                    stop_evt.set()
                    print(f"DONE: {finished_id}")
                current_ids = {target["id"] for target in current_targets}
                # stop thread
                obsolete_ids = set(self.threads.keys()) - current_ids
                for obsolete_id in obsolete_ids:
                    print(f"STOP: {obsolete_id}")
                    thread, stop_evt = self.threads.pop(obsolete_id)
                    stop_evt.set()
                    thread.join(timeout=2)
                # start thread
                for target in current_targets:
                    identifier = target["id"]
                    status = str(target.get("status", "active")).strip().lower()
                    try:
                        progress = float(target.get("progress", 0.0) or 0.0)
                    except Exception:
                        progress = 0.0
                    if status == "active" and progress >= 100.0:
                        continue
                    if status == "restarting" and identifier in self.threads:
                        print(f"RESTART-STOP: {identifier}")
                        thread, stop_evt = self.threads.pop(identifier)
                        stop_evt.set()
                        thread.join(timeout=2)
                    if identifier not in self.threads:
                        stop_evt = threading.Event()
                        thread = threading.Thread(
                            target=self.scan,
                            daemon=True,
                            kwargs={
                                "identifier": identifier,
                                "network": target["network"],
                                "type_scan": target["type"],
                                "port_mode": target.get("port_mode", "preset"),
                                "port_start": target.get("port_start"),
                                "port_end": target.get("port_end"),
                                "timesleep": target["timesleep"],
                                "progress": target["progress"],
                                "stop_event": stop_evt,
                            },
                        )
                        self.threads[identifier] = (thread, stop_evt)
                        thread.start()
                        print(f"START: {identifier}")
                        if status == "restarting":
                            self.db.set_target_status(
                                data={"id": identifier, "status": "active"}
                            )
                            print(f"RESTART-START: {identifier}")
                    self.stop_event.wait(1)
            except Exception as e:
                print(f"TCP() -> run(): {e}")
            finally:
                self.stop_event.wait(5)

    def scan(
        self,
        identifier: int,
        network: str,
        type_scan: str,
        port_mode: str,
        port_start,
        port_end,
        timesleep: float,
        progress: float,
        stop_event: threading.Event,
    ):
        network_obj: ipaddress.IPv4Network = ipaddress.IPv4Network(
            network, strict=False
        )
        ips = [ip.exploded for ip in network_obj.hosts()]
        len_ips = len(ips)
        ports = resolve_target_ports(
            type_scan=type_scan,
            port_mode=port_mode,
            port_start=port_start,
            port_end=port_end,
        )
        len_ports = len(ports)
        if len_ips == 0 or len_ports == 0:
            self.db.targets_progress(
                data={
                    "id": identifier,
                    "progress": 100.0,
                    "proto": "tcp",
                }
            )
            return
        total_combinations = len_ips * len_ports
        start_index = int((progress / 100.0) * total_combinations)
        current_combination = 0
        host_offset = identifier % len_ips
        for i_port, port in enumerate(ports):
            try:
                if stop_event.is_set():
                    raise BreakLoop
                for hop in range(len_ips):
                    ip = ips[(host_offset + i_port + hop) % len_ips]
                    if current_combination < start_index:
                        current_combination += 1
                        continue
                    if progress >= 100.0:
                        raise BreakLoop
                    try:
                        self.stop_event.wait(timesleep)
                        if stop_event.is_set():
                            raise BreakLoop
                        result = self.tcp(ip, port)
                        if result["state"] == "OPEN":
                            self.db.insert_port(
                                data={
                                    "ip": ip,
                                    "port": port,
                                    "proto": "tcp",
                                    "state": "open",
                                },
                            )
                            self.db.insert_tags(
                                data={
                                    "ip": ip,
                                    "port": port,
                                    "proto": "tcp",
                                    "key": "time_ms",
                                    "value": result["tiempo_ms"],
                                },
                            )
                        elif result["state"] == "FILTERED":
                            self.db.insert_port(
                                data={
                                    "ip": ip,
                                    "port": port,
                                    "proto": "tcp",
                                    "state": "filtered",
                                },
                            )
                    except BreakLoop:
                        print("FIN", network)
                        raise
                    except Exception as e:
                        print("TCP() -> scan()", e)

                    finally:
                        current_combination += 1
                        progress = (current_combination / total_combinations) * 100
                        self.db.targets_progress(
                            data={
                                "id": identifier,
                                "progress": progress,
                                "proto": "tcp",
                            }
                        )
            except BreakLoop:
                break

    def tcp(self, host, port, timeout=2):
        resultado = {
            "protocolo": "TCP",
            "host": host,
            "port": port,
            "state": "UNKNOWN",
            "tiempo_ms": None,
        }
        try:
            inicio = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            bind_source_ip(sock)
            sock.settimeout(timeout)

            conexion = sock.connect_ex((host, port))
            fin = time.time()

            resultado["tiempo_ms"] = round((fin - inicio) * 1000, 2)

            if conexion == 0:
                resultado["state"] = "OPEN"
            else:
                resultado["state"] = "CLOSED"
        except socket.timeout:
            resultado["state"] = "FILTERED"
        except Exception as e:
            resultado["state"] = "ERROR"
        finally:
            try:
                sock.close()
            except:
                pass

        return resultado


class UDP(threading.Thread):
    def __init__(self, db: DB):
        threading.Thread.__init__(self)
        self.db = db
        self.stop_event = threading.Event()
        self.threads = {}

    def stop(self):
        self.stop_event.set()
        for identifier, (thread, stop_evt) in self.threads.items():
            stop_evt.set()
            thread.join(timeout=2)
        self.threads.clear()

    def run(self):
        while not self.stop_event.is_set():
            try:
                current_targets = self.db.select_targets_where_udp()
                finished_ids = [
                    identifier
                    for identifier, (thread, _stop_evt) in list(self.threads.items())
                    if not thread.is_alive()
                ]
                for finished_id in finished_ids:
                    _thread, stop_evt = self.threads.pop(finished_id)
                    stop_evt.set()
                    print(f"DONE: {finished_id}")
                current_ids = {target["id"] for target in current_targets}
                obsolete_ids = set(self.threads.keys()) - current_ids
                for obsolete_id in obsolete_ids:
                    print(f"STOP: {obsolete_id}")
                    thread, stop_evt = self.threads.pop(obsolete_id)
                    stop_evt.set()
                    thread.join(timeout=2)
                for target in current_targets:
                    identifier = target["id"]
                    status = str(target.get("status", "active")).strip().lower()
                    try:
                        progress = float(target.get("progress", 0.0) or 0.0)
                    except Exception:
                        progress = 0.0
                    if status == "active" and progress >= 100.0:
                        continue
                    if status == "restarting" and identifier in self.threads:
                        print(f"RESTART-STOP: {identifier}")
                        thread, stop_evt = self.threads.pop(identifier)
                        stop_evt.set()
                        thread.join(timeout=2)
                    if identifier not in self.threads:
                        stop_evt = threading.Event()
                        thread = threading.Thread(
                            target=self.scan,
                            daemon=True,
                            kwargs={
                                "identifier": identifier,
                                "network": target["network"],
                                "type_scan": target["type"],
                                "port_mode": target.get("port_mode", "preset"),
                                "port_start": target.get("port_start"),
                                "port_end": target.get("port_end"),
                                "timesleep": target["timesleep"],
                                "progress": target["progress"],
                                "stop_event": stop_evt,
                            },
                        )
                        self.threads[identifier] = (thread, stop_evt)
                        thread.start()
                        print(f"START: {identifier}")
                        if status == "restarting":
                            self.db.set_target_status(
                                data={"id": identifier, "status": "active"}
                            )
                            print(f"RESTART-START: {identifier}")
                    self.stop_event.wait(1)
            except Exception as e:
                print("UDP() -> run()", e)
            finally:
                self.stop_event.wait(5)

    def scan(
        self,
        identifier: int,
        network: str,
        type_scan: str,
        port_mode: str,
        port_start,
        port_end,
        timesleep: float,
        progress: float,
        stop_event: threading.Event,
    ):
        network_obj = ipaddress.IPv4Network(network, strict=False)
        ips = [ip.exploded for ip in network_obj.hosts()]
        len_ips = len(ips)
        ports = resolve_target_ports(
            type_scan=type_scan,
            port_mode=port_mode,
            port_start=port_start,
            port_end=port_end,
        )
        len_ports = len(ports)
        if len_ips == 0 or len_ports == 0:
            self.db.targets_progress(
                data={
                    "id": identifier,
                    "progress": 100.0,
                    "proto": "udp",
                }
            )
            return
        total_combinations = len_ips * len_ports
        start_index = int((progress / 100.0) * total_combinations)
        current_combination = 0
        host_offset = identifier % len_ips
        for i_port, port in enumerate(ports):
            try:
                if stop_event.is_set():
                    raise BreakLoop
                for hop in range(len_ips):
                    ip = ips[(host_offset + i_port + hop) % len_ips]
                    if current_combination < start_index:
                        current_combination += 1
                        continue
                    if progress >= 100.0:
                        raise BreakLoop
                    try:
                        self.stop_event.wait(timesleep)
                        if stop_event.is_set():
                            raise BreakLoop
                        result = self.udp(ip, port)
                        if result["state"] == "OPEN":
                            self.db.insert_port(
                                data={
                                    "ip": ip,
                                    "port": port,
                                    "proto": "udp",
                                    "state": "open",
                                },
                            )
                            self.db.insert_tags(
                                data={
                                    "ip": ip,
                                    "port": port,
                                    "proto": "udp",
                                    "key": "time_ms",
                                    "value": result["tiempo_ms"],
                                },
                            )
                        elif result["state"] == "FILTERED":
                            self.db.insert_port(
                                data={
                                    "ip": ip,
                                    "port": port,
                                    "proto": "udp",
                                    "state": "filtered",
                                },
                            )
                    except BreakLoop:
                        print("FIN", network)
                        raise
                    except Exception as e:
                        print("UDP() -> scan()", e)
                    finally:
                        current_combination += 1
                        progress = (current_combination / total_combinations) * 100
                        self.db.targets_progress(
                            data={
                                "id": identifier,
                                "progress": progress,
                                "proto": "udp",
                            }
                        )
            except BreakLoop:
                break

    def udp(self, host, port, timeout=2):
        resultado = {
            "protocolo": "UDP",
            "host": host,
            "port": port,
            "state": "UNKNOWN",
            "tiempo_ms": None,
        }
        sock = None
        try:
            inicio = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            bind_source_ip(sock)
            sock.settimeout(timeout)
            sock.sendto(b"", (host, port))
            try:
                sock.recvfrom(1024)
                fin = time.time()
                resultado["state"] = "OPEN"
            except socket.timeout:
                fin = time.time()
                resultado["state"] = "FILTERED"
            except Exception as e:
                fin = time.time()
                resultado["state"] = "ERROR"
                print("UDP() -> udp()", e)

            resultado["tiempo_ms"] = round((fin - inicio) * 1000, 2)

        except Exception as e:
            resultado["state"] = "ERROR"
            print("UDP() -> udp()", e)
        finally:
            try:
                if sock:
                    sock.close()
            except Exception:
                pass

        return resultado


class SCTP(threading.Thread):
    def __init__(self, db: DB):
        threading.Thread.__init__(self)
        self.db = db
        self.stop_event = threading.Event()
        self.threads = {}
        self.enabled = supports_sctp()
        self.proto_number = getattr(socket, "IPPROTO_SCTP", None)
        self.socket_types = [("stream", socket.SOCK_STREAM)]
        sock_seqpacket = getattr(socket, "SOCK_SEQPACKET", None)
        if sock_seqpacket is not None:
            self.socket_types.append(("seqpacket", sock_seqpacket))

    def stop(self):
        self.stop_event.set()
        for identifier, (thread, stop_evt) in self.threads.items():
            stop_evt.set()
            thread.join(timeout=2)
        self.threads.clear()

    def run(self):
        if not self.enabled:
            print(
                "SCTP() -> native sockets unavailable, using fallback host discovery mode"
            )
        while not self.stop_event.is_set():
            try:
                current_targets = self.db.select_targets_where_sctp()
                finished_ids = [
                    identifier
                    for identifier, (thread, _stop_evt) in list(self.threads.items())
                    if not thread.is_alive()
                ]
                for finished_id in finished_ids:
                    _thread, stop_evt = self.threads.pop(finished_id)
                    stop_evt.set()
                    print(f"DONE: {finished_id}")
                current_ids = {target["id"] for target in current_targets}
                obsolete_ids = set(self.threads.keys()) - current_ids
                for obsolete_id in obsolete_ids:
                    print(f"STOP: {obsolete_id}")
                    thread, stop_evt = self.threads.pop(obsolete_id)
                    stop_evt.set()
                    thread.join(timeout=2)
                for target in current_targets:
                    identifier = target["id"]
                    status = str(target.get("status", "active")).strip().lower()
                    try:
                        progress = float(target.get("progress", 0.0) or 0.0)
                    except Exception:
                        progress = 0.0
                    if status == "active" and progress >= 100.0:
                        continue
                    if status == "restarting" and identifier in self.threads:
                        print(f"RESTART-STOP: {identifier}")
                        thread, stop_evt = self.threads.pop(identifier)
                        stop_evt.set()
                        thread.join(timeout=2)
                    if identifier not in self.threads:
                        stop_evt = threading.Event()
                        thread = threading.Thread(
                            target=self.scan,
                            daemon=True,
                            kwargs={
                                "identifier": identifier,
                                "network": target["network"],
                                "type_scan": target["type"],
                                "port_mode": target.get("port_mode", "preset"),
                                "port_start": target.get("port_start"),
                                "port_end": target.get("port_end"),
                                "timesleep": target["timesleep"],
                                "progress": target["progress"],
                                "stop_event": stop_evt,
                            },
                        )
                        self.threads[identifier] = (thread, stop_evt)
                        thread.start()
                        print(f"START: {identifier}")
                        if status == "restarting":
                            self.db.set_target_status(
                                data={"id": identifier, "status": "active"}
                            )
                            print(f"RESTART-START: {identifier}")
                    self.stop_event.wait(1)
            except Exception as e:
                print("SCTP() -> run()", e)
            finally:
                self.stop_event.wait(5)

    def _record_host_discovery(self, ip: str, state: str, evidence: dict | None = None):
        state_value = "open" if str(state).upper() == "OPEN" else "filtered"
        self.db.insert_port(
            data={
                "ip": ip,
                "port": 0,
                "proto": "sctp",
                "state": state_value,
            }
        )
        if not evidence:
            return
        if evidence.get("tiempo_ms") is not None:
            self.db.insert_tags(
                data={
                    "ip": ip,
                    "port": 0,
                    "proto": "sctp",
                    "key": "host_discovery_time_ms",
                    "value": evidence.get("tiempo_ms"),
                }
            )
        if evidence.get("method"):
            self.db.insert_tags(
                data={
                    "ip": ip,
                    "port": 0,
                    "proto": "sctp",
                    "key": "host_discovery_method",
                    "value": evidence.get("method"),
                }
            )
        if evidence.get("probe_port") is not None:
            self.db.insert_tags(
                data={
                    "ip": ip,
                    "port": 0,
                    "proto": "sctp",
                    "key": "host_discovery_probe_port",
                    "value": evidence.get("probe_port"),
                }
            )

    def _fallback_host_probe(self, host: str, timeout=1.0) -> dict:
        probe = tcp_reachability_probe(host=host, timeout=timeout)
        probe["method"] = "sctp_fallback_tcp_connect"
        return probe

    def _scan_hosts_without_sctp(
        self,
        identifier: int,
        ips: list,
        progress: float,
        stop_event: threading.Event,
    ):
        total_hosts = len(ips)
        if total_hosts == 0:
            self.db.targets_progress(
                data={
                    "id": identifier,
                    "progress": 100.0,
                    "proto": "sctp",
                }
            )
            return

        start_index = int((progress / 100.0) * total_hosts)
        current_index = 0
        for ip in ips:
            try:
                if current_index < start_index:
                    current_index += 1
                    continue
                if progress >= 100.0 or stop_event.is_set():
                    raise BreakLoop
                probe = self._fallback_host_probe(ip, timeout=0.9)
                if probe["state"] == "OPEN":
                    self._record_host_discovery(ip=ip, state="OPEN", evidence=probe)
                elif probe["state"] == "FILTERED":
                    self._record_host_discovery(ip=ip, state="FILTERED", evidence=probe)
            except BreakLoop:
                break
            except Exception as e:
                print("SCTP() -> _scan_hosts_without_sctp()", e)
            finally:
                current_index += 1
                progress = (current_index / total_hosts) * 100
                self.db.targets_progress(
                    data={
                        "id": identifier,
                        "progress": progress,
                        "proto": "sctp",
                    }
                )

    def scan(
        self,
        identifier: int,
        network: str,
        type_scan: str,
        port_mode: str,
        port_start,
        port_end,
        timesleep: float,
        progress: float,
        stop_event: threading.Event,
    ):
        network_obj = ipaddress.IPv4Network(network, strict=False)
        ips = [ip.exploded for ip in network_obj.hosts()]
        if not self.enabled:
            self._scan_hosts_without_sctp(
                identifier=identifier,
                ips=ips,
                progress=progress,
                stop_event=stop_event,
            )
            return
        ports = resolve_target_ports(
            type_scan=type_scan,
            port_mode=port_mode,
            port_start=port_start,
            port_end=port_end,
        )
        len_ips = len(ips)
        len_ports = len(ports)
        if len_ips == 0 or len_ports == 0:
            self.db.targets_progress(
                data={
                    "id": identifier,
                    "progress": 100.0,
                    "proto": "sctp",
                }
            )
            return
        total_combinations = len_ips * len_ports
        start_index = int((progress / 100.0) * total_combinations)
        current_combination = 0
        host_offset = identifier % len_ips
        host_open_evidence = {}
        host_filtered_evidence = {}
        for i_port, port in enumerate(ports):
            try:
                if stop_event.is_set():
                    raise BreakLoop
                for hop in range(len_ips):
                    ip = ips[(host_offset + i_port + hop) % len_ips]
                    if current_combination < start_index:
                        current_combination += 1
                        continue
                    if progress >= 100.0:
                        raise BreakLoop
                    try:
                        self.stop_event.wait(timesleep)
                        if stop_event.is_set():
                            raise BreakLoop
                        result = self.sctp(ip, port)
                        if result["state"] == "OPEN":
                            self.db.insert_port(
                                data={
                                    "ip": ip,
                                    "port": port,
                                    "proto": "sctp",
                                    "state": "open",
                                },
                            )
                            self.db.insert_tags(
                                data={
                                    "ip": ip,
                                    "port": port,
                                    "proto": "sctp",
                                    "key": "time_ms",
                                    "value": result["tiempo_ms"],
                                },
                            )
                            self.db.insert_tags(
                                data={
                                    "ip": ip,
                                    "port": port,
                                    "proto": "sctp",
                                    "key": "socket_type",
                                    "value": result["socket_type"],
                                },
                            )
                            if ip not in host_open_evidence:
                                host_open_evidence[ip] = {
                                    "tiempo_ms": result.get("tiempo_ms"),
                                    "method": f"sctp_native_{result.get('socket_type', 'unknown')}",
                                    "probe_port": port,
                                }
                        elif result["state"] == "CLOSED":
                            if ip not in host_open_evidence:
                                host_open_evidence[ip] = {
                                    "tiempo_ms": result.get("tiempo_ms"),
                                    "method": f"sctp_native_{result.get('socket_type', 'unknown')}",
                                    "probe_port": port,
                                }
                        elif result["state"] == "FILTERED":
                            self.db.insert_port(
                                data={
                                    "ip": ip,
                                    "port": port,
                                    "proto": "sctp",
                                    "state": "filtered",
                                },
                            )
                            if ip not in host_open_evidence and ip not in host_filtered_evidence:
                                host_filtered_evidence[ip] = {
                                    "tiempo_ms": result.get("tiempo_ms"),
                                    "method": "sctp_native_filtered",
                                    "probe_port": port,
                                }
                    except BreakLoop:
                        print("FIN", network)
                        raise
                    except Exception as e:
                        print("SCTP() -> scan()", e)
                    finally:
                        current_combination += 1
                        progress = (current_combination / total_combinations) * 100
                        self.db.targets_progress(
                            data={
                                "id": identifier,
                                "progress": progress,
                                "proto": "sctp",
                            }
                        )
            except BreakLoop:
                break
        for ip in ips:
            if ip in host_open_evidence:
                self._record_host_discovery(
                    ip=ip,
                    state="OPEN",
                    evidence=host_open_evidence[ip],
                )
            elif ip in host_filtered_evidence:
                self._record_host_discovery(
                    ip=ip,
                    state="FILTERED",
                    evidence=host_filtered_evidence[ip],
                )

    def _build_socket(self):
        for label, sock_type in self.socket_types:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, sock_type, self.proto_number)
                bind_source_ip(sock)
                return label, sock
            except Exception:
                try:
                    if sock:
                        sock.close()
                except Exception:
                    pass
                continue
        raise OSError("SCTP socket unavailable")

    def sctp(self, host, port, timeout=2):
        result = {
            "protocolo": "SCTP",
            "host": host,
            "port": port,
            "state": "UNKNOWN",
            "tiempo_ms": None,
            "socket_type": "unknown",
        }
        sock = None
        try:
            socket_type, sock = self._build_socket()
            result["socket_type"] = socket_type
            sock.settimeout(timeout)
            start = time.time()
            connection = sock.connect_ex((host, port))
            end = time.time()
            result["tiempo_ms"] = round((end - start) * 1000, 2)
            if connection == 0:
                result["state"] = "OPEN"
            else:
                result["state"] = "CLOSED"
        except socket.timeout:
            result["state"] = "FILTERED"
        except Exception:
            result["state"] = "ERROR"
        finally:
            try:
                if sock:
                    sock.close()
            except Exception:
                pass

        return result


class ICMP(threading.Thread):
    def __init__(self, db: DB):
        threading.Thread.__init__(self)
        self.db = db
        self.stop_event = threading.Event()
        self.threads = {}

    def stop(self):
        self.stop_event.set()
        for identifier, (thread, stop_evt) in self.threads.items():
            stop_evt.set()
            thread.join(timeout=2)
        self.threads.clear()

    def run(self):
        while not self.stop_event.is_set():
            try:
                current_targets = self.db.select_targets_where_icmp()
                finished_ids = [
                    identifier
                    for identifier, (thread, _stop_evt) in list(self.threads.items())
                    if not thread.is_alive()
                ]
                for finished_id in finished_ids:
                    _thread, stop_evt = self.threads.pop(finished_id)
                    stop_evt.set()
                    print(f"DONE: {finished_id}")
                current_ids = {target["id"] for target in current_targets}
                obsolete_ids = set(self.threads.keys()) - current_ids
                for obsolete_id in obsolete_ids:
                    print(f"STOP: {obsolete_id}")
                    thread, stop_evt = self.threads.pop(obsolete_id)
                    stop_evt.set()
                    thread.join(timeout=2)
                for target in current_targets:
                    identifier = target["id"]
                    status = str(target.get("status", "active")).strip().lower()
                    try:
                        progress = float(target.get("progress", 0.0) or 0.0)
                    except Exception:
                        progress = 0.0
                    if status == "active" and progress >= 100.0:
                        continue
                    if status == "restarting" and identifier in self.threads:
                        print(f"RESTART-STOP: {identifier}")
                        thread, stop_evt = self.threads.pop(identifier)
                        stop_evt.set()
                        thread.join(timeout=2)
                    if identifier not in self.threads:
                        stop_evt = threading.Event()
                        thread = threading.Thread(
                            target=self.scan,
                            daemon=True,
                            kwargs={
                                "identifier": identifier,
                                "network": target["network"],
                                "timesleep": target["timesleep"],
                                "progress": target["progress"],
                                "stop_event": stop_evt,
                            },
                        )
                        self.threads[identifier] = (thread, stop_evt)
                        thread.start()
                        print(f"START: {identifier}")
                        if status == "restarting":
                            self.db.set_target_status(
                                data={"id": identifier, "status": "active"}
                            )
                            print(f"RESTART-START: {identifier}")
                    self.stop_event.wait(1)
            except Exception as e:
                print("ICMP() -> run()", e)
            finally:
                self.stop_event.wait(5)

    def scan(
        self,
        identifier: int,
        network: str,
        timesleep: float,
        progress: float,
        stop_event: threading.Event,
    ):
        network_obj = ipaddress.IPv4Network(network, strict=False)
        ips = [ip.exploded for ip in network_obj.hosts()]
        total_hosts = len(ips)
        if total_hosts == 0:
            self.db.targets_progress(
                data={
                    "id": identifier,
                    "progress": 100.0,
                    "proto": "icmp",
                }
            )
            return

        start_index = int((progress / 100.0) * total_hosts)
        current_index = 0
        for ip in ips:
            try:
                if current_index < start_index:
                    current_index += 1
                    continue
                if progress >= 100.0 or stop_event.is_set():
                    raise BreakLoop
                try:
                    self.stop_event.wait(timesleep)
                    if stop_event.is_set():
                        raise BreakLoop
                    result = self.icmp(ip)
                    if result["state"] == "OPEN":
                        self.db.insert_port(
                            data={
                                "ip": ip,
                                "port": 0,
                                "proto": "icmp",
                                "state": "open",
                            },
                        )
                        self.db.insert_tags(
                            data={
                                "ip": ip,
                                "port": 0,
                                "proto": "icmp",
                                "key": "time_ms",
                                "value": result["tiempo_ms"],
                            },
                        )
                        self.db.insert_tags(
                            data={
                                "ip": ip,
                                "port": 0,
                                "proto": "icmp",
                                "key": "probe_method",
                                "value": result["method"],
                            },
                        )
                        reply_ttl = result.get("reply_ttl")
                        if isinstance(reply_ttl, int) and 0 < reply_ttl <= 255:
                            self.db.insert_tags(
                                data={
                                    "ip": ip,
                                    "port": 0,
                                    "proto": "icmp",
                                    "key": "reply_ttl",
                                    "value": str(reply_ttl),
                                },
                            )
                    elif result["state"] == "FILTERED":
                        self.db.insert_port(
                            data={
                                "ip": ip,
                                "port": 0,
                                "proto": "icmp",
                                "state": "filtered",
                            },
                        )
                except BreakLoop:
                    print("FIN", network)
                    break
                except Exception as e:
                    print("ICMP() -> scan()", e)
                finally:
                    current_index += 1
                    progress = (current_index / total_hosts) * 100
                    self.db.targets_progress(
                        data={
                            "id": identifier,
                            "progress": progress,
                            "proto": "icmp",
                        }
                    )
            except BreakLoop:
                break

    def icmp(self, host, timeout=1.5):
        try:
            return self._icmp_raw(host=host, timeout=timeout)
        except (PermissionError, OSError):
            # Raw ICMP usually requires elevated privileges.
            ping_probe = self._icmp_subprocess_ping(host=host, timeout=timeout)
            if ping_probe:
                return ping_probe
            tcp_probe = tcp_reachability_probe(host=host, timeout=min(1.0, timeout))
            return {
                "protocolo": "ICMP",
                "host": host,
                "port": 0,
                "state": tcp_probe.get("state", "FILTERED"),
                "tiempo_ms": tcp_probe.get("tiempo_ms"),
                "method": tcp_probe.get("method", "tcp_connect_fallback"),
            }
        except Exception:
            ping_probe = self._icmp_subprocess_ping(host=host, timeout=timeout)
            if ping_probe:
                return ping_probe
            return {
                "protocolo": "ICMP",
                "host": host,
                "port": 0,
                "state": "FILTERED",
                "tiempo_ms": None,
                "method": "fallback_unavailable",
            }

    def _icmp_subprocess_ping(self, host, timeout=1.5):
        timeout = max(0.4, float(timeout))
        if sys.platform.startswith("win"):
            commands = [
                [
                    "ping",
                    "-n",
                    "1",
                    "-w",
                    str(max(250, int(timeout * 1000))),
                    host,
                ]
            ]
        else:
            commands = [
                [
                    "ping",
                    "-n",
                    "-c",
                    "1",
                    "-W",
                    str(max(1, int(round(timeout)))),
                    host,
                ],
                ["ping", "-n", "-c", "1", host],
            ]

        for command in commands:
            start = time.time()
            try:
                completed = subprocess.run(
                    command,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=max(timeout + 0.6, 1.2),
                    check=False,
                )
                end = time.time()
                if completed.returncode == 0:
                    state = "OPEN"
                elif completed.returncode == 1:
                    state = "FILTERED"
                else:
                    continue
                return {
                    "protocolo": "ICMP",
                    "host": host,
                    "port": 0,
                    "state": state,
                    "tiempo_ms": round((end - start) * 1000, 2),
                    "method": "ping_subprocess",
                }
            except FileNotFoundError:
                continue
            except subprocess.TimeoutExpired:
                end = time.time()
                return {
                    "protocolo": "ICMP",
                    "host": host,
                    "port": 0,
                    "state": "FILTERED",
                    "tiempo_ms": round((end - start) * 1000, 2),
                    "method": "ping_subprocess",
                }
            except Exception:
                continue
        return None

    def _icmp_raw(self, host, timeout=1.5):
        result = {
            "protocolo": "ICMP",
            "host": host,
            "port": 0,
            "state": "UNKNOWN",
            "tiempo_ms": None,
            "method": "raw",
            "reply_ttl": None,
        }

        sock = None
        try:
            ident = threading.get_ident() & 0xFFFF
            seq = int(time.time() * 1000) & 0xFFFF
            payload = b"PortHoundICMP-" + str(int(time.time() * 1000)).encode(
                "ascii",
                errors="ignore",
            )
            header = bytes(
                [
                    8,
                    0,
                    0,
                    0,
                    (ident >> 8) & 0xFF,
                    ident & 0xFF,
                    (seq >> 8) & 0xFF,
                    seq & 0xFF,
                ]
            )
            checksum = icmp_checksum(header + payload)
            packet = bytes(
                [
                    8,
                    0,
                    (checksum >> 8) & 0xFF,
                    checksum & 0xFF,
                    (ident >> 8) & 0xFF,
                    ident & 0xFF,
                    (seq >> 8) & 0xFF,
                    seq & 0xFF,
                ]
            ) + payload

            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            bind_source_ip(sock)
            sock.settimeout(timeout)
            start = time.time()
            sock.sendto(packet, (host, 0))
            deadline = start + timeout

            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise socket.timeout()
                sock.settimeout(remaining)
                recv_data, addr = sock.recvfrom(1024)
                if addr[0] != host or len(recv_data) < 28:
                    continue
                ip_header_len = (recv_data[0] & 0x0F) * 4
                if len(recv_data) < ip_header_len + 8:
                    continue
                if len(recv_data) >= 9:
                    try:
                        result["reply_ttl"] = int(recv_data[8])
                    except Exception:
                        result["reply_ttl"] = None
                icmp_hdr = recv_data[ip_header_len : ip_header_len + 8]
                icmp_type = icmp_hdr[0]
                recv_ident = (icmp_hdr[4] << 8) | icmp_hdr[5]
                recv_seq = (icmp_hdr[6] << 8) | icmp_hdr[7]
                if icmp_type == 0 and recv_ident == ident and recv_seq == seq:
                    end = time.time()
                    result["state"] = "OPEN"
                    result["tiempo_ms"] = round((end - start) * 1000, 2)
                    return result
                if icmp_type == 3:
                    end = time.time()
                    result["state"] = "FILTERED"
                    result["tiempo_ms"] = round((end - start) * 1000, 2)
                    return result
        except socket.timeout:
            result["state"] = "FILTERED"
            result["tiempo_ms"] = round(timeout * 1000, 2)
        finally:
            try:
                if sock:
                    sock.close()
            except:
                pass
        return result


class BannerUDP(threading.Thread):
    BANNERS = BANNER_UDP_PROBES
    READ_TIMEOUT = 2.5
    MAX_UNIQUE_BANNERS_PER_PORT = 3
    MAX_EMPTY_PROBES = 12
    MAX_PROBES_PER_PORT = 120
    MAX_DUPLICATE_RESPONSES = 8
    MAX_TARGET_WORKERS = 32

    def __init__(self, db: DB):
        threading.Thread.__init__(self)
        self.db = db
        self.stop_event = threading.Event()
        payload_sets = {}
        if self.db is not None and hasattr(self.db, "load_probe_payloads"):
            try:
                payload_sets = self.db.load_probe_payloads("udp") or {}
            except Exception:
                payload_sets = {}
        self.port_probe_overrides = payload_sets.get("overrides") or {
            int(port): [bytes(p) for p in payloads]
            for port, payloads in UDP_PORT_PROBE_OVERRIDES.items()
        }
        self.generic_requests = dedupe_probe_payloads(
            payload_sets.get("generic") or self.BANNERS
        )
        coverage_probes = []
        for probe_group in self.port_probe_overrides.values():
            coverage_probes.extend(probe_group)
        self.banner_requests = dedupe_probe_payloads(
            coverage_probes + self.generic_requests
        )

    def _build_probe_sequence(self, port: int):
        probes = []
        probes.extend(self.port_probe_overrides.get(port, []))
        probes.extend(self.banner_requests)
        probes = dedupe_probe_payloads(probes)
        if self.MAX_PROBES_PER_PORT > 0:
            probes = probes[: self.MAX_PROBES_PER_PORT]
        return probes

    def _save_banner_if_new(self, ip: str, port: int, banner: bytes, seen: set):
        if not banner or banner in seen:
            return False
        seen.add(banner)
        review = review_banner_payload(banner)
        self.db.insert_banners(
            data={
                "ip": ip,
                "port": port,
                "proto": "udp",
                "response": review["payload"],
                "response_plain": review["text"],
            },
        )
        for row in build_banner_rule_tags(
            ip=ip,
            port=port,
            proto="udp",
            findings=review["findings"],
            banner_text=review["text"],
        ):
            self.db.insert_tags(data=row)
        return True

    def run(self):
        with ThreadPoolExecutor(
            max_workers=self.MAX_TARGET_WORKERS,
            thread_name_prefix="banner-udp",
        ) as pool:
            while not self.stop_event.is_set():
                try:
                    targets = self.db.select_ports_where_udp_for_scan()
                    futures = [
                        pool.submit(
                            self.scan,
                            target["id"],
                            target["ip"],
                            target["port"],
                            target["progress"],
                        )
                        for target in targets
                    ]
                    for future in futures:
                        try:
                            future.result()
                        except Exception as worker_error:
                            print("BannerUDP() -> worker()", worker_error)
                except Exception as e:
                    print("BannerUDP() -> run()", e)
                finally:
                    self.stop_event.wait(5)

    def scan(self, identifier: int, ip: str, port: int, progress: float):
        probes = self._build_probe_sequence(port)
        len_banners = len(probes)
        if len_banners == 0:
            self.db.ports_progress(data={"id": identifier, "progress": 100.0})
            return

        has_saved_banner = self.db.banner_exists(ip=ip, port=port, proto="udp")
        if progress >= 100.0 and not has_saved_banner:
            progress = 0.0
            self.db.ports_progress(data={"id": identifier, "progress": 0.0})

        start_index = min(len_banners, int((progress / 100.0) * len_banners))
        if start_index >= len_banners:
            self.db.ports_progress(data={"id": identifier, "progress": 100.0})
            return

        unique_responses = set()
        empty_probes = 0
        duplicate_hits = 0
        for i, banner in enumerate(
            probes[start_index:], start=start_index + 1
        ):
            if (
                progress >= 100.0
                or self.stop_event.is_set()
                or not self.db.is_port_scan_runnable(identifier)
            ):
                break
            try:
                result = self.get_banner(ip, port, banner)
                if result["state"] == "OK" and result["banner"]:
                    empty_probes = 0
                    inserted = self._save_banner_if_new(
                        ip=ip,
                        port=port,
                        banner=result["banner"],
                        seen=unique_responses,
                    )
                    if inserted:
                        duplicate_hits = 0
                    else:
                        duplicate_hits += 1
                        if duplicate_hits >= self.MAX_DUPLICATE_RESPONSES:
                            break
                    if len(unique_responses) >= self.MAX_UNIQUE_BANNERS_PER_PORT:
                        break
                else:
                    empty_probes += 1
                    if unique_responses and empty_probes >= self.MAX_EMPTY_PROBES:
                        break
            except Exception as e:
                print("BannerUDP() -> scan()", e)
            finally:
                progress = (i / len_banners) * 100
                self.db.ports_progress(
                    data={
                        "id": identifier,
                        "progress": progress,
                    }
                )
                self.stop_event.wait(0.2)

    def get_banner(self, ip, port, request_bytes, timeout=None):
        resultado = {
            "banner": b"",
            "state": "UNKNOWN",
            "tiempo_ms": None,
        }
        timeout = self.READ_TIMEOUT if timeout is None else timeout
        sock = None

        try:
            inicio = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            bind_source_ip(sock)
            sock.settimeout(timeout)
            sock.sendto(request_bytes or b"\x00", (ip, port))
            banner, _ = sock.recvfrom(1024)
            fin = time.time()
            resultado["banner"] = banner
            resultado["tiempo_ms"] = round((fin - inicio) * 1000, 2)
            resultado["state"] = "OK" if banner else "NOOK"
        except socket.timeout:
            resultado["state"] = "NOOK"
        except Exception:
            resultado["state"] = "NOOK"
        finally:
            try:
                if sock:
                    sock.close()
            except:
                pass

        return resultado


class BannerTCP(threading.Thread):
    BANNERS = BANNER_TCP_PROBES
    CONNECT_TIMEOUT = 2.0
    READ_TIMEOUT = 2.5
    FAVICON_TIMEOUT = 2.5
    FAVICON_MAX_BYTES = 512 * 1024
    FAVICON_REDIRECT_LIMIT = 2
    ENABLE_HTTP_FAVICON_CAPTURE = True
    MAX_UNIQUE_BANNERS_PER_PORT = 4
    MAX_EMPTY_PROBES = 10
    MAX_PROBES_PER_PORT = 140
    MAX_DUPLICATE_RESPONSES = 10
    MAX_TARGET_WORKERS = 32
    FAVICON_LINK_TAG_RE = re.compile(r"<link\b[^>]*>", re.IGNORECASE)
    FAVICON_ATTR_RE = re.compile(r"([a-zA-Z_:][a-zA-Z0-9_:.-]*)\s*=\s*([\"'])(.*?)\2")

    def __init__(self, db: DB):
        threading.Thread.__init__(self)
        self.db = db
        self.stop_event = threading.Event()
        payload_sets = {}
        if self.db is not None and hasattr(self.db, "load_probe_payloads"):
            try:
                payload_sets = self.db.load_probe_payloads("tcp") or {}
            except Exception:
                payload_sets = {}
        self.port_probe_overrides = payload_sets.get("overrides") or {
            int(port): [bytes(p) for p in payloads]
            for port, payloads in TCP_PORT_PROBE_OVERRIDES.items()
        }
        self.http_requests = dedupe_probe_payloads(
            payload_sets.get("http") or TCP_HTTP_PROBES
        )
        self.generic_requests = dedupe_probe_payloads(
            payload_sets.get("generic") or self.BANNERS
        )
        coverage_probes = []
        for probe_group in self.port_probe_overrides.values():
            coverage_probes.extend(probe_group)
        self.banner_requests = dedupe_probe_payloads(
            self.http_requests + coverage_probes + self.generic_requests
        )

    def _build_probe_sequence(self, port: int):
        probes = []
        probes.extend(self.port_probe_overrides.get(port, []))
        if port in TCP_HTTP_PORTS:
            probes.extend(self.http_requests)
        probes.extend(self.banner_requests)
        probes = dedupe_probe_payloads(probes)
        if self.MAX_PROBES_PER_PORT > 0:
            probes = probes[: self.MAX_PROBES_PER_PORT]
        return probes

    def _is_http_banner(self, port: int, review: dict) -> bool:
        text = str((review or {}).get("text", "") or "")
        if re.search(r"(?im)^HTTP/[0-9.]+", text):
            return True
        if re.search(r"(?im)^Server:\s*", text):
            return True
        for finding in (review or {}).get("findings", []) or []:
            service = str(finding.get("service", "")).strip().lower()
            protocol = str(finding.get("protocol", "")).strip().upper()
            if service == "http" or protocol in {"HTTP", "HTTPS"}:
                return True
        return int(port) in TCP_HTTP_PORTS

    def _normalize_icon_path(self, value: str) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        lowered = raw.lower()
        if lowered.startswith(("data:", "javascript:", "mailto:")):
            return ""
        if lowered.startswith("//"):
            return ""
        if lowered.startswith("http://") or lowered.startswith("https://"):
            parsed = urlsplit(raw)
            if parsed.scheme.lower() != "http":
                return ""
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"
            return path
        if not raw.startswith("/"):
            return "/" + raw.lstrip("./")
        return raw

    def _decode_chunked_body(self, body: bytes) -> bytes:
        if not body:
            return b""
        index = 0
        chunks = []
        total = len(body)
        while index < total:
            line_end = body.find(b"\r\n", index)
            if line_end < 0:
                return body
            size_hex = body[index:line_end].split(b";", 1)[0].strip()
            try:
                size = int(size_hex, 16)
            except Exception:
                return body
            index = line_end + 2
            if size == 0:
                return b"".join(chunks)
            if index + size > total:
                return body
            chunks.append(body[index : index + size])
            index += size
            if body[index : index + 2] == b"\r\n":
                index += 2
        return b"".join(chunks)

    def _parse_http_response(self, raw: bytes):
        if not raw or b"\r\n\r\n" not in raw:
            return None
        header_blob, body = raw.split(b"\r\n\r\n", 1)
        lines = header_blob.decode("iso-8859-1", errors="ignore").split("\r\n")
        if not lines:
            return None
        parts = lines[0].split(" ", 2)
        if len(parts) < 2:
            return None
        try:
            status_code = int(parts[1])
        except Exception:
            return None

        headers = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            if key and key not in headers:
                headers[key] = value

        transfer = headers.get("transfer-encoding", "").lower()
        if "chunked" in transfer:
            body = self._decode_chunked_body(body)
        else:
            try:
                content_length = int(headers.get("content-length", "").strip())
            except Exception:
                content_length = None
            if content_length is not None and content_length >= 0:
                body = body[:content_length]

        return {
            "status": status_code,
            "headers": headers,
            "body": body,
        }

    def _http_get_resource(self, ip: str, port: int, path: str):
        normalized_path = self._normalize_icon_path(path)
        if not normalized_path:
            return None

        host_header = ip if int(port) in {80, 443} else f"{ip}:{port}"
        redirect_budget = self.FAVICON_REDIRECT_LIMIT
        current_path = normalized_path

        while redirect_budget >= 0 and current_path:
            sock = None
            raw = b""
            try:
                request = (
                    f"GET {current_path} HTTP/1.1\r\n"
                    f"Host: {host_header}\r\n"
                    "User-Agent: PortHound/1.0\r\n"
                    "Accept: image/*,*/*;q=0.8\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii", errors="ignore")

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                bind_source_ip(sock)
                sock.settimeout(self.FAVICON_TIMEOUT)
                sock.connect((ip, int(port)))
                sock.sendall(request)

                while len(raw) < self.FAVICON_MAX_BYTES:
                    chunk = sock.recv(min(4096, self.FAVICON_MAX_BYTES - len(raw)))
                    if not chunk:
                        break
                    raw += chunk
            except Exception:
                return None
            finally:
                try:
                    if sock:
                        sock.close()
                except Exception:
                    pass

            response = self._parse_http_response(raw)
            if not response:
                return None
            response["path"] = current_path

            if response["status"] in {301, 302, 303, 307, 308}:
                redirect_budget -= 1
                location = response["headers"].get("location", "")
                next_path = self._normalize_icon_path(location)
                if not next_path or next_path == current_path:
                    return response
                current_path = next_path
                continue
            return response

        return None

    def _extract_icon_paths_from_html(self, body: bytes):
        paths = []
        text = body.decode("utf-8", errors="ignore")
        for match in self.FAVICON_LINK_TAG_RE.finditer(text):
            tag = match.group(0)
            attrs = {}
            for attr_match in self.FAVICON_ATTR_RE.finditer(tag):
                attrs[attr_match.group(1).lower()] = attr_match.group(3).strip()
            rel_value = attrs.get("rel", "").lower()
            href_value = attrs.get("href", "")
            if "icon" not in rel_value:
                continue
            icon_path = self._normalize_icon_path(href_value)
            if icon_path:
                paths.append(icon_path)
        return paths

    def _guess_icon_mime(self, path: str, header_mime: str, body: bytes) -> str:
        mime = str(header_mime or "").split(";", 1)[0].strip().lower()
        if mime and mime not in {"application/octet-stream", "binary/octet-stream"}:
            return mime

        blob = body or b""
        if blob.startswith(b"\x00\x00\x01\x00"):
            return "image/x-icon"
        if blob.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if blob.startswith((b"GIF87a", b"GIF89a")):
            return "image/gif"
        if blob.startswith(b"\xff\xd8\xff"):
            return "image/jpeg"
        if blob.startswith(b"RIFF") and b"WEBP" in blob[:16]:
            return "image/webp"
        if blob.lstrip().startswith(b"<svg") or b"<svg" in blob[:512].lower():
            return "image/svg+xml"

        lower_path = str(path or "").lower().split("?", 1)[0]
        if lower_path.endswith(".ico"):
            return "image/x-icon"
        if lower_path.endswith(".png"):
            return "image/png"
        if lower_path.endswith(".gif"):
            return "image/gif"
        if lower_path.endswith(".jpg") or lower_path.endswith(".jpeg"):
            return "image/jpeg"
        if lower_path.endswith(".svg"):
            return "image/svg+xml"
        if lower_path.endswith(".webp"):
            return "image/webp"
        return "application/octet-stream"

    def _is_likely_icon(self, path: str, mime: str, body: bytes) -> bool:
        if not body:
            return False
        if str(mime).lower().startswith("image/"):
            return True
        lower_path = str(path or "").lower().split("?", 1)[0]
        if lower_path.endswith(
            (".ico", ".png", ".gif", ".jpg", ".jpeg", ".svg", ".webp")
        ):
            return True
        if body.startswith((b"\x00\x00\x01\x00", b"\x89PNG", b"GIF87a", b"GIF89a")):
            return True
        if body.startswith(b"\xff\xd8\xff"):
            return True
        if b"<svg" in body[:512].lower():
            return True
        return False

    def _capture_http_favicon(self, ip: str, port: int):
        if self.db.favicon_exists(ip=ip, port=port, proto="tcp"):
            return False

        candidate_paths = ["/favicon.ico"]
        root_response = self._http_get_resource(ip=ip, port=port, path="/")
        if root_response and 200 <= root_response.get("status", 0) < 400:
            content_type = str(root_response.get("headers", {}).get("content-type", ""))
            if "text/html" in content_type.lower() and root_response.get("body"):
                candidate_paths.extend(
                    self._extract_icon_paths_from_html(root_response["body"])
                )

        visited = set()
        for path in candidate_paths:
            normalized_path = self._normalize_icon_path(path)
            if not normalized_path or normalized_path in visited:
                continue
            visited.add(normalized_path)
            response = self._http_get_resource(ip=ip, port=port, path=normalized_path)
            if not response or int(response.get("status", 0)) != 200:
                continue
            body = bytes(response.get("body", b"") or b"")
            if not body:
                continue
            mime = self._guess_icon_mime(
                path=normalized_path,
                header_mime=response.get("headers", {}).get("content-type", ""),
                body=body,
            )
            if not self._is_likely_icon(normalized_path, mime, body):
                continue

            sha256 = hashlib.sha256(body).hexdigest()
            self.db.insert_favicon(
                data={
                    "ip": ip,
                    "port": int(port),
                    "proto": "tcp",
                    "icon_url": normalized_path,
                    "mime_type": mime,
                    "icon_blob": body,
                    "size": len(body),
                    "sha256": sha256,
                }
            )
            self.db.insert_tags(
                data={
                    "ip": ip,
                    "port": int(port),
                    "proto": "tcp",
                    "key": "favicon.available",
                    "value": "true",
                }
            )
            self.db.insert_tags(
                data={
                    "ip": ip,
                    "port": int(port),
                    "proto": "tcp",
                    "key": "favicon.url",
                    "value": normalized_path,
                }
            )
            self.db.insert_tags(
                data={
                    "ip": ip,
                    "port": int(port),
                    "proto": "tcp",
                    "key": "favicon.mime",
                    "value": mime,
                }
            )
            self.db.insert_tags(
                data={
                    "ip": ip,
                    "port": int(port),
                    "proto": "tcp",
                    "key": "favicon.size",
                    "value": str(len(body)),
                }
            )
            self.db.insert_tags(
                data={
                    "ip": ip,
                    "port": int(port),
                    "proto": "tcp",
                    "key": "favicon.sha256",
                    "value": sha256,
                }
            )
            return True
        return False

    def _save_banner_if_new(self, ip: str, port: int, banner: bytes, seen: set):
        if not banner or banner in seen:
            return False
        seen.add(banner)
        review = review_banner_payload(banner)
        self.db.insert_banners(
            data={
                "ip": ip,
                "port": port,
                "proto": "tcp",
                "response": review["payload"],
                "response_plain": review["text"],
            },
        )
        for row in build_banner_rule_tags(
            ip=ip,
            port=port,
            proto="tcp",
            findings=review["findings"],
            banner_text=review["text"],
        ):
            self.db.insert_tags(data=row)
        if self.ENABLE_HTTP_FAVICON_CAPTURE and self._is_http_banner(
            port=port, review=review
        ):
            try:
                self._capture_http_favicon(ip=ip, port=port)
            except Exception as e:
                print("BannerTCP() -> favicon_capture()", e)
        return True

    def run(self):
        with ThreadPoolExecutor(
            max_workers=self.MAX_TARGET_WORKERS,
            thread_name_prefix="banner-tcp",
        ) as pool:
            while not self.stop_event.is_set():
                try:
                    targets = self.db.select_ports_where_tcp_for_scan()
                    futures = [
                        pool.submit(
                            self.scan,
                            target["id"],
                            target["ip"],
                            target["port"],
                            target["progress"],
                        )
                        for target in targets
                    ]
                    for future in futures:
                        try:
                            future.result()
                        except Exception as worker_error:
                            print("BannerTCP() -> worker()", worker_error)
                except Exception as e:
                    print("BannerTCP() -> run()", e)
                finally:
                    self.stop_event.wait(5)

    def scan(self, identifier: int, ip: str, port: int, progress: float):
        probes = self._build_probe_sequence(port)
        len_banners = len(probes)
        if len_banners == 0:
            self.db.ports_progress(data={"id": identifier, "progress": 100.0})
            return

        has_saved_banner = self.db.banner_exists(ip=ip, port=port, proto="tcp")
        if progress >= 100.0 and not has_saved_banner:
            progress = 0.0
            self.db.ports_progress(data={"id": identifier, "progress": 0.0})

        start_index = min(len_banners, int((progress / 100.0) * len_banners))
        if start_index >= len_banners:
            self.db.ports_progress(data={"id": identifier, "progress": 100.0})
            return

        unique_responses = set()
        empty_probes = 0
        duplicate_hits = 0

        # Passive read first for services that send greeting banners immediately.
        passive_result = self.get_banner(
            ip=ip,
            port=port,
            request_bytes=b"",
            send_payload=False,
            connect_timeout=self.CONNECT_TIMEOUT,
            read_timeout=min(self.READ_TIMEOUT, 0.8),
        )
        if passive_result["state"] == "OK":
            self._save_banner_if_new(
                ip=ip,
                port=port,
                banner=passive_result["banner"],
                seen=unique_responses,
            )

        for i, banner in enumerate(
            probes[start_index:], start=start_index + 1
        ):
            if (
                progress >= 100.0
                or self.stop_event.is_set()
                or not self.db.is_port_scan_runnable(identifier)
            ):
                break
            try:
                result = self.get_banner(ip, port, banner)
                if result["state"] == "OK" and result["banner"]:
                    empty_probes = 0
                    inserted = self._save_banner_if_new(
                        ip=ip,
                        port=port,
                        banner=result["banner"],
                        seen=unique_responses,
                    )
                    if inserted:
                        duplicate_hits = 0
                    else:
                        duplicate_hits += 1
                        if duplicate_hits >= self.MAX_DUPLICATE_RESPONSES:
                            break
                    if len(unique_responses) >= self.MAX_UNIQUE_BANNERS_PER_PORT:
                        break
                else:
                    empty_probes += 1
                    if unique_responses and empty_probes >= self.MAX_EMPTY_PROBES:
                        break
            except Exception as e:
                print("BannerTCP() -> scan()", e)
            finally:
                progress = (i / len_banners) * 100
                self.db.ports_progress(
                    data={
                        "id": identifier,
                        "progress": progress,
                    }
                )
                self.stop_event.wait(0.2)

    def get_banner(
        self,
        ip,
        port,
        request_bytes,
        connect_timeout=None,
        read_timeout=None,
        send_payload=True,
    ):
        resultado = {
            "banner": b"",
            "state": "UNKNOWN",
            "tiempo_ms": None,
        }
        connect_timeout = (
            self.CONNECT_TIMEOUT if connect_timeout is None else connect_timeout
        )
        read_timeout = self.READ_TIMEOUT if read_timeout is None else read_timeout
        sock = None

        try:
            inicio = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            bind_source_ip(sock)
            sock.settimeout(connect_timeout)
            sock.connect((ip, port))
            sock.settimeout(read_timeout)
            if send_payload:
                sock.sendall(request_bytes or b"\r\n")
            banner = sock.recv(1024)
            fin = time.time()
            resultado["banner"] = banner
            resultado["tiempo_ms"] = round((fin - inicio) * 1000, 2)
            resultado["state"] = "OK" if banner else "NOOK"
        except socket.timeout:
            resultado["state"] = "NOOK"
        except Exception:
            resultado["state"] = "NOOK"
        finally:
            try:
                if sock:
                    sock.close()
            except:
                pass
        return resultado


class HTTP(threading.Thread):
    def __init__(self, lock=None):
        threading.Thread.__init__(self)
        self.db_lock = lock if lock else threading.Lock()
        self.conn = sqlite3.connect(
            "file::memory:?cache=shared", check_same_thread=False, timeout=10.0
        )
        self.stop_event = threading.Event()

    def client_send_http_request(
        self,
        path: str,
        method: str,
        headers: dict,
        body: str = "",
        http_version: str = "HTTP/1.1",
        port: int = None,
    ) -> str:
        host = headers.get("Host")
        if not host:
            raise ValueError("El encabezado 'Host' es obligatorio")

        if port is None:
            port = 443 if headers.get("Host", "").startswith("https") else 80

        request_line = f"{method} {path} {http_version}\r\n"
        header_lines = "\r\n".join([f"{k}: {v}" for k, v in headers.items()])
        http_request = f"{request_line}{header_lines}\r\n\r\n{body}"

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            bind_source_ip(s)
            s.connect((host, port))
            s.sendall(http_request.encode("utf-8"))
            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk

        return response.decode("utf-8")

    def client_parse_http_response(self, response: str) -> dict:
        lines = response.split("\r\n")
        status_line_parts = lines[0].split(" ", 2)
        http_version = status_line_parts[0]
        status_code = status_line_parts[1]
        status_message = status_line_parts[2] if len(status_line_parts) > 2 else ""

        headers = {}
        body = ""
        index = 1

        while index < len(lines) and lines[index]:
            if ": " in lines[index]:
                key, value = lines[index].split(": ", 1)
                headers[key] = value
            index += 1

        body = "\r\n".join(lines[index + 1 :])

        return {
            "http_version": http_version,
            "status_code": status_code,
            "status_message": status_message,
            "headers": headers,
            "body": body,
        }

    def run(self):
        while not self.stop_event.is_set():
            try:
                threads = []
                targets = self.db_get_targets()
                for target in targets:
                    threads.append(
                        threading.Thread(
                            target=self.scan,
                            daemon=True,
                            kwargs={
                                "network": target["network"],
                                "type_scan": target["type"],
                                "timesleep": target["timesleep"],
                            },
                        )
                    )
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()

            except Exception as e:
                print("HTTP() -> run()", e)
            finally:
                self.stop_event.wait(5)

    def scan(self, network: str, type_scan: str, timesleep: float):
        response = self.client_send_http_request(
            path="/targets/",
            method="GET",
            headers={
                "Host": "127.0.0.1",
                "User-Agent": "PortHoundMicroService",
                "Accept": "*/*",
                "Connection": "close",
            },
            body="",
            http_version="HTTP/1.1",
            port=45678,
        )
        parsed_response = self.client_parse_http_response(response)
        print(parsed_response)

    def db_insert(self, table, data):
        try:
            self.db_lock.acquire()
            cursor = self.conn.cursor()
            if table == "port_open":
                cursor.execute(
                    "INSERT OR IGNORE INTO port_open (ip, port, proto) VALUES (?, ?, ?);",
                    (data["ip"], data["port"], data["proto"]),
                )
            elif table == "port_filtered":
                cursor.execute(
                    "INSERT OR IGNORE INTO port_filtered (ip, port, proto) VALUES (?, ?, ?);",
                    (data["ip"], data["port"], data["proto"]),
                )
            elif table == "tags":
                cursor.execute(
                    "INSERT OR IGNORE INTO tags (ip, port, proto, key, value) VALUES (?, ?, ?, ?, ?);",
                    (
                        data["ip"],
                        data["port"],
                        data["proto"],
                        data["key"],
                        data["value"],
                    ),
                )
            self.conn.commit()
        except Exception as e:
            print("HTTP() -> db_insert()", e)
        finally:
            self.db_lock.release()
            cursor.close()

    def db_get_targets(self):
        output = []
        try:
            self.db_lock.acquire()
            cursor = self.conn.cursor()
            cursor.execute(f"SELECT * FROM targets WHERE proto='tcp';")
            column_names = [col[0] for col in cursor.description]
            output = [dict(zip(column_names, row)) for row in cursor.fetchall()]
            cursor.close()
        except Exception as e:
            print("HTTP() -> db_get_targets()", e)
        finally:
            self.db_lock.release()
            return output


if __name__ == "__main__":
    db = DB()
    API(host="127.0.0.1", port=45678, db=db).start()
    TCP(db=db).start()
    UDP(db=db).start()
    if "sctp" in TARGET_PROTOS:
        SCTP(db=db).start()
    ICMP(db=db).start()
    BannerTCP(db=db).start()
    BannerUDP(db=db).start()
