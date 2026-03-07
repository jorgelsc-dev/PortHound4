import json
import mimetypes
import random
import sqlite3
import re
import errno
import base64
import socket
import ssl
import statistics
import tempfile
import threading
import time
import uuid
from collections import Counter, deque
from ipaddress import IPv4Address, ip_address, ip_network
from pathlib import Path
from urllib.parse import urlsplit

import settings
from framework import App, Response, Route, parse_close_payload

from server import (
    DB,
    TCP,
    UDP,
    SCTP,
    ICMP,
    BannerTCP,
    BannerUDP,
    TARGET_TYPES,
    TARGET_PROTOS,
    TARGET_STATUSES,
    TARGET_PORT_MODES,
    PORT_SCAN_STATUSES,
    normalize_target_port_config,
)
from ws_demo import INDEX_HTML, Database, ChatMessage, parse_chat_line, ClientRegistry


REGEX_IPV4_CIDR = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
PROJECT_ROOT = Path(__file__).resolve().parent
FRONTEND_DIST_DIR = PROJECT_ROOT / "frontend" / "dist"
SPA_ROUTES = (
    "/map",
    "/charts",
    "/explorer",
    "/agents",
    "/targets",
    "/ports",
    "/banners",
    "/tags",
    "/catalog",
    "/api",
)
STATIC_CONTENT_TYPE_OVERRIDES = {
    ".js": "application/javascript; charset=utf-8",
    ".mjs": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".map": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
}
_frontend_dist_routes_registered = False

app = App()
scan_db = DB(path=settings.SCAN_DB_PATH)
ws_db = Database(
    path=":memory:",
    shared_cache=True,
    timeout=10.0,
    pragmas={
        "journal_mode": "WAL",
        "synchronous": "NORMAL",
        "foreign_keys": 1,
    },
)
ChatMessage.create_table(ws_db)
registry = ClientRegistry()


EXAMPLE_TARGETS = [
    {
        "id": 1,
        "network": "10.0.0.0/24",
        "type": "common",
        "proto": "tcp",
        "port_mode": "preset",
        "port_start": 0,
        "port_end": 0,
        "status": "active",
        "timesleep": 0.5,
        "progress": 62.5,
        "created_at": "2025-04-24 00:00:00",
        "updated_at": "2025-04-24 00:00:00",
    },
    {
        "id": 2,
        "network": "10.0.1.0/24",
        "type": "not_common",
        "proto": "udp",
        "port_mode": "range",
        "port_start": 500,
        "port_end": 2000,
        "status": "stopped",
        "timesleep": 1.0,
        "progress": 14.0,
        "created_at": "2025-04-24 00:00:00",
        "updated_at": "2025-04-24 00:00:00",
    },
]

EXAMPLE_PORTS = [
    {
        "id": 10,
        "ip": "10.0.0.10",
        "port": 22,
        "proto": "tcp",
        "state": "open",
        "scan_state": "active",
        "progress": 100.0,
        "created_at": "2025-04-24 00:00:00",
        "updated_at": "2025-04-24 00:00:00",
    },
    {
        "id": 11,
        "ip": "10.0.0.15",
        "port": 80,
        "proto": "tcp",
        "state": "open",
        "scan_state": "active",
        "progress": 100.0,
        "created_at": "2025-04-24 00:00:00",
        "updated_at": "2025-04-24 00:00:00",
    },
    {
        "id": 12,
        "ip": "10.0.1.12",
        "port": 53,
        "proto": "udp",
        "state": "filtered",
        "scan_state": "stopped",
        "progress": 100.0,
        "created_at": "2025-04-24 00:00:00",
        "updated_at": "2025-04-24 00:00:00",
    },
    {
        "id": 13,
        "ip": "10.0.0.1",
        "port": 0,
        "proto": "icmp",
        "state": "open",
        "scan_state": "active",
        "progress": 100.0,
        "created_at": "2025-04-24 00:00:00",
        "updated_at": "2025-04-24 00:00:00",
    },
]

EXAMPLE_TAGS = [
    {
        "id": 100,
        "ip": "10.0.0.10",
        "port": 22,
        "proto": "tcp",
        "key": "time_ms",
        "value": "12.5",
        "created_at": "2025-04-24 00:00:00",
        "updated_at": "2025-04-24 00:00:00",
    },
    {
        "id": 101,
        "ip": "10.0.0.15",
        "port": 80,
        "proto": "tcp",
        "key": "time_ms",
        "value": "22.1",
        "created_at": "2025-04-24 00:00:00",
        "updated_at": "2025-04-24 00:00:00",
    },
    {
        "id": 102,
        "ip": "10.0.0.1",
        "port": 0,
        "proto": "icmp",
        "key": "time_ms",
        "value": "4.6",
        "created_at": "2025-04-24 00:00:00",
        "updated_at": "2025-04-24 00:00:00",
    },
]

if "sctp" in TARGET_PROTOS:
    EXAMPLE_TARGETS.append(
        {
            "id": 3,
            "network": "10.0.2.0/24",
            "type": "common",
            "proto": "sctp",
            "port_mode": "single",
            "port_start": 3868,
            "port_end": 3868,
            "status": "active",
            "timesleep": 0.8,
            "progress": 9.0,
            "created_at": "2025-04-24 00:00:00",
            "updated_at": "2025-04-24 00:00:00",
        }
    )
    EXAMPLE_PORTS.append(
        {
            "id": 14,
            "ip": "10.0.2.20",
            "port": 3868,
            "proto": "sctp",
            "state": "open",
            "scan_state": "active",
            "progress": 100.0,
            "created_at": "2025-04-24 00:00:00",
            "updated_at": "2025-04-24 00:00:00",
        }
    )
    EXAMPLE_TAGS.append(
        {
            "id": 103,
            "ip": "10.0.2.20",
            "port": 3868,
            "proto": "sctp",
            "key": "time_ms",
            "value": "15.3",
            "created_at": "2025-04-24 00:00:00",
            "updated_at": "2025-04-24 00:00:00",
        }
    )

EXAMPLE_BANNERS = [
    {
        "id": 200,
        "ip": "10.0.0.10",
        "port": 22,
        "proto": "tcp",
        "response_plain": "SSH-2.0-OpenSSH_8.2",
        "created_at": "2025-04-24 00:00:00",
        "updated_at": "2025-04-24 00:00:00",
    },
    {
        "id": 201,
        "ip": "10.0.0.15",
        "port": 80,
        "proto": "tcp",
        "response_plain": "HTTP/1.1 200 OK",
        "created_at": "2025-04-24 00:00:00",
        "updated_at": "2025-04-24 00:00:00",
    },
]

EXAMPLE_FAVICON_BYTES = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x17\x7f\xb3\x00\x00\x00!"
    b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00"
    b"\x00\x02\x02D\x01\x00;"
)

EXAMPLE_FAVICONS = [
    {
        "id": 300,
        "ip": "10.0.0.15",
        "port": 80,
        "proto": "tcp",
        "icon_url": "/favicon.ico",
        "mime_type": "image/gif",
        "size": len(EXAMPLE_FAVICON_BYTES),
        "sha256": "example-favicon",
        "created_at": "2025-04-24 00:00:00",
        "updated_at": "2025-04-24 00:00:00",
    },
]

EXAMPLE_WS_CLIENTS = [
    {
        "id": "demo-1",
        "addr": "10.0.0.10:54123",
        "subprotocol": "chat",
        "created": 0,
    }
]

EXAMPLE_CHAT_MESSAGES = [
    {
        "id": 1,
        "client_id": "demo-1",
        "alias": "analyst",
        "message": "scan started",
        "created_at": 0,
    },
    {
        "id": 2,
        "client_id": "demo-1",
        "alias": "analyst",
        "message": "ssh open on 10.0.0.10",
        "created_at": 0,
    },
]

ATTACK_SOURCE_NODES = [
    {
        "ip": "185.220.101.45",
        "city": "Berlin",
        "country": "DE",
        "lat": 52.52,
        "lon": 13.405,
        "asn": "AS9009",
        "actor": "botnet-edge-01",
    },
    {
        "ip": "91.214.124.18",
        "city": "Moscow",
        "country": "RU",
        "lat": 55.7558,
        "lon": 37.6176,
        "asn": "AS49505",
        "actor": "credential-spray-node",
    },
    {
        "ip": "103.145.13.76",
        "city": "Singapore",
        "country": "SG",
        "lat": 1.3521,
        "lon": 103.8198,
        "asn": "AS58563",
        "actor": "scanner-proxy",
    },
    {
        "ip": "45.95.147.212",
        "city": "Amsterdam",
        "country": "NL",
        "lat": 52.3676,
        "lon": 4.9041,
        "asn": "AS60781",
        "actor": "bulletproof-host",
    },
    {
        "ip": "179.43.188.53",
        "city": "Sao Paulo",
        "country": "BR",
        "lat": -23.5505,
        "lon": -46.6333,
        "asn": "AS51852",
        "actor": "mass-scan-worker",
    },
    {
        "ip": "196.251.84.102",
        "city": "Johannesburg",
        "country": "ZA",
        "lat": -26.2041,
        "lon": 28.0473,
        "asn": "AS328543",
        "actor": "exploit-prober",
    },
]

ATTACK_TARGET_NODES = [
    {
        "ip": "34.117.59.81",
        "city": "Ashburn",
        "country": "US",
        "lat": 39.0438,
        "lon": -77.4874,
        "asn": "AS15169",
        "asset": "api-gateway-prod",
    },
    {
        "ip": "104.18.23.42",
        "city": "San Francisco",
        "country": "US",
        "lat": 37.7749,
        "lon": -122.4194,
        "asn": "AS13335",
        "asset": "edge-waf-01",
    },
    {
        "ip": "18.195.122.73",
        "city": "Frankfurt",
        "country": "DE",
        "lat": 50.1109,
        "lon": 8.6821,
        "asn": "AS16509",
        "asset": "auth-cluster-eu",
    },
    {
        "ip": "13.229.114.87",
        "city": "Singapore",
        "country": "SG",
        "lat": 1.3521,
        "lon": 103.8198,
        "asn": "AS16509",
        "asset": "cdn-ingress-apac",
    },
    {
        "ip": "52.172.47.11",
        "city": "Sao Paulo",
        "country": "BR",
        "lat": -23.5505,
        "lon": -46.6333,
        "asn": "AS8075",
        "asset": "payments-latam",
    },
    {
        "ip": "20.25.144.69",
        "city": "Sydney",
        "country": "AU",
        "lat": -33.8688,
        "lon": 151.2093,
        "asn": "AS8075",
        "asset": "customer-api-au",
    },
]

ATTACK_SIGNATURES = [
    {
        "attack_type": "credential-stuffing",
        "protocol": "tcp",
        "port": 443,
        "service": "https",
        "severity": "high",
        "default_action": "blocked",
    },
    {
        "attack_type": "ssh-bruteforce",
        "protocol": "tcp",
        "port": 22,
        "service": "ssh",
        "severity": "high",
        "default_action": "rate_limited",
    },
    {
        "attack_type": "rdp-bruteforce",
        "protocol": "tcp",
        "port": 3389,
        "service": "rdp",
        "severity": "critical",
        "default_action": "blocked",
    },
    {
        "attack_type": "dns-amplification-probe",
        "protocol": "udp",
        "port": 53,
        "service": "dns",
        "severity": "medium",
        "default_action": "observed",
    },
    {
        "attack_type": "smb-enum",
        "protocol": "tcp",
        "port": 445,
        "service": "smb",
        "severity": "medium",
        "default_action": "blocked",
    },
    {
        "attack_type": "api-path-fuzzing",
        "protocol": "tcp",
        "port": 443,
        "service": "https",
        "severity": "medium",
        "default_action": "challenged",
    },
]


def clamp_int(value, default, minimum, maximum):
    try:
        number = int(value)
    except Exception:
        number = default
    if number < minimum:
        return minimum
    if number > maximum:
        return maximum
    return number


def utc_iso(ts_value):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts_value))


def detect_scan_origin_ip():
    source_override = str(getattr(settings, "PORTHOUND_IP", "") or "").strip()
    if source_override:
        return source_override
    configured_host = str(getattr(settings, "HOST", "") or "").strip()
    if configured_host and configured_host not in {"0.0.0.0", "::"}:
        return configured_host
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        detected = sock.getsockname()[0]
        if detected:
            return str(detected)
    except Exception:
        pass
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass
    return "127.0.0.1"


def classify_ipv4_scope(ip_value):
    try:
        addr = ip_address(str(ip_value))
    except Exception:
        return "invalid"
    if not isinstance(addr, IPv4Address):
        return "invalid"
    if addr.is_global:
        return "public"
    return "private"


REGEX_IPV4_EXACT = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
REGEX_DOMAIN_CANDIDATE = re.compile(r"^(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+\.?$", re.I)
REGEX_DOMAIN_IN_TEXT = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.I,
)
REGEX_URL_WITH_HOST = re.compile(r"^[a-z][a-z0-9+\-.]*://([^/\s?#]+)", re.I)
REGEX_SINGLE_LABEL_HOST = re.compile(r"^[a-z][a-z0-9-]{0,62}$", re.I)
HTTP_DOMAIN_PORT_HINTS = (80, 8080, 8000, 8888, 3000, 5000, 7001, 8081, 8088, 8880, 8090, 8443)
SOCKET_TTL_PROBE_BASE_PORT = 33434
TTL_BASE_HINTS = (32, 60, 64, 128, 255)
TCP_TTL_PORT_HINTS = (443, 80, 53, 22, 8080)
TLS_PORT_HINTS = (443, 465, 563, 636, 853, 989, 990, 992, 993, 995, 8443, 9443, 10443)
DNS_RESOLVER_HINTS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")
DNS_QTYPE_A = 1
DNS_QTYPE_CNAME = 5
DNS_QTYPE_PTR = 12
NON_DNS_SUFFIXES = {
    "ico",
    "icon",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "webp",
    "css",
    "js",
    "woff",
    "woff2",
    "ttf",
    "eot",
    "map",
    "txt",
    "json",
    "xml",
    "pdf",
    "zip",
    "bin",
    "exe",
}
IP_INTEL_CACHE_TTL_SECONDS = 600
IP_INTEL_CACHE = {}
IP_INTEL_CACHE_LOCK = threading.Lock()
HOST_INTEL_HTTP_TIMEOUT_SECONDS = 1.4
HOST_INTEL_TLS_TIMEOUT_SECONDS = 1.8
HOST_INTEL_MAX_HTTP_PORTS = 6
HOST_INTEL_MAX_TLS_PORTS = 5


def normalize_ipv4_input(ip_value):
    raw = str(ip_value or "").strip()
    if not REGEX_IPV4_EXACT.match(raw):
        raise ValueError("Invalid IPv4 address")
    try:
        parsed = ip_address(raw)
    except Exception:
        raise ValueError("Invalid IPv4 address")
    if not isinstance(parsed, IPv4Address):
        raise ValueError("Only IPv4 addresses are supported")
    return str(parsed)


def normalize_domain_candidate(value):
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if raw.endswith("."):
        raw = raw[:-1]
    if raw.startswith("*."):
        raw = raw[2:]
    if not raw or "." not in raw:
        return ""
    if REGEX_IPV4_EXACT.match(raw):
        return ""
    if not REGEX_DOMAIN_CANDIDATE.match(raw):
        return ""
    labels = [part for part in raw.split(".") if part]
    if any(len(label) > 63 for label in labels):
        return ""
    if len(raw) > 253:
        return ""
    tld = labels[-1]
    if not re.match(r"^[a-z]{2,63}$", tld):
        return ""
    if tld in NON_DNS_SUFFIXES:
        return ""
    if not any(ch.isalpha() for ch in raw):
        return ""
    return raw


def normalize_nslookup_host(value):
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if raw.endswith("."):
        raw = raw[:-1]
    domain_name = normalize_domain_candidate(raw)
    if domain_name:
        return domain_name
    if REGEX_SINGLE_LABEL_HOST.match(raw):
        return raw
    return ""


def encode_dns_name(name_value):
    labels = [part for part in str(name_value or "").strip(".").split(".") if part]
    output = bytearray()
    for label in labels:
        try:
            label_bytes = label.encode("idna")
        except Exception:
            return b""
        if not label_bytes or len(label_bytes) > 63:
            return b""
        output.append(len(label_bytes))
        output.extend(label_bytes)
    output.append(0)
    return bytes(output)


def dns_build_query(name_value, qtype):
    encoded_name = encode_dns_name(name_value)
    if not encoded_name:
        raise ValueError("invalid dns name")
    txid = random.randint(0, 65535)
    flags = 0x0100  # recursion desired
    header = (
        int(txid).to_bytes(2, "big")
        + int(flags).to_bytes(2, "big")
        + (1).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
    )
    question = encoded_name + int(qtype).to_bytes(2, "big") + (1).to_bytes(2, "big")
    return txid, header + question


def dns_skip_name(packet_bytes, offset):
    steps = 0
    current = int(offset)
    while True:
        if current >= len(packet_bytes):
            raise ValueError("dns name overflow")
        length = int(packet_bytes[current])
        if length == 0:
            return current + 1
        if (length & 0xC0) == 0xC0:
            if current + 1 >= len(packet_bytes):
                raise ValueError("dns pointer overflow")
            return current + 2
        current += 1 + length
        steps += 1
        if steps > 255:
            raise ValueError("dns name loop")


def dns_read_name(packet_bytes, offset):
    labels = []
    current = int(offset)
    next_offset = int(offset)
    jumped = False
    jumps = 0
    while True:
        if current >= len(packet_bytes):
            raise ValueError("dns name overflow")
        length = int(packet_bytes[current])
        if length == 0:
            if not jumped:
                next_offset = current + 1
            break
        if (length & 0xC0) == 0xC0:
            if current + 1 >= len(packet_bytes):
                raise ValueError("dns pointer overflow")
            pointer = ((length & 0x3F) << 8) | int(packet_bytes[current + 1])
            if not jumped:
                next_offset = current + 2
            current = pointer
            jumped = True
            jumps += 1
            if jumps > 255:
                raise ValueError("dns pointer loop")
            continue
        current += 1
        label_bytes = packet_bytes[current : current + length]
        if len(label_bytes) < length:
            raise ValueError("dns label overflow")
        label = bytes(label_bytes).decode("idna", errors="ignore")
        if label:
            labels.append(label)
        current += length
        if not jumped:
            next_offset = current
    return ".".join(labels).strip(".").lower(), int(next_offset)


def dns_parse_response(packet_bytes, expected_txid):
    if not isinstance(packet_bytes, (bytes, bytearray)) or len(packet_bytes) < 12:
        raise ValueError("short dns response")
    txid = int.from_bytes(packet_bytes[0:2], "big")
    flags = int.from_bytes(packet_bytes[2:4], "big")
    qdcount = int.from_bytes(packet_bytes[4:6], "big")
    ancount = int.from_bytes(packet_bytes[6:8], "big")
    rcode = flags & 0x000F
    is_response = (flags >> 15) & 0x01
    if is_response != 1:
        raise ValueError("invalid dns response flag")
    if int(expected_txid) != int(txid):
        raise ValueError("dns txid mismatch")

    offset = 12
    for _ in range(qdcount):
        offset = dns_skip_name(packet_bytes, offset)
        if offset + 4 > len(packet_bytes):
            raise ValueError("short dns question")
        offset += 4

    answers = []
    for _ in range(ancount):
        _name, offset = dns_read_name(packet_bytes, offset)
        if offset + 10 > len(packet_bytes):
            raise ValueError("short dns answer")
        rtype = int.from_bytes(packet_bytes[offset : offset + 2], "big")
        rclass = int.from_bytes(packet_bytes[offset + 2 : offset + 4], "big")
        ttl = int.from_bytes(packet_bytes[offset + 4 : offset + 8], "big")
        rdlength = int.from_bytes(packet_bytes[offset + 8 : offset + 10], "big")
        rdata_offset = offset + 10
        rdata_end = rdata_offset + rdlength
        if rdata_end > len(packet_bytes):
            raise ValueError("short dns rdata")
        if rclass == 1:
            if rtype == DNS_QTYPE_A and rdlength == 4:
                value = ".".join(str(int(byte)) for byte in packet_bytes[rdata_offset:rdata_end])
                answers.append({"type": "A", "value": value, "ttl": ttl})
            elif rtype in {DNS_QTYPE_PTR, DNS_QTYPE_CNAME}:
                value, _ = dns_read_name(packet_bytes, rdata_offset)
                answer_type = "PTR" if rtype == DNS_QTYPE_PTR else "CNAME"
                answers.append({"type": answer_type, "value": value, "ttl": ttl})
        offset = rdata_end

    return {
        "rcode": int(rcode),
        "answers": answers,
    }


def dns_udp_query(name_value, qtype, resolver_ip, timeout_seconds=1.4):
    resolver = str(resolver_ip or "").strip()
    if not resolver:
        return {
            "resolver": resolver,
            "rcode": None,
            "answers": [],
            "error": "empty resolver",
        }
    sock = None
    try:
        txid, query_packet = dns_build_query(name_value, qtype)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(max(0.3, float(timeout_seconds or 1.4)))
        sock.sendto(query_packet, (resolver, 53))
        response_packet, _addr = sock.recvfrom(4096)
        parsed = dns_parse_response(response_packet, expected_txid=txid)
        return {
            "resolver": resolver,
            "rcode": parsed.get("rcode"),
            "answers": parsed.get("answers", []),
            "error": "",
        }
    except Exception as exc:
        return {
            "resolver": resolver,
            "rcode": None,
            "answers": [],
            "error": str(exc),
        }
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass


def dns_ptr_lookup_for_ip(ip_value):
    octets = str(ip_value or "").strip().split(".")
    if len(octets) != 4:
        return {
            "query_name": "",
            "domains": [],
            "attempts": [],
            "error": "invalid ipv4",
            "status": "invalid",
        }
    query_name = ".".join(reversed(octets)) + ".in-addr.arpa"
    found = set()
    attempts = []
    for resolver_ip in DNS_RESOLVER_HINTS:
        response = dns_udp_query(query_name, DNS_QTYPE_PTR, resolver_ip, timeout_seconds=1.4)
        answer_values = []
        for answer in response.get("answers", []):
            value = normalize_nslookup_host(answer.get("value", ""))
            if value:
                found.add(value)
                answer_values.append(value)
        attempts.append(
            {
                "resolver": response.get("resolver", ""),
                "rcode": response.get("rcode"),
                "answers": answer_values,
                "error": response.get("error", ""),
            }
        )
        if found:
            break

    errors = [str(item.get("error", "")).strip() for item in attempts if str(item.get("error", "")).strip()]
    if found:
        status = "ok"
        error = ""
    elif errors and len(errors) == len(attempts):
        status = "error"
        error = errors[0]
    else:
        status = "no_ptr"
        error = ""
    return {
        "query_name": query_name,
        "domains": sorted(found),
        "attempts": attempts[:8],
        "error": error,
        "status": status,
    }


def dns_a_lookup_for_host(host_value):
    host = str(host_value or "").strip().lower()
    if not host:
        return {
            "host": host,
            "ips": [],
            "attempts": [],
            "error": "empty host",
            "status": "invalid",
        }

    found = set()
    attempts = []
    pending = [host]
    visited = set()
    max_names = 4

    while pending and len(visited) < max_names:
        current_name = str(pending.pop(0) or "").strip().lower()
        if not current_name or current_name in visited:
            continue
        visited.add(current_name)

        for resolver_ip in DNS_RESOLVER_HINTS:
            response = dns_udp_query(current_name, DNS_QTYPE_A, resolver_ip, timeout_seconds=1.4)
            next_names = []
            for answer in response.get("answers", []):
                answer_type = str(answer.get("type", "")).strip().upper()
                value = str(answer.get("value", "")).strip().lower()
                if answer_type == "A" and REGEX_IPV4_EXACT.match(value):
                    found.add(value)
                elif answer_type == "CNAME":
                    cname = normalize_nslookup_host(value)
                    if cname and cname not in visited and cname not in pending:
                        next_names.append(cname)
            attempts.append(
                {
                    "resolver": response.get("resolver", ""),
                    "name": current_name,
                    "rcode": response.get("rcode"),
                    "answers": response.get("answers", []),
                    "error": response.get("error", ""),
                }
            )
            if next_names:
                pending.extend(next_names)
            if found:
                break
        if found:
            break

    errors = [str(item.get("error", "")).strip() for item in attempts if str(item.get("error", "")).strip()]
    if found:
        status = "ok"
        error = ""
    elif errors and len(errors) == len(attempts):
        status = "error"
        error = errors[0]
    else:
        status = "no_a"
        error = ""
    return {
        "host": host,
        "ips": sorted(found),
        "attempts": attempts[:16],
        "error": error,
        "status": status,
    }


def resolve_ipv4_addresses_for_host(host_value):
    host = str(host_value or "").strip().lower()
    if not host:
        return [], "empty host"
    found = set()
    errors = []
    try:
        _hostname, _aliases, addr_list = socket.gethostbyname_ex(host)
        for addr in addr_list or []:
            candidate = str(addr or "").strip()
            if REGEX_IPV4_EXACT.match(candidate):
                found.add(candidate)
    except Exception as exc:
        errors.append(str(exc))
    try:
        for item in socket.getaddrinfo(host, None, socket.AF_INET):
            sockaddr = item[4] if len(item) > 4 else ()
            if not isinstance(sockaddr, tuple) or not sockaddr:
                continue
            candidate = str(sockaddr[0] or "").strip()
            if REGEX_IPV4_EXACT.match(candidate):
                found.add(candidate)
    except Exception as exc:
        errors.append(str(exc))

    if not found:
        dns_data = dns_a_lookup_for_host(host)
        for addr in dns_data.get("ips", []):
            candidate = str(addr or "").strip()
            if REGEX_IPV4_EXACT.match(candidate):
                found.add(candidate)
        dns_error = str(dns_data.get("error", "")).strip()
        if dns_error:
            errors.append(dns_error)

    unique_errors = [msg for msg in dict.fromkeys(errors) if msg]
    return sorted(found), unique_errors[0] if unique_errors else ""


def filter_domains_for_ip_socket(domains, ip_value, max_checks=48):
    verified = set()
    rejected = []
    checked = 0
    for domain in sorted({str(item or "").strip().lower() for item in (domains or []) if str(item or "").strip()}):
        normalized = normalize_domain_candidate(domain)
        if not normalized:
            continue
        if checked >= int(max_checks):
            break
        checked += 1
        resolved, lookup_error = resolve_ipv4_addresses_for_host(normalized)
        if ip_value in resolved:
            verified.add(normalized)
            continue
        rejected.append(
            {
                "domain": normalized,
                "resolved_ipv4": resolved[:8],
                "error": lookup_error,
            }
        )
    return {
        "domains": sorted(verified),
        "checked": checked,
        "rejected": rejected[:24],
    }


def discover_reverse_dns_domains(ip_value):
    found = set()
    reverse_host = ""
    aliases = []
    addresses = []
    error = ""
    lookups = []
    ptr_lookup = {
        "query_name": "",
        "domains": [],
        "attempts": [],
        "error": "",
        "status": "unknown",
    }
    try:
        hostname, alias_list, address_list = socket.gethostbyaddr(ip_value)
        reverse_host = str(hostname or "").strip().lower()
        aliases = [str(item).strip().lower() for item in (alias_list or []) if str(item).strip()]
        addresses = [str(item).strip() for item in (address_list or []) if str(item).strip()]

        for candidate in [reverse_host, *aliases]:
            normalized = normalize_nslookup_host(candidate)
            if normalized:
                found.add(normalized)

        ptr_lookup = {
            "query_name": "",
            "domains": sorted(found),
            "attempts": [],
            "error": "",
            "status": "ok",
        }
        for host_value in sorted(found):
            lookups.append(
                {
                    "host": host_value,
                    "resolved_ipv4": addresses[:8],
                    "matches_ip": ip_value in addresses or (host_value == "localhost" and str(ip_value).startswith("127.")),
                    "error": "",
                }
            )
    except socket.herror as exc:
        error = f"No PTR configurado: {exc}"
        ptr_lookup = {
            "query_name": "",
            "domains": [],
            "attempts": [],
            "error": str(exc),
            "status": "no_ptr",
        }
    except Exception as exc:
        error = str(exc)
        ptr_lookup = {
            "query_name": "",
            "domains": [],
            "attempts": [],
            "error": str(exc),
            "status": "error",
        }

    return {
        "domains": sorted(found),
        "verified_domains": sorted(found),
        "candidates": sorted(found),
        "reverse_host": reverse_host,
        "fqdn_host": reverse_host,
        "aliases": sorted(set(aliases)),
        "addresses": addresses[:8],
        "lookups": lookups[:24],
        "ptr_lookup": ptr_lookup,
        "error": error,
    }


def infer_hops_from_observed_ttl(observed_ttl):
    try:
        ttl_value = int(observed_ttl)
    except Exception:
        return None
    if ttl_value < 1 or ttl_value > 255:
        return None
    guessed_base = 255
    for base in TTL_BASE_HINTS:
        if ttl_value <= base:
            guessed_base = base
            break
    devices_in_path = max(int(guessed_base) - int(ttl_value), 0)
    hops_to_target = int(devices_in_path) + 1
    return {
        "observed_ttl": int(ttl_value),
        "initial_ttl_guess": int(guessed_base),
        "hops_to_target": int(hops_to_target),
        "devices_in_path": int(devices_in_path),
    }


def estimate_ttl_from_scanned_tags(ip_value):
    try:
        scan_db.create_tables()
    except Exception:
        pass
    ttl_rows = []
    errors = []
    try:
        for row in scan_db.select_tags():
            item = row if isinstance(row, dict) else {}
            if str(item.get("ip", "")).strip() != ip_value:
                continue
            key = str(item.get("key", "") or "").strip().lower()
            if "ttl" not in key:
                continue
            value = str(item.get("value", "") or "").strip()
            inferred = infer_hops_from_observed_ttl(value)
            if not inferred:
                continue
            ttl_rows.append(
                {
                    "key": key,
                    "value": int(inferred["observed_ttl"]),
                    "hops_to_target": int(inferred["hops_to_target"]),
                    "devices_in_path": int(inferred["devices_in_path"]),
                    "initial_ttl_guess": int(inferred["initial_ttl_guess"]),
                }
            )
    except Exception as exc:
        errors.append(str(exc))

    if not ttl_rows:
        return {
            "method": "scan_tag_ttl_estimate",
            "available": False,
            "reached": False,
            "hops_to_target": None,
            "devices_in_path": None,
            "route": [],
            "raw": "",
            "observed_ttl": None,
            "initial_ttl_guess": None,
            "source_tag": "",
            "error": errors[0] if errors else "no TTL tags available for this IP",
        }

    ttl_rows.sort(key=lambda row: row["hops_to_target"])
    best = ttl_rows[0]
    return {
        "method": "scan_tag_ttl_estimate",
        "available": True,
        "reached": True,
        "hops_to_target": int(best["hops_to_target"]),
        "devices_in_path": int(best["devices_in_path"]),
        "route": [],
        "raw": "",
        "observed_ttl": int(best["value"]),
        "initial_ttl_guess": int(best["initial_ttl_guess"]),
        "source_tag": str(best["key"]),
        "error": "",
    }


def tcp_ttl_candidate_ports(ip_value):
    ports = set(TCP_TTL_PORT_HINTS)
    try:
        scan_db.create_tables()
    except Exception:
        pass
    try:
        for row in scan_db.select_ports_where_tcp():
            item = row if isinstance(row, dict) else {}
            if str(item.get("ip", "")).strip() != ip_value:
                continue
            if str(item.get("state", "")).strip().lower() != "open":
                continue
            try:
                port_value = int(item.get("port", 0) or 0)
            except Exception:
                port_value = 0
            if 1 <= port_value <= 65535:
                ports.add(port_value)
    except Exception:
        pass
    return sorted(ports)


def tcp_connect_ttl_estimate(ip_value, max_hops=30, timeout_seconds=0.9):
    max_hops = clamp_int(max_hops, 30, 1, 64)
    timeout_seconds = max(float(timeout_seconds or 0.9), 0.2)
    candidate_ports = tcp_ttl_candidate_ports(ip_value)[:8]
    attempts = []
    last_error = ""
    reached_codes = {0}
    for code_name in ("ECONNREFUSED", "ECONNRESET"):
        if hasattr(errno, code_name):
            reached_codes.add(int(getattr(errno, code_name)))

    for port in candidate_ports:
        for ttl in range(1, max_hops + 1):
            sock = None
            start = time.time()
            code = None
            error_text = ""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout_seconds)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, int(ttl))
                code = int(sock.connect_ex((ip_value, int(port))))
            except Exception as exc:
                error_text = str(exc)
                last_error = error_text
            finally:
                try:
                    if sock:
                        sock.close()
                except Exception:
                    pass

            elapsed_ms = round((time.time() - start) * 1000, 2)
            err_name = errno.errorcode.get(int(code), "") if isinstance(code, int) else ""
            attempts.append(
                {
                    "port": int(port),
                    "ttl": int(ttl),
                    "code": int(code) if isinstance(code, int) else None,
                    "code_name": err_name,
                    "time_ms": elapsed_ms,
                    "error": error_text,
                }
            )

            if error_text and "operation not permitted" in error_text.lower():
                return {
                    "method": "tcp_ttl_estimate",
                    "available": False,
                    "reached": False,
                    "hops_to_target": None,
                    "devices_in_path": None,
                    "route": [],
                    "raw": "",
                    "probe_port": int(port),
                    "samples": attempts[-24:],
                    "error": error_text,
                }

            if isinstance(code, int) and int(code) in reached_codes:
                hops_to_target = int(ttl)
                return {
                    "method": "tcp_ttl_estimate",
                    "available": True,
                    "reached": True,
                    "hops_to_target": hops_to_target,
                    "devices_in_path": max(hops_to_target - 1, 0),
                    "route": [],
                    "raw": "",
                    "probe_port": int(port),
                    "samples": attempts[-24:],
                    "error": "",
                }

            if len(attempts) >= 128:
                break
        if len(attempts) >= 128:
            break

    return {
        "method": "tcp_ttl_estimate",
        "available": False,
        "reached": False,
        "hops_to_target": None,
        "devices_in_path": None,
        "route": [],
        "raw": "",
        "probe_port": int(candidate_ports[0]) if candidate_ports else None,
        "samples": attempts[-24:],
        "error": last_error or "tcp ttl estimation could not reach destination",
    }


def extract_domains_from_text(text_value, max_domains=160):
    found = set()
    text = str(text_value or "")
    for match in REGEX_DOMAIN_IN_TEXT.finditer(text):
        normalized = normalize_domain_candidate(match.group(0))
        if normalized:
            found.add(normalized)
            if len(found) >= max_domains:
                break
    return sorted(found)


def extract_host_from_url_candidate(url_value):
    raw = str(url_value or "").strip()
    if not raw:
        return ""
    match = REGEX_URL_WITH_HOST.match(raw)
    if not match:
        return ""
    host_port = str(match.group(1) or "").strip()
    if "@" in host_port:
        host_port = host_port.rsplit("@", 1)[-1]
    if host_port.startswith("["):
        close_index = host_port.find("]")
        host = host_port[1:close_index] if close_index > 1 else ""
    else:
        host = host_port.split(":", 1)[0]
    return normalize_domain_candidate(host)


def discover_domains_from_scanned_data(ip_value):
    found = set()
    samples = {
        "banners": [],
        "tags": [],
        "favicon_urls": [],
    }
    errors = []

    try:
        scan_db.create_tables()
    except Exception:
        pass

    try:
        for row in scan_db.select_banners():
            item = row if isinstance(row, dict) else {}
            if str(item.get("ip", "")).strip() != ip_value:
                continue
            chunks = [str(item.get("response_plain", "") or "")]
            for extra_key in ("response", "banner", "payload"):
                raw = item.get(extra_key, "")
                if isinstance(raw, (bytes, bytearray)):
                    chunks.append(bytes(raw).decode("iso-8859-1", errors="ignore"))
                elif raw:
                    chunks.append(str(raw))
            text = "\n".join(chunks)
            domains = extract_domains_from_text(text, max_domains=64)
            for domain in domains:
                found.add(domain)
            if domains and len(samples["banners"]) < 12:
                samples["banners"].append(
                    {
                        "port": int(item.get("port", 0) or 0),
                        "domains": domains[:10],
                    }
                )
    except Exception as exc:
        errors.append(f"banners: {exc}")

    try:
        for row in scan_db.select_tags():
            item = row if isinstance(row, dict) else {}
            if str(item.get("ip", "")).strip() != ip_value:
                continue
            tag_key = str(item.get("key", "") or "").strip().lower()
            tag_value = str(item.get("value", "") or "").strip()
            has_domain_hint = any(
                token in tag_key
                for token in (
                    "domain",
                    "host",
                    "hostname",
                    "url",
                    "uri",
                    "fqdn",
                    "sni",
                    "cn",
                    "location",
                    "origin",
                )
            )
            domains = set(extract_domains_from_text(tag_value, max_domains=64))
            if has_domain_hint:
                normalized_value = normalize_domain_candidate(tag_value)
                if normalized_value:
                    domains.add(normalized_value)
                url_host = extract_host_from_url_candidate(tag_value)
                if url_host:
                    domains.add(url_host)
            domains = sorted(domains)
            for domain in domains:
                found.add(domain)
            if domains and len(samples["tags"]) < 12:
                samples["tags"].append(
                    {
                        "key": tag_key,
                        "domains": domains[:10],
                    }
                )
    except Exception as exc:
        errors.append(f"tags: {exc}")

    try:
        for row in scan_db.select_favicons():
            item = row if isinstance(row, dict) else {}
            if str(item.get("ip", "")).strip() != ip_value:
                continue
            icon_url = str(item.get("icon_url", "") or "").strip()
            if not icon_url:
                continue
            host = extract_host_from_url_candidate(icon_url)
            if host:
                found.add(host)
                if len(samples["favicon_urls"]) < 12:
                    samples["favicon_urls"].append(host)
    except Exception as exc:
        errors.append(f"favicons: {exc}")

    return {
        "domains": sorted(found),
        "samples": samples,
        "errors": errors[:10],
    }


def tcp_http_candidate_ports_for_ip(ip_value):
    ports = set(HTTP_DOMAIN_PORT_HINTS)
    try:
        scan_db.create_tables()
    except Exception:
        pass
    try:
        for row in scan_db.select_ports_where_tcp():
            item = row if isinstance(row, dict) else {}
            if str(item.get("ip", "")).strip() != ip_value:
                continue
            if str(item.get("state", "")).strip().lower() != "open":
                continue
            port = int(item.get("port", 0) or 0)
            if port > 0:
                ports.add(port)
    except Exception:
        pass
    return sorted(ports)


def discover_http_header_domains(ip_value, timeout_seconds=1.6):
    found = set()
    ports_with_data = []
    errors = []

    for port in tcp_http_candidate_ports_for_ip(ip_value)[:14]:
        sock = None
        raw = b""
        try:
            request = (
                "GET / HTTP/1.1\r\n"
                f"Host: {ip_value}\r\n"
                "User-Agent: PortHound/1.0\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii", errors="ignore")

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(float(timeout_seconds))
            sock.connect((ip_value, int(port)))
            sock.sendall(request)
            while len(raw) < 16384:
                chunk = sock.recv(min(2048, 16384 - len(raw)))
                if not chunk:
                    break
                raw += chunk
        except Exception as exc:
            errors.append(f"port {port}: {exc}")
            continue
        finally:
            try:
                if sock:
                    sock.close()
            except Exception:
                pass

        if not raw:
            continue
        text = raw.decode("iso-8859-1", errors="ignore")
        domains = extract_domains_from_text(text, max_domains=90)
        if domains:
            ports_with_data.append(int(port))
            for domain in domains:
                found.add(domain)

    return {
        "domains": sorted(found),
        "ports": sorted(set(ports_with_data)),
        "errors": errors[:14],
    }


def parse_icmp_type_code(packet_bytes):
    if not isinstance(packet_bytes, (bytes, bytearray)) or len(packet_bytes) < 28:
        return None, None
    ip_header_size = (int(packet_bytes[0]) & 0x0F) * 4
    if len(packet_bytes) < ip_header_size + 2:
        return None, None
    return int(packet_bytes[ip_header_size]), int(packet_bytes[ip_header_size + 1])


def parse_icmp_embedded_udp_dst_port(packet_bytes):
    if not isinstance(packet_bytes, (bytes, bytearray)) or len(packet_bytes) < 56:
        return None
    outer_ip_header_size = (int(packet_bytes[0]) & 0x0F) * 4
    if len(packet_bytes) < outer_ip_header_size + 8:
        return None
    inner_ip_offset = outer_ip_header_size + 8
    if len(packet_bytes) < inner_ip_offset + 20:
        return None
    inner_ip_header_size = (int(packet_bytes[inner_ip_offset]) & 0x0F) * 4
    udp_offset = inner_ip_offset + inner_ip_header_size
    if len(packet_bytes) < udp_offset + 4:
        return None
    return (int(packet_bytes[udp_offset + 2]) << 8) | int(packet_bytes[udp_offset + 3])


def traceroute_ttl_path(ip_value, max_hops=30, timeout_seconds=1.2):
    max_hops = clamp_int(max_hops, 30, 1, 64)
    timeout_seconds = max(float(timeout_seconds or 1.2), 0.2)
    route = []
    reached = False
    errors = []
    destination_port = SOCKET_TTL_PROBE_BASE_PORT + random.randint(0, 2000)

    for ttl in range(1, max_hops + 1):
        recv_sock = None
        send_sock = None
        hop_ip = ""
        icmp_type = None
        icmp_code = None
        rtt_ms = None
        try:
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            recv_sock.settimeout(timeout_seconds)

            send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, int(ttl))

            start = time.time()
            send_sock.sendto(b"PH-TTL", (ip_value, destination_port))
            deadline = start + timeout_seconds
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise socket.timeout()
                recv_sock.settimeout(remaining)
                packet, addr = recv_sock.recvfrom(1024)
                embedded_dst = parse_icmp_embedded_udp_dst_port(packet)
                if embedded_dst is not None and int(embedded_dst) != int(destination_port):
                    continue
                rtt_ms = round((time.time() - start) * 1000, 2)
                hop_ip = str((addr or [""])[0] or "")
                icmp_type, icmp_code = parse_icmp_type_code(packet)

                if hop_ip == ip_value:
                    reached = True
                if icmp_type == 3 and icmp_code == 3 and hop_ip == ip_value:
                    reached = True
                break
        except PermissionError:
            return {
                "method": "socket_traceroute",
                "available": False,
                "reached": False,
                "hops_to_target": None,
                "devices_in_path": None,
                "route": [],
                "raw": "",
                "error": "raw socket permission denied",
            }
        except socket.timeout:
            pass
        except OSError as exc:
            errors.append(f"hop {ttl}: {exc}")
        except Exception as exc:
            errors.append(f"hop {ttl}: {exc}")
        finally:
            try:
                if send_sock:
                    send_sock.close()
            except Exception:
                pass
            try:
                if recv_sock:
                    recv_sock.close()
            except Exception:
                pass

        route.append(
            {
                "hop": int(ttl),
                "ip": hop_ip,
                "resolved": bool(hop_ip),
                "rtt_ms": rtt_ms,
                "icmp_type": icmp_type,
                "icmp_code": icmp_code,
            }
        )
        if reached:
            break

    hops_to_target = None
    devices_in_path = None
    if route:
        if reached:
            hops_to_target = int(route[-1]["hop"])
        else:
            last_resolved = [item for item in route if item.get("resolved")]
            if last_resolved:
                hops_to_target = int(last_resolved[-1]["hop"])
        if hops_to_target is not None:
            devices_in_path = max(hops_to_target - 1, 0)

    if not route:
        return {
            "method": "socket_traceroute",
            "available": False,
            "reached": False,
            "hops_to_target": None,
            "devices_in_path": None,
            "route": [],
            "raw": "",
            "error": errors[0] if errors else "no route data",
        }

    return {
        "method": "socket_traceroute",
        "available": True,
        "reached": reached,
        "hops_to_target": hops_to_target,
        "devices_in_path": devices_in_path,
        "route": route,
        "raw": "",
        "error": errors[0] if errors else "",
    }


def compute_ttl_path(ip_value):
    trace = traceroute_ttl_path(ip_value=ip_value, max_hops=30)
    has_trace_data = bool(trace.get("route")) or bool(trace.get("reached"))
    if trace.get("available") and has_trace_data:
        return trace

    tcp_estimate = tcp_connect_ttl_estimate(
        ip_value=ip_value,
        max_hops=30,
        timeout_seconds=0.9,
    )
    if tcp_estimate.get("available"):
        return {
            **tcp_estimate,
            "fallback_from": trace.get("method"),
            "trace_error": trace.get("error", ""),
        }

    tag_estimate = estimate_ttl_from_scanned_tags(ip_value=ip_value)
    if tag_estimate.get("available"):
        return {
            **tag_estimate,
            "fallback_from": trace.get("method"),
            "trace_error": trace.get("error", ""),
            "tcp_error": tcp_estimate.get("error", ""),
        }
    return {
        **trace,
        "tcp_fallback": tcp_estimate,
        "tag_fallback": tag_estimate,
    }


def compute_ip_domains(ip_value):
    reverse_data = discover_reverse_dns_domains(ip_value)
    scanned_data = discover_domains_from_scanned_data(ip_value)
    socket_probe_data = discover_http_header_domains(ip_value)
    candidate_domains = set(scanned_data.get("domains", []))
    candidate_domains.update(socket_probe_data.get("domains", []))
    verified_candidates = filter_domains_for_ip_socket(
        domains=sorted(candidate_domains),
        ip_value=ip_value,
        max_checks=48,
    )

    merged = set(reverse_data.get("domains", []))
    merged.update(reverse_data.get("verified_domains", []))
    merged.update(verified_candidates.get("domains", []))

    return {
        "ip": ip_value,
        "domains": sorted(merged),
        "sources": {
            "reverse_dns": reverse_data,
            "socket_nslookup": reverse_data,
            "tls_certificate": {
                "domains": [],
                "ports": [],
                "errors": ["disabled in socket-only mode"],
            },
            "scanned_data": scanned_data,
            "socket_probe": socket_probe_data,
            "socket_verification": verified_candidates,
        },
    }


def split_tag_values(value):
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def summarize_numeric_samples(values, digits=2):
    samples = []
    for value in values or []:
        try:
            numeric = float(value)
        except Exception:
            continue
        if numeric != numeric:
            continue
        samples.append(numeric)

    if not samples:
        return {
            "count": 0,
            "min": None,
            "max": None,
            "avg": None,
            "stddev": None,
            "jitter": None,
        }

    diffs = [abs(samples[idx] - samples[idx - 1]) for idx in range(1, len(samples))]
    return {
        "count": len(samples),
        "min": round(min(samples), digits),
        "max": round(max(samples), digits),
        "avg": round(sum(samples) / len(samples), digits),
        "stddev": round(statistics.pstdev(samples), digits) if len(samples) > 1 else 0.0,
        "jitter": round(sum(diffs) / len(diffs), digits) if diffs else 0.0,
    }


def compact_banner_preview(text_value, max_len=180):
    text = re.sub(r"\s+", " ", str(text_value or "")).strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def extract_ssl_name_component(name_items, key_name):
    target = str(key_name or "").strip().lower()
    for group in name_items or []:
        for pair in group or []:
            if not isinstance(pair, tuple) or len(pair) < 2:
                continue
            key, value = pair[0], pair[1]
            if str(key or "").strip().lower() == target and value:
                return str(value).strip()
    return ""


def normalize_cert_domains(values):
    found = set()
    for raw in values or []:
        candidate = normalize_domain_candidate(raw)
        if candidate:
            found.add(candidate)
    return sorted(found)


def cert_time_to_iso(value):
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        return utc_iso(int(ssl.cert_time_to_seconds(raw)))
    except Exception:
        return raw


def build_ttl_os_hint(ttl_data):
    guess = ttl_data.get("initial_ttl_guess")
    if guess == 64:
        return {
            "initial_ttl_guess": 64,
            "label": "unix-like",
            "description": "Typical of Linux, BSD and many embedded stacks.",
        }
    if guess == 128:
        return {
            "initial_ttl_guess": 128,
            "label": "windows-like",
            "description": "Typical of Windows hosts and some enterprise appliances.",
        }
    if guess == 255:
        return {
            "initial_ttl_guess": 255,
            "label": "network-device-like",
            "description": "Typical of routers, firewalls and network appliances.",
        }
    if guess == 32:
        return {
            "initial_ttl_guess": 32,
            "label": "legacy-or-embedded",
            "description": "Low initial TTL commonly seen in constrained or legacy stacks.",
        }
    return {
        "initial_ttl_guess": guess,
        "label": "",
        "description": "",
    }


def parse_http_probe_response(raw_bytes):
    raw = bytes(raw_bytes or b"")
    head_end = raw.find(b"\r\n\r\n")
    if head_end >= 0:
        head = raw[:head_end]
        body = raw[head_end + 4 :]
    else:
        head = raw
        body = b""
    lines = head.decode("iso-8859-1", errors="ignore").split("\r\n")
    status_code = None
    reason = ""
    headers = {}
    if lines and lines[0]:
        parts = lines[0].split(" ", 2)
        if len(parts) >= 2:
            try:
                status_code = int(parts[1])
            except Exception:
                status_code = None
        if len(parts) >= 3:
            reason = str(parts[2] or "").strip()
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = str(key or "").strip().lower()
        value = str(value or "").strip()
        if not key:
            continue
        if key in headers and value:
            headers[key] = f"{headers[key]}, {value}"
        else:
            headers[key] = value
    return {
        "status_code": status_code,
        "reason": reason,
        "headers": headers,
        "body_preview": body[:4096].decode("utf-8", errors="replace"),
        "raw_size": len(raw),
    }


def extract_html_title(text_value):
    match = re.search(r"<title[^>]*>\s*(.*?)\s*</title>", str(text_value or ""), re.I | re.S)
    if not match:
        return ""
    return compact_banner_preview(match.group(1), max_len=120)


def http_request_probe(
    ip_value,
    port,
    method="GET",
    use_tls=False,
    host_header="",
    timeout_seconds=1.4,
):
    host = str(host_header or ip_value or "").strip() or str(ip_value)
    request = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: PortHound/host-intel\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii", errors="ignore")
    started = time.time()
    try:
        with socket.create_connection((ip_value, int(port)), timeout=float(timeout_seconds)) as sock:
            sock.settimeout(float(timeout_seconds))
            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(sock, server_hostname=host if host else None) as tls_sock:
                    tls_sock.settimeout(float(timeout_seconds))
                    tls_version = str(tls_sock.version() or "")
                    cipher_info = tls_sock.cipher() or ()
                    cipher_name = str(cipher_info[0] or "") if cipher_info else ""
                    tls_sock.sendall(request)
                    raw = bytearray()
                    while len(raw) < 24576:
                        chunk = tls_sock.recv(min(4096, 24576 - len(raw)))
                        if not chunk:
                            break
                        raw.extend(chunk)
            else:
                sock.sendall(request)
                tls_version = ""
                cipher_name = ""
                raw = bytearray()
                while len(raw) < 24576:
                    chunk = sock.recv(min(4096, 24576 - len(raw)))
                    if not chunk:
                        break
                    raw.extend(chunk)
        parsed = parse_http_probe_response(bytes(raw))
        return {
            "ok": True,
            "error": "",
            "response_time_ms": round((time.time() - started) * 1000, 2),
            "tls_version": tls_version,
            "cipher": cipher_name,
            "host_header": host,
            **parsed,
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
            "response_time_ms": round((time.time() - started) * 1000, 2),
            "tls_version": "",
            "cipher": "",
            "host_header": host,
            "status_code": None,
            "reason": "",
            "headers": {},
            "body_preview": "",
            "raw_size": 0,
        }


def collect_host_scan_rows(ip_value):
    try:
        scan_db.create_tables()
    except Exception:
        pass

    output = {
        "ports": [],
        "tags": [],
        "banners": [],
        "favicons": [],
    }
    try:
        output["ports"] = [
            row for row in scan_db.select_ports() if str((row or {}).get("ip", "")).strip() == ip_value
        ]
    except Exception:
        output["ports"] = []
    try:
        output["tags"] = [
            row for row in scan_db.select_tags() if str((row or {}).get("ip", "")).strip() == ip_value
        ]
    except Exception:
        output["tags"] = []
    try:
        output["banners"] = [
            row for row in scan_db.select_banners() if str((row or {}).get("ip", "")).strip() == ip_value
        ]
    except Exception:
        output["banners"] = []
    try:
        output["favicons"] = [
            row for row in scan_db.select_favicons() if str((row or {}).get("ip", "")).strip() == ip_value
        ]
    except Exception:
        output["favicons"] = []
    return output


def build_host_service_inventory(ip_value, host_rows):
    ports = host_rows.get("ports", [])
    tags = host_rows.get("tags", [])
    banners = host_rows.get("banners", [])
    favicons = host_rows.get("favicons", [])

    tag_fields = (
        "service",
        "product",
        "server",
        "version",
        "runtime",
        "framework",
        "vendor",
        "protocol",
        "protocol_version",
        "http_status",
        "auth_scheme",
        "realm",
        "powered_by",
        "server_header",
    )
    proto_order = {"tcp": 0, "udp": 1, "icmp": 2, "sctp": 3}

    tags_by_endpoint = {}
    for row in tags:
        key = (
            int(row.get("port", 0) or 0),
            str(row.get("proto", "") or "").strip().lower(),
        )
        tags_by_endpoint.setdefault(key, []).append(row)

    banners_by_endpoint = {}
    for row in banners:
        key = (
            int(row.get("port", 0) or 0),
            str(row.get("proto", "") or "").strip().lower(),
        )
        banners_by_endpoint.setdefault(key, []).append(row)

    favicons_by_endpoint = {}
    for row in favicons:
        key = (
            int(row.get("port", 0) or 0),
            str(row.get("proto", "") or "").strip().lower(),
        )
        favicons_by_endpoint.setdefault(key, []).append(row)

    port_by_endpoint = {}
    endpoint_keys = set()
    for row in ports:
        key = (
            int(row.get("port", 0) or 0),
            str(row.get("proto", "") or "").strip().lower(),
        )
        endpoint_keys.add(key)
        port_by_endpoint[key] = row
    endpoint_keys.update(tags_by_endpoint.keys())
    endpoint_keys.update(banners_by_endpoint.keys())
    endpoint_keys.update(favicons_by_endpoint.keys())

    services = []
    for port, proto in sorted(endpoint_keys, key=lambda item: (proto_order.get(item[1], 99), item[0], item[1])):
        port_row = port_by_endpoint.get((port, proto), {})
        endpoint_tags = tags_by_endpoint.get((port, proto), [])
        endpoint_banner = banners_by_endpoint.get((port, proto), [{}])[0]
        endpoint_favicon = favicons_by_endpoint.get((port, proto), [{}])[0]

        fields = {field: set() for field in tag_fields}
        time_values = []
        tag_samples = []
        for tag_row in endpoint_tags:
            tag_key = str(tag_row.get("key", "") or "").strip().lower()
            tag_value = str(tag_row.get("value", "") or "").strip()
            if tag_key and tag_value and len(tag_samples) < 10:
                tag_samples.append(f"{tag_key}={tag_value}")
            if tag_key.endswith("time_ms"):
                try:
                    time_values.append(float(tag_value))
                except Exception:
                    pass
            for field in tag_fields:
                if tag_key == field or tag_key == f"banner.{field}":
                    for item in split_tag_values(tag_value):
                        fields[field].add(item)

        services.append(
            {
                "ip": ip_value,
                "port": int(port),
                "proto": proto,
                "state": str(port_row.get("state", "observed") or "observed").strip().lower(),
                "progress": port_row.get("progress"),
                "service": sorted(fields["service"]),
                "product": sorted(fields["product"]),
                "server": sorted(fields["server"]),
                "version": sorted(fields["version"]),
                "runtime": sorted(fields["runtime"]),
                "framework": sorted(fields["framework"]),
                "vendor": sorted(fields["vendor"]),
                "protocol": sorted(fields["protocol"]),
                "protocol_version": sorted(fields["protocol_version"]),
                "http_status": sorted(fields["http_status"]),
                "auth_scheme": sorted(fields["auth_scheme"]),
                "realm": sorted(fields["realm"]),
                "powered_by": sorted(fields["powered_by"]),
                "server_header": sorted(fields["server_header"]),
                "time_ms": summarize_numeric_samples(time_values),
                "time_ms_samples": [round(item, 2) for item in time_values[:24]],
                "tag_count": len(endpoint_tags),
                "tag_samples": tag_samples,
                "banner_preview": compact_banner_preview(endpoint_banner.get("response_plain", "")),
                "banner_updated_at": endpoint_banner.get("updated_at", ""),
                "favicon": (
                    {
                        "id": endpoint_favicon.get("id"),
                        "mime_type": endpoint_favicon.get("mime_type", ""),
                        "size": endpoint_favicon.get("size"),
                        "sha256": endpoint_favicon.get("sha256", ""),
                        "icon_url": endpoint_favicon.get("icon_url", ""),
                    }
                    if endpoint_favicon.get("id")
                    else None
                ),
            }
        )

    return services


def build_firewall_heuristic(service_rows):
    total = len(service_rows)
    open_rows = [row for row in service_rows if str(row.get("state", "")).strip().lower() == "open"]
    filtered_rows = [
        row for row in service_rows if str(row.get("state", "")).strip().lower() == "filtered"
    ]
    filtered_ratio = round(len(filtered_rows) / total, 3) if total else None
    if total == 0:
        return {
            "status": "unknown",
            "filtered_ratio": None,
            "summary": "No local scan rows available for this host.",
            "evidence": [],
        }
    if not filtered_rows:
        status = "low_filtering"
        summary = "No filtered ports observed in stored scan results."
    elif filtered_ratio is not None and filtered_ratio >= 0.65:
        status = "strong_filtering"
        summary = "High filtered ratio suggests a firewall or ACL is dropping probes."
    elif filtered_ratio is not None and filtered_ratio >= 0.3:
        status = "mixed_filtering"
        summary = "Mixed open and filtered exposure suggests selective packet filtering."
    else:
        status = "light_filtering"
        summary = "Some filtered ports were observed, but the host still exposes multiple services."
    return {
        "status": status,
        "filtered_ratio": filtered_ratio,
        "summary": summary,
        "evidence": [
            f"open={len(open_rows)}",
            f"filtered={len(filtered_rows)}",
            f"total_observed={total}",
        ],
    }


def build_http_surface(ip_value, service_rows, candidate_domains):
    candidates = {}
    for row in service_rows:
        if str(row.get("proto", "")).strip().lower() != "tcp":
            continue
        if str(row.get("state", "")).strip().lower() != "open":
            continue
        port = int(row.get("port", 0) or 0)
        if port <= 0:
            continue
        service_tokens = {item.lower() for item in row.get("service", [])}
        protocol_tokens = {item.lower() for item in row.get("protocol", [])}
        has_http_signal = (
            port in HTTP_DOMAIN_PORT_HINTS
            or bool(row.get("favicon"))
            or "http" in service_tokens
            or "https" in service_tokens
            or "http" in protocol_tokens
            or "https" in protocol_tokens
        )
        if not has_http_signal:
            continue
        use_tls = port in TLS_PORT_HINTS or "https" in service_tokens or "https" in protocol_tokens
        candidates[port] = bool(candidates.get(port) or use_tls)

    host_headers = []
    for domain in candidate_domains or []:
        if domain and domain not in host_headers:
            host_headers.append(domain)
    if ip_value not in host_headers:
        host_headers.append(ip_value)

    responses = []
    errors = []
    methods = set()
    server_headers = set()
    status_codes = set()
    auth_schemes = set()
    redirects = set()
    titles = set()
    timings = []

    for port in sorted(candidates)[:HOST_INTEL_MAX_HTTP_PORTS]:
        use_tls = bool(candidates.get(port))
        best = None
        for host_header in host_headers[:4]:
            probe = http_request_probe(
                ip_value=ip_value,
                port=port,
                method="GET",
                use_tls=use_tls,
                host_header=host_header,
                timeout_seconds=HOST_INTEL_HTTP_TIMEOUT_SECONDS,
            )
            if probe.get("ok"):
                best = probe
                break
            if host_header == host_headers[min(len(host_headers) - 1, 3)]:
                best = probe
        if not best or not best.get("ok"):
            errors.append(f"port {port}: {best.get('error', 'probe failed') if best else 'probe failed'}")
            responses.append(
                {
                    "port": int(port),
                    "scheme": "https" if use_tls else "http",
                    "reachable": False,
                    "status_code": None,
                    "server": "",
                    "powered_by": "",
                    "allow_methods": [],
                    "location": "",
                    "auth_scheme": "",
                    "content_type": "",
                    "title": "",
                    "response_time_ms": best.get("response_time_ms") if best else None,
                    "error": best.get("error", "probe failed") if best else "probe failed",
                }
            )
            continue

        options_probe = http_request_probe(
            ip_value=ip_value,
            port=port,
            method="OPTIONS",
            use_tls=use_tls,
            host_header=best.get("host_header", ip_value),
            timeout_seconds=HOST_INTEL_HTTP_TIMEOUT_SECONDS,
        )
        allow_header = ""
        if options_probe.get("ok"):
            allow_header = str(options_probe.get("headers", {}).get("allow", "") or "").strip()
        allow_methods = sorted({item.upper() for item in split_tag_values(allow_header)})
        if allow_methods:
            methods.update(allow_methods)

        headers = best.get("headers", {})
        server_value = str(headers.get("server", "") or "").strip()
        powered_by = str(headers.get("x-powered-by", "") or "").strip()
        location = str(headers.get("location", "") or "").strip()
        auth_header = str(headers.get("www-authenticate", "") or "").strip()
        auth_scheme = auth_header.split(" ", 1)[0].strip() if auth_header else ""
        content_type = str(headers.get("content-type", "") or "").strip()
        title = extract_html_title(best.get("body_preview", ""))

        if server_value:
            server_headers.add(server_value)
        if best.get("status_code") is not None:
            status_codes.add(int(best.get("status_code")))
        if auth_scheme:
            auth_schemes.add(auth_scheme)
        if location:
            redirects.add(location)
        if title:
            titles.add(title)
        if best.get("response_time_ms") is not None:
            timings.append(best.get("response_time_ms"))

        responses.append(
            {
                "port": int(port),
                "scheme": "https" if use_tls else "http",
                "reachable": True,
                "status_code": best.get("status_code"),
                "reason": best.get("reason", ""),
                "server": server_value,
                "powered_by": powered_by,
                "allow_methods": allow_methods,
                "location": location,
                "auth_scheme": auth_scheme,
                "content_type": content_type,
                "title": title,
                "response_time_ms": best.get("response_time_ms"),
                "tls_version": best.get("tls_version", ""),
                "cipher": best.get("cipher", ""),
                "error": "",
            }
        )

    return {
        "ports": [item["port"] for item in responses if item.get("reachable")],
        "methods": sorted(methods),
        "server_headers": sorted(server_headers),
        "status_codes": sorted(status_codes),
        "auth_schemes": sorted(auth_schemes),
        "redirects": sorted(redirects),
        "titles": sorted(titles),
        "timing_ms": summarize_numeric_samples(timings),
        "responses": responses,
        "errors": errors[:12],
    }


def probe_tls_service(ip_value, port, server_name="", timeout_seconds=1.8):
    started = time.time()
    with socket.create_connection((ip_value, int(port)), timeout=float(timeout_seconds)) as sock:
        sock.settimeout(float(timeout_seconds))
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(sock, server_hostname=server_name if server_name else None) as tls_sock:
            handshake_ms = round((time.time() - started) * 1000, 2)
            cert = tls_sock.getpeercert() or {}
            cipher_info = tls_sock.cipher() or ()
            not_after = str(cert.get("notAfter", "") or "").strip()
            not_before = str(cert.get("notBefore", "") or "").strip()
            days_remaining = None
            if not_after:
                try:
                    days_remaining = int((ssl.cert_time_to_seconds(not_after) - time.time()) / 86400)
                except Exception:
                    days_remaining = None
            san_dns = normalize_cert_domains(
                value for kind, value in cert.get("subjectAltName", []) if str(kind).upper() == "DNS"
            )
            subject_cn = extract_ssl_name_component(cert.get("subject", []), "commonName")
            return {
                "port": int(port),
                "sni": str(server_name or "").strip(),
                "tls_version": str(tls_sock.version() or ""),
                "cipher": str(cipher_info[0] or "") if cipher_info else "",
                "handshake_ms": handshake_ms,
                "subject_cn": subject_cn,
                "subject_org": extract_ssl_name_component(cert.get("subject", []), "organizationName"),
                "issuer_cn": extract_ssl_name_component(cert.get("issuer", []), "commonName"),
                "issuer_org": extract_ssl_name_component(cert.get("issuer", []), "organizationName"),
                "san_dns": san_dns,
                "not_before": cert_time_to_iso(not_before),
                "not_after": cert_time_to_iso(not_after),
                "days_remaining": days_remaining,
                "serial_number": str(cert.get("serialNumber", "") or "").strip(),
            }


def build_tls_surface(ip_value, service_rows, candidate_domains):
    candidates = set()
    for row in service_rows:
        if str(row.get("proto", "")).strip().lower() != "tcp":
            continue
        if str(row.get("state", "")).strip().lower() != "open":
            continue
        port = int(row.get("port", 0) or 0)
        service_tokens = {item.lower() for item in row.get("service", [])}
        protocol_tokens = {item.lower() for item in row.get("protocol", [])}
        if (
            port in TLS_PORT_HINTS
            or "https" in service_tokens
            or "tls" in service_tokens
            or "ssl" in service_tokens
            or "https" in protocol_tokens
        ):
            candidates.add(port)

    if 443 in [row.get("port") for row in service_rows if row.get("favicon")]:
        candidates.add(443)

    server_names = []
    for domain in candidate_domains or []:
        if domain and domain not in server_names:
            server_names.append(domain)
    server_names = server_names[:4]

    certificates = []
    errors = []
    versions = set()
    ciphers = set()
    cert_domains = set()
    handshakes = []

    for port in sorted(candidates)[:HOST_INTEL_MAX_TLS_PORTS]:
        attempt_names = list(server_names)
        if "" not in attempt_names:
            attempt_names.append("")
        last_error = "tls probe failed"
        success = None
        for server_name in attempt_names:
            try:
                success = probe_tls_service(
                    ip_value=ip_value,
                    port=port,
                    server_name=server_name,
                    timeout_seconds=HOST_INTEL_TLS_TIMEOUT_SECONDS,
                )
                break
            except Exception as exc:
                last_error = str(exc)
        if not success:
            errors.append(f"port {port}: {last_error}")
            continue
        certificates.append(success)
        if success.get("tls_version"):
            versions.add(success["tls_version"])
        if success.get("cipher"):
            ciphers.add(success["cipher"])
        if success.get("handshake_ms") is not None:
            handshakes.append(success["handshake_ms"])
        cert_domains.update(normalize_cert_domains([success.get("subject_cn", ""), *success.get("san_dns", [])]))

    return {
        "available": bool(certificates),
        "ports": [item["port"] for item in certificates],
        "versions": sorted(versions),
        "ciphers": sorted(ciphers),
        "certificate_domains": sorted(cert_domains),
        "handshake_ms": summarize_numeric_samples(handshakes),
        "certificates": certificates,
        "errors": errors[:12],
    }


def build_host_fingerprint(service_rows, ttl_data):
    services = set()
    products = set()
    servers = set()
    vendors = set()
    frameworks = set()
    runtimes = set()
    versions = set()
    protocols = set()

    for row in service_rows:
        services.update(str(item).strip() for item in row.get("service", []) if str(item).strip())
        products.update(str(item).strip() for item in row.get("product", []) if str(item).strip())
        servers.update(str(item).strip() for item in row.get("server", []) if str(item).strip())
        vendors.update(str(item).strip() for item in row.get("vendor", []) if str(item).strip())
        frameworks.update(str(item).strip() for item in row.get("framework", []) if str(item).strip())
        runtimes.update(str(item).strip() for item in row.get("runtime", []) if str(item).strip())
        versions.update(str(item).strip() for item in row.get("version", []) if str(item).strip())
        protocols.update(str(item).strip() for item in row.get("protocol", []) if str(item).strip())

    return {
        "services": sorted(services),
        "products": sorted(products),
        "servers": sorted(servers),
        "vendors": sorted(vendors),
        "frameworks": sorted(frameworks),
        "runtimes": sorted(runtimes),
        "versions": sorted(versions),
        "protocols": sorted(protocols),
        "ttl_os_hint": build_ttl_os_hint(ttl_data),
    }


def build_host_metrics(service_rows, domains_data, ttl_data, http_surface, tls_surface, host_rows):
    scan_time_values = []
    for row in service_rows:
        scan_time_values.extend(row.get("time_ms_samples", []))
    route_rtt_values = [
        float(hop.get("rtt_ms"))
        for hop in ttl_data.get("route", [])
        if hop.get("rtt_ms") is not None
    ]
    app_response_values = []
    for row in http_surface.get("responses", []):
        if row.get("reachable") and row.get("response_time_ms") is not None:
            app_response_values.append(float(row.get("response_time_ms")))
    for row in tls_surface.get("certificates", []):
        if row.get("handshake_ms") is not None:
            app_response_values.append(float(row.get("handshake_ms")))

    filtered_count = len(
        [row for row in service_rows if str(row.get("state", "")).strip().lower() == "filtered"]
    )
    open_count = len([row for row in service_rows if str(row.get("state", "")).strip().lower() == "open"])
    total_states = filtered_count + open_count

    return {
        "scan_time_ms": summarize_numeric_samples(scan_time_values),
        "route_rtt_ms": summarize_numeric_samples(route_rtt_values),
        "application_response_ms": summarize_numeric_samples(app_response_values),
        "timeout_ratio": round(filtered_count / total_states, 3) if total_states else None,
        "banner_count": len(host_rows.get("banners", [])),
        "favicon_count": len(host_rows.get("favicons", [])),
        "domain_count": len(domains_data.get("domains", [])),
        "service_count": len(service_rows),
        "hops_to_target": ttl_data.get("hops_to_target"),
    }


def build_host_profile(ip_value, domains_data, ttl_data):
    host_rows = collect_host_scan_rows(ip_value)
    service_rows = build_host_service_inventory(ip_value, host_rows)

    scope = classify_ipv4_scope(ip_value)
    geo = None
    if scope == "public":
        try:
            geo = scan_db.lookup_geoip_ipv4(ip_value)
        except Exception:
            geo = None
        if geo and geo.get("found") is False:
            geo = None

    domain_candidates = []
    for candidate in domains_data.get("domains", []):
        normalized = normalize_domain_candidate(candidate)
        if normalized and normalized not in domain_candidates:
            domain_candidates.append(normalized)
    reverse_host = str(
        domains_data.get("sources", {}).get("reverse_dns", {}).get("reverse_host", "") or ""
    ).strip().lower()
    if reverse_host:
        normalized_reverse = normalize_domain_candidate(reverse_host)
        if normalized_reverse and normalized_reverse not in domain_candidates:
            domain_candidates.insert(0, normalized_reverse)

    http_surface = build_http_surface(ip_value, service_rows, domain_candidates)
    tls_surface = build_tls_surface(ip_value, service_rows, domain_candidates)
    fingerprint = build_host_fingerprint(service_rows, ttl_data)
    firewall = build_firewall_heuristic(service_rows)
    metrics = build_host_metrics(
        service_rows=service_rows,
        domains_data=domains_data,
        ttl_data=ttl_data,
        http_surface=http_surface,
        tls_surface=tls_surface,
        host_rows=host_rows,
    )

    open_ports = [
        row["port"] for row in service_rows if str(row.get("state", "")).strip().lower() == "open"
    ]
    filtered_ports = [
        row["port"] for row in service_rows if str(row.get("state", "")).strip().lower() == "filtered"
    ]
    protocols = sorted(
        {
            str(row.get("proto", "")).strip().lower()
            for row in service_rows
            if str(row.get("proto", "")).strip()
        }
    )

    notes = []
    ttl_error = str(ttl_data.get("error", "") or "").strip()
    if ttl_error and "raw socket permission denied" in ttl_error.lower():
        notes.append("Traceroute raw socket mode requires root/CAP_NET_RAW; TCP fallback was used when possible.")
    if tls_surface.get("errors") and not tls_surface.get("available"):
        notes.append("TLS analysis could not complete on detected secure ports.")
    if firewall.get("status") in {"strong_filtering", "mixed_filtering"}:
        notes.append(firewall.get("summary"))

    return {
        "target": {
            "ip": ip_value,
            "ip_version": 4,
            "scope": scope,
            "geo": geo,
        },
        "transport": {
            "protocols": protocols,
            "open_port_count": len(open_ports),
            "filtered_port_count": len(filtered_ports),
            "open_ports": sorted(open_ports),
            "filtered_ports": sorted(filtered_ports),
            "services": service_rows[:64],
            "firewall": firewall,
        },
        "application": {
            "http": http_surface,
            "tls": tls_surface,
            "fingerprint": fingerprint,
        },
        "metrics": metrics,
        "notes": notes[:8],
    }


def ip_intel_cache_get(ip_value):
    now = time.time()
    with IP_INTEL_CACHE_LOCK:
        cached = IP_INTEL_CACHE.get(ip_value)
        if not cached:
            return None
        age = now - float(cached.get("cached_at", 0))
        if age > IP_INTEL_CACHE_TTL_SECONDS:
            IP_INTEL_CACHE.pop(ip_value, None)
            return None
        return dict(cached.get("data", {}))


def ip_intel_cache_set(ip_value, payload):
    with IP_INTEL_CACHE_LOCK:
        IP_INTEL_CACHE[ip_value] = {
            "cached_at": time.time(),
            "data": dict(payload or {}),
        }


def build_ip_intel(ip_value, force_refresh=False):
    if not force_refresh:
        cached = ip_intel_cache_get(ip_value)
        if cached:
            cached["cached"] = True
            return cached

    domains_data = compute_ip_domains(ip_value)
    ttl_data = compute_ttl_path(ip_value)
    host_profile = build_host_profile(
        ip_value=ip_value,
        domains_data=domains_data,
        ttl_data=ttl_data,
    )
    tls_surface = host_profile.get("application", {}).get("tls", {})
    tls_cert_domains = tls_surface.get("certificate_domains", [])
    if tls_cert_domains:
        merged_domains = set(domains_data.get("domains", []))
        merged_domains.update(tls_cert_domains)
        domains_data["domains"] = sorted(merged_domains)
    domains_data.setdefault("sources", {})
    domains_data["sources"]["tls_certificate"] = {
        "domains": list(tls_cert_domains),
        "ports": list(tls_surface.get("ports", [])),
        "errors": list(tls_surface.get("errors", [])),
    }
    payload = {
        "ip": ip_value,
        "cached": False,
        "generated_at": utc_iso(int(time.time())),
        "domains": domains_data,
        "ttl_path": ttl_data,
        "host_profile": host_profile,
    }
    ip_intel_cache_set(ip_value, payload)
    return payload


def build_scan_map_snapshot(limit_hosts=300):
    limit_hosts = clamp_int(limit_hosts, 300, 1, 2000)
    rows = scan_db.select_ports()
    hosts = {}
    total_ports = 0
    total_open_ports = 0

    for row in rows:
        ip_value = str((row or {}).get("ip", "")).strip()
        if not ip_value:
            continue
        host = hosts.get(ip_value)
        if host is None:
            host = {
                "ip": ip_value,
                "port_count": 0,
                "open_port_count": 0,
                "protocols": set(),
                "last_seen": "",
            }
            hosts[ip_value] = host
        host["port_count"] += 1
        total_ports += 1

        state = str((row or {}).get("state", "")).strip().lower()
        if state == "open":
            host["open_port_count"] += 1
            total_open_ports += 1

        proto = str((row or {}).get("proto", "")).strip().lower()
        if proto:
            host["protocols"].add(proto)

        seen_ts = str((row or {}).get("updated_at") or (row or {}).get("created_at") or "")
        if seen_ts and seen_ts > host["last_seen"]:
            host["last_seen"] = seen_ts

    ordered_hosts = sorted(
        hosts.values(),
        key=lambda item: (-item["open_port_count"], -item["port_count"], item["ip"]),
    )

    public_points = []
    private_hosts = []
    unmapped_public = []

    for host in ordered_hosts:
        formatted = {
            "ip": host["ip"],
            "port_count": int(host["port_count"]),
            "open_port_count": int(host["open_port_count"]),
            "protocols": sorted(host["protocols"]),
            "last_seen": host["last_seen"],
        }
        scope = classify_ipv4_scope(host["ip"])
        if scope != "public":
            private_hosts.append(formatted)
            continue
        geo = scan_db.lookup_geoip_ipv4(host["ip"])
        if not geo:
            unmapped_public.append(formatted)
            continue
        public_points.append(
            {
                **formatted,
                "lat": geo["lat"],
                "lon": geo["lon"],
                "rir": geo["rir"],
                "area": geo["area"],
                "country": geo["country"],
                "cidr": geo["cidr"],
            }
        )

    origin_ip = detect_scan_origin_ip()
    origin_scope = classify_ipv4_scope(origin_ip)
    origin_geo = scan_db.lookup_geoip_ipv4(origin_ip) if origin_scope == "public" else None
    origin_node = {
        "ip": origin_ip,
        "label": "Scan origin",
        "scope": origin_scope,
        "off_map": True,
    }
    if origin_geo:
        origin_node["rir"] = origin_geo["rir"]
        origin_node["area"] = origin_geo["area"]
        origin_node["country"] = origin_geo["country"]

    public_total = len(public_points)
    private_total = len(private_hosts)
    unmapped_total = len(unmapped_public)

    return {
        "generated_at": utc_iso(int(time.time())),
        "geoip": scan_db.geoip_status(),
        "origin": origin_node,
        "summary": {
            "total_hosts": len(ordered_hosts),
            "public_hosts": public_total,
            "private_hosts": private_total,
            "unmapped_public_hosts": unmapped_total,
            "total_ports": total_ports,
            "total_open_ports": total_open_ports,
        },
        "public_points": public_points[:limit_hosts],
        "private_hosts": private_hosts[:limit_hosts],
        "private_bucket": {
            "label": "Private and reserved IPs",
            "off_map": True,
            "count": private_total,
        },
        "unmapped_public": unmapped_public[: min(limit_hosts, 250)],
    }


def build_synthetic_attack_event(event_id, rng, ts_value=None):
    now_ts = int(ts_value if ts_value is not None else time.time())
    src = dict(rng.choice(ATTACK_SOURCE_NODES))
    dst = dict(rng.choice(ATTACK_TARGET_NODES))
    if src["ip"] == dst["ip"]:
        dst = dict(ATTACK_TARGET_NODES[(ATTACK_TARGET_NODES.index(dst) + 1) % len(ATTACK_TARGET_NODES)])
    signature = dict(rng.choice(ATTACK_SIGNATURES))
    severity = signature["severity"]
    if severity == "critical":
        action = rng.choice(["blocked", "blocked", "rate_limited"])
    elif severity == "high":
        action = rng.choice(["blocked", "rate_limited", "challenged"])
    elif severity == "medium":
        action = rng.choice(["blocked", "observed", "challenged"])
    else:
        action = rng.choice(["observed", "challenged"])
    base_confidence = {
        "critical": 0.95,
        "high": 0.88,
        "medium": 0.76,
        "low": 0.62,
    }.get(severity, 0.7)
    confidence = round(max(0.35, min(0.99, base_confidence + rng.uniform(-0.1, 0.07))), 3)
    packets = rng.randint(8, 140)
    bytes_count = packets * rng.randint(64, 1450)
    return {
        "id": event_id,
        "timestamp": now_ts,
        "timestamp_iso": utc_iso(now_ts),
        "attack_type": signature["attack_type"],
        "severity": severity,
        "protocol": signature["protocol"],
        "port": signature["port"],
        "service": signature["service"],
        "action": action if action else signature["default_action"],
        "confidence": confidence,
        "packets": packets,
        "bytes": bytes_count,
        "src": src,
        "dst": dst,
    }


def summarize_attacks(events):
    snapshot = list(events)
    now_ts = int(time.time())
    severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_action = {}
    by_type = {}
    targets = {}
    last_minute = 0
    confidence_sum = 0.0
    confidence_count = 0
    for item in snapshot:
        sev = str(item.get("severity", "low")).lower()
        severity[sev] = severity.get(sev, 0) + 1
        action = str(item.get("action", "observed"))
        by_action[action] = by_action.get(action, 0) + 1
        attack_type = str(item.get("attack_type", "unknown"))
        by_type[attack_type] = by_type.get(attack_type, 0) + 1
        if now_ts - int(item.get("timestamp", now_ts)) <= 60:
            last_minute += 1
        dst = item.get("dst", {}) if isinstance(item.get("dst"), dict) else {}
        dst_key = f"{dst.get('asset', 'unknown')} ({dst.get('ip', 'n/a')})"
        targets[dst_key] = targets.get(dst_key, 0) + 1
        try:
            confidence_sum += float(item.get("confidence", 0))
            confidence_count += 1
        except Exception:
            pass
    top_targets = sorted(
        [{"target": key, "hits": value} for key, value in targets.items()],
        key=lambda row: row["hits"],
        reverse=True,
    )[:5]
    return {
        "total_events": len(snapshot),
        "events_last_minute": last_minute,
        "severity": severity,
        "actions": by_action,
        "attack_types": by_type,
        "top_targets": top_targets,
        "avg_confidence": round(confidence_sum / confidence_count, 3) if confidence_count else 0.0,
        "generated_at": utc_iso(now_ts),
    }


def build_example_attack_events():
    sample_rng = random.Random(20260208)
    base_ts = int(time.time()) - 1800
    output = []
    for index in range(1, 31):
        output.append(build_synthetic_attack_event(index, sample_rng, ts_value=base_ts + index * 30))
    return output


EXAMPLE_ATTACK_EVENTS = build_example_attack_events()
EXAMPLE_ATTACK_SUMMARY = summarize_attacks(EXAMPLE_ATTACK_EVENTS)


class AttackTelemetry:
    def __init__(self, ws_registry, max_events=800):
        self.registry = ws_registry
        self.max_events = max_events
        self._rng = random.Random()
        self._lock = threading.Lock()
        self._events = deque(maxlen=max_events)
        self._seq = 0
        self._thread = None
        self._stop_event = threading.Event()
        self._running = True

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self.seed(45)
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="attack-telemetry")
        self._thread.start()

    def seed(self, count=45):
        count = clamp_int(count, 45, 1, 200)
        now_ts = int(time.time())
        seeded = []
        with self._lock:
            for idx in range(count):
                self._seq += 1
                event = build_synthetic_attack_event(
                    self._seq,
                    self._rng,
                    ts_value=now_ts - (count - idx) * 6,
                )
                self._events.append(event)
                seeded.append(event)
        return seeded

    def _run(self):
        while not self._stop_event.is_set():
            if self._running:
                event = self.generate_and_store()
                self.broadcast_event(event)
                if event["id"] % 6 == 0:
                    self.broadcast_summary()
            self._stop_event.wait(self._rng.uniform(0.9, 2.2))

    def set_running(self, running):
        with self._lock:
            self._running = bool(running)

    def status(self):
        with self._lock:
            size = len(self._events)
            running = self._running
            last_id = self._seq
        return {
            "running": running,
            "buffer_size": size,
            "max_buffer_size": self.max_events,
            "last_event_id": last_id,
        }

    def latest(self, limit=40):
        limit = clamp_int(limit, 40, 1, 250)
        with self._lock:
            return list(self._events)[-limit:]

    def summary(self):
        with self._lock:
            snapshot = list(self._events)
        return summarize_attacks(snapshot)

    def generate_and_store(self):
        with self._lock:
            self._seq += 1
            event = build_synthetic_attack_event(self._seq, self._rng)
            self._events.append(event)
            return event

    def push_custom(self, payload):
        payload = payload if isinstance(payload, dict) else {}
        with self._lock:
            self._seq += 1
            event = build_synthetic_attack_event(self._seq, self._rng)
            if isinstance(payload.get("src"), dict):
                event["src"].update(payload["src"])
            if isinstance(payload.get("dst"), dict):
                event["dst"].update(payload["dst"])
            for field in ("attack_type", "severity", "protocol", "service", "action"):
                if payload.get(field):
                    event[field] = str(payload[field])
            if "port" in payload:
                event["port"] = clamp_int(payload.get("port"), event["port"], 1, 65535)
            if "confidence" in payload:
                try:
                    event["confidence"] = round(float(payload.get("confidence")), 3)
                except Exception:
                    pass
            event["packets"] = clamp_int(payload.get("packets"), event["packets"], 1, 20000)
            event["bytes"] = clamp_int(payload.get("bytes"), event["bytes"], 64, 50000000)
            event["timestamp"] = int(time.time())
            event["timestamp_iso"] = utc_iso(event["timestamp"])
            self._events.append(event)
        self.broadcast_event(event)
        return event

    def broadcast_event(self, event):
        payload = json.dumps({"type": "attack_event", "data": event})
        self.registry.broadcast(1, payload.encode("utf-8"))

    def broadcast_summary(self):
        payload = json.dumps({"type": "attack_summary", "data": self.summary()})
        self.registry.broadcast(1, payload.encode("utf-8"))

    def burst(self, count=6):
        count = clamp_int(count, 6, 1, 30)
        generated = []
        for _ in range(count):
            event = self.generate_and_store()
            generated.append(event)
            self.broadcast_event(event)
        self.broadcast_summary()
        return generated


class ScanMapTelemetry:
    def __init__(self, ws_registry, interval_seconds=5.0):
        self.registry = ws_registry
        self.interval_seconds = float(interval_seconds)
        self._thread = None
        self._stop_event = threading.Event()
        self._last_signature = ""
        self._lock = threading.Lock()

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="scan-map-telemetry")
        self._thread.start()

    def snapshot(self, limit=300):
        return build_scan_map_snapshot(limit_hosts=limit)

    def _signature(self, snapshot):
        summary = snapshot.get("summary", {})
        public_points = snapshot.get("public_points", [])
        private_bucket = snapshot.get("private_bucket", {})
        key = {
            "summary": summary,
            "private_count": private_bucket.get("count", 0),
            "public": [
                f"{row.get('ip')}|{row.get('open_port_count')}|{row.get('last_seen')}"
                for row in public_points[:500]
            ],
        }
        return json.dumps(key, sort_keys=True, separators=(",", ":"))

    def _run(self):
        while not self._stop_event.wait(self.interval_seconds):
            try:
                snapshot = self.snapshot(limit=400)
                signature = self._signature(snapshot)
                with self._lock:
                    changed = signature != self._last_signature
                    if changed:
                        self._last_signature = signature
                if changed:
                    self.broadcast_snapshot(snapshot, event_type="scan_map_update")
            except Exception as e:
                print("[scan-map] telemetry loop:", e)

    def broadcast_snapshot(self, snapshot=None, event_type="scan_map_snapshot"):
        payload_data = snapshot if snapshot is not None else self.snapshot(limit=300)
        payload = json.dumps({"type": event_type, "data": payload_data})
        self.registry.broadcast(1, payload.encode("utf-8"))


RAW_ATTACK_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>PortHound Raw Attack Console</title>
  <style>
    :root { color-scheme: dark; }
    body { margin: 0; font-family: "JetBrains Mono", monospace; background: #060a12; color: #dce3ef; }
    .wrap { max-width: 1100px; margin: 24px auto; padding: 0 16px; }
    .row { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
    .card { background: #0b1320; border: 1px solid #20334d; border-radius: 10px; padding: 12px; }
    .card h3 { margin: 0 0 8px 0; font-size: 14px; color: #7ed3ff; }
    .metric { min-width: 170px; }
    canvas { width: 100%; max-width: 100%; background: #02060d; border: 1px solid #20334d; border-radius: 10px; display: block; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td { border-bottom: 1px solid #1c2d45; text-align: left; padding: 6px; }
    th { color: #91e6ff; font-weight: 600; }
    .small { font-size: 11px; color: #90a1bb; }
    .ok { color: #55d68c; }
    .warn { color: #ffbf55; }
    .bad { color: #ff6b6b; }
  </style>
</head>
<body>
  <div class="wrap">
    <h2>PortHound Raw Attack Console (REST + WS)</h2>
    <div class="small">Este panel usa <code>/api/attacks/feed</code>, <code>/api/attacks/summary</code> y <code>ws://.../ws/</code>.</div>
    <div class="row" id="metrics"></div>
    <canvas id="map" width="1000" height="420"></canvas>
    <div class="card" style="margin-top: 12px;">
      <h3>Live attack feed</h3>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Type</th>
            <th>Source</th>
            <th>Target</th>
            <th>Service</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody id="feed-body"></tbody>
      </table>
    </div>
  </div>
  <script>
    const feed = [];
    const maxFeed = 40;
    const canvas = document.getElementById("map");
    const ctx = canvas.getContext("2d");
    const metricsEl = document.getElementById("metrics");
    const feedBody = document.getElementById("feed-body");

    function lonLatToXY(lon, lat) {
      const x = ((Number(lon) + 180) / 360) * canvas.width;
      const y = ((90 - Number(lat)) / 180) * canvas.height;
      return [x, y];
    }

    function drawGrid() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = "#02060d";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.strokeStyle = "rgba(80, 130, 180, 0.18)";
      ctx.lineWidth = 1;
      for (let lat = -60; lat <= 60; lat += 30) {
        const y = lonLatToXY(0, lat)[1];
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
      }
      for (let lon = -150; lon <= 150; lon += 30) {
        const x = lonLatToXY(lon, 0)[0];
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, canvas.height);
        ctx.stroke();
      }
    }

    function severityColor(sev) {
      if (sev === "critical") return "rgba(255,72,72,0.95)";
      if (sev === "high") return "rgba(255,128,72,0.9)";
      if (sev === "medium") return "rgba(255,198,88,0.85)";
      return "rgba(107,202,255,0.85)";
    }

    function renderMap() {
      drawGrid();
      feed.slice(-20).forEach((event, idx) => {
        const src = event.src || {};
        const dst = event.dst || {};
        const [x1, y1] = lonLatToXY(src.lon, src.lat);
        const [x2, y2] = lonLatToXY(dst.lon, dst.lat);
        const midX = (x1 + x2) / 2;
        const midY = (y1 + y2) / 2 - Math.max(14, Math.abs(x1 - x2) * 0.09);
        ctx.strokeStyle = severityColor(String(event.severity || "low"));
        ctx.lineWidth = 1 + Math.max(0, 5 - idx * 0.2);
        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.quadraticCurveTo(midX, midY, x2, y2);
        ctx.stroke();
        ctx.fillStyle = "rgba(88, 220, 255, 0.9)";
        ctx.beginPath();
        ctx.arc(x1, y1, 2.2, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = "rgba(255, 120, 120, 0.95)";
        ctx.beginPath();
        ctx.arc(x2, y2, 2.4, 0, Math.PI * 2);
        ctx.fill();
      });
    }

    function renderMetrics(summary) {
      const data = summary || {};
      const severity = data.severity || {};
      metricsEl.innerHTML = [
        ["Total events", data.total_events || 0, "ok"],
        ["Last minute", data.events_last_minute || 0, "warn"],
        ["Critical", severity.critical || 0, "bad"],
        ["High", severity.high || 0, "warn"],
        ["Medium", severity.medium || 0, "ok"],
        ["Avg confidence", data.avg_confidence || 0, "ok"],
      ].map((item) =>
        `<div class="card metric"><h3>${item[0]}</h3><div class="${item[2]}">${item[1]}</div></div>`
      ).join("");
    }

    function renderFeed() {
      feedBody.innerHTML = feed.slice(-15).reverse().map((event) => {
        const src = event.src || {};
        const dst = event.dst || {};
        const ts = event.timestamp_iso || "";
        return `<tr>
          <td>${ts}</td>
          <td>${event.attack_type || "-"}</td>
          <td>${src.city || "-"} (${src.ip || "-"})</td>
          <td>${dst.asset || "-"} (${dst.ip || "-"})</td>
          <td>${event.protocol || ""}/${event.port || ""} ${event.service || ""}</td>
          <td>${event.action || "-"}</td>
        </tr>`;
      }).join("");
    }

    function pushEvent(event) {
      if (!event || typeof event !== "object") return;
      feed.push(event);
      while (feed.length > maxFeed) feed.shift();
      renderFeed();
      renderMap();
    }

    async function loadBootstrap() {
      const [feedRes, summaryRes] = await Promise.all([
        fetch("/api/attacks/feed?limit=40"),
        fetch("/api/attacks/summary"),
      ]);
      const feedJson = await feedRes.json();
      const summaryJson = await summaryRes.json();
      const events = Array.isArray(feedJson.datas) ? feedJson.datas : [];
      events.forEach(pushEvent);
      renderMetrics(summaryJson.summary || summaryJson);
    }

    function connectWs() {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      const ws = new WebSocket(`${proto}://${location.host}/ws/`);
      ws.addEventListener("open", () => {
        ws.send(JSON.stringify({ action: "attacks_snapshot", limit: 30 }));
        ws.send(JSON.stringify({ action: "attacks_summary" }));
      });
      ws.addEventListener("message", (msg) => {
        try {
          const payload = JSON.parse(msg.data);
          if (payload.type === "attack_event") pushEvent(payload.data);
          if (payload.type === "attack_snapshot" && Array.isArray(payload.data)) {
            payload.data.forEach(pushEvent);
          }
          if (payload.type === "attack_summary") {
            renderMetrics(payload.data || {});
          }
        } catch (err) {}
      });
      ws.addEventListener("close", () => {
        setTimeout(connectWs, 1500);
      });
    }

    drawGrid();
    loadBootstrap().catch(() => {});
    connectWs();
  </script>
</body>
</html>
"""

CLUSTER_AGENTS_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PortHound Cluster Agents</title>
  <style>
    :root { color-scheme: light dark; }
    body {
      margin: 0;
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
    }
    .wrap {
      max-width: 1200px;
      margin: 24px auto;
      padding: 0 16px 32px;
    }
    h1 { margin: 0 0 10px; font-size: 1.6rem; }
    .muted { color: #94a3b8; margin: 0 0 18px; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 10px;
      margin: 16px 0 24px;
    }
    .card {
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 10px;
      padding: 10px 12px;
    }
    .k { color: #94a3b8; font-size: 0.82rem; }
    .v { font-size: 1.2rem; font-weight: 700; }
    table {
      width: 100%;
      border-collapse: collapse;
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 10px;
      overflow: hidden;
    }
    th, td {
      padding: 10px 8px;
      border-bottom: 1px solid #1f2937;
      text-align: left;
      vertical-align: top;
      font-size: 0.92rem;
    }
    th {
      background: #0b1220;
      color: #93c5fd;
      font-weight: 600;
    }
    .status { font-weight: 700; text-transform: uppercase; letter-spacing: 0.03em; font-size: 0.76rem; }
    .online { color: #22c55e; }
    .stale { color: #f59e0b; }
    .offline { color: #ef4444; }
    .toolbar {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin: 12px 0;
    }
    input[type="text"] {
      min-width: 240px;
      background: #020617;
      color: #e2e8f0;
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 8px;
      font-size: 0.88rem;
    }
    button, a.btn {
      border: 1px solid #334155;
      background: #1e293b;
      color: #e2e8f0;
      border-radius: 8px;
      padding: 8px 10px;
      cursor: pointer;
      text-decoration: none;
      font-size: 0.85rem;
    }
    textarea {
      width: 100%;
      min-height: 90px;
      background: #020617;
      color: #e2e8f0;
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 8px;
      font-family: Consolas, Monaco, monospace;
      font-size: 0.82rem;
      margin-top: 8px;
      resize: vertical;
    }
    .warning {
      background: #1f2937;
      border: 1px solid #374151;
      border-radius: 8px;
      padding: 10px 12px;
      margin-top: 12px;
      color: #fcd34d;
      font-size: 0.86rem;
    }
    .badge {
      display: inline-block;
      border-radius: 999px;
      padding: 2px 8px;
      font-size: 0.74rem;
      border: 1px solid #334155;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Cluster Agents</h1>
    <p class="muted">Monitor de agentes + onboarding con llaves compartidas.</p>
    <div id="summary" class="grid"></div>
    <table>
      <thead>
        <tr>
          <th>Agent</th>
          <th>Auth</th>
          <th>Status</th>
          <th>Last Seen</th>
          <th>Client</th>
          <th>CN</th>
          <th>Active Tasks</th>
        </tr>
      </thead>
      <tbody id="agents-body"></tbody>
    </table>

    <h2 style="margin-top:26px;">Agent Onboarding</h2>
    <div class="toolbar">
      <input id="new-agent-id" type="text" placeholder="agent_id opcional (ej: edge-havana-01)">
      <button id="create-agent-credential">Agregar agente</button>
      <button id="copy-agent-output">Copiar datos</button>
    </div>
    <label class="k">Credenciales nuevas (mostrar una sola vez)</label>
    <textarea id="new-agent-output" readonly></textarea>
    <div class="warning">
      Si usas llaves compartidas, en el master configura `PORTHOUND_TLS_REQUIRE_CLIENT_CERT=0`
      o usa HTTP interno para que el agente pueda conectar sin certificado cliente.
    </div>

    <h3 style="margin-top:20px;">Credenciales registradas</h3>
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Agent</th>
          <th>Status</th>
          <th>Last Used</th>
          <th>Updated</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody id="credentials-body"></tbody>
    </table>

    <h2 style="margin-top:26px;">CA Distribution</h2>
    <div class="toolbar">
      <button id="copy-oneline">Copy CA one-line</button>
      <button id="copy-export">Copy export command</button>
      <a class="btn" href="/api/cluster/ca/raw" download>Download CA (.pem)</a>
    </div>
    <label class="k">CA one-line (`PORTHOUND_CA_ONELINE`)</label>
    <textarea id="ca-oneline" readonly></textarea>
    <label class="k" style="display:block; margin-top:12px;">Terminal export command</label>
    <textarea id="ca-export" readonly></textarea>
  </div>

  <script>
    const summaryEl = document.getElementById("summary");
    const agentsBody = document.getElementById("agents-body");
    const credentialsBody = document.getElementById("credentials-body");
    const caOneLineEl = document.getElementById("ca-oneline");
    const caExportEl = document.getElementById("ca-export");
    const newAgentIdEl = document.getElementById("new-agent-id");
    const newAgentOutputEl = document.getElementById("new-agent-output");

    function escapeHtml(value) {
      return String(value || "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
    }

    function renderSummary(summary) {
      const s = summary || {};
      const cards = [
        ["Total agents", s.total_agents || 0],
        ["Online", s.online || 0],
        ["Stale", s.stale || 0],
        ["Offline", s.offline || 0],
        ["Active tasks", s.active_tasks || 0],
      ];
      summaryEl.innerHTML = cards
        .map(([k, v]) => `<div class="card"><div class="k">${escapeHtml(k)}</div><div class="v">${escapeHtml(v)}</div></div>`)
        .join("");
    }

    function renderAgents(rows) {
      const data = Array.isArray(rows) ? rows : [];
      agentsBody.innerHTML = data.map((row) => {
        const tasks = Array.isArray(row.active_tasks) ? row.active_tasks : [];
        const tasksText = tasks.map((task) => {
          const tid = task.task_id || "-";
          const target = `${task.network || "?"} (${task.proto || "?"})`;
          return `${tid} - ${target} - ${task.lease_seconds_left || 0}s`;
        }).join("\\n");
        const status = String(row.status || "").toLowerCase();
        const authMode = String(row.auth_mode || "mtls").toLowerCase();
        return `<tr>
          <td>${escapeHtml(row.agent_id)}</td>
          <td><span class="badge">${escapeHtml(authMode)}</span></td>
          <td><span class="status ${escapeHtml(status)}">${escapeHtml(status || "-")}</span></td>
          <td>${escapeHtml(row.last_seen_iso || "-")}<br><span class="k">${escapeHtml(row.seconds_since_seen)}s ago</span></td>
          <td>${escapeHtml((row.client || []).join(":"))}</td>
          <td>${escapeHtml(row.certificate_cn || "-")}</td>
          <td><pre style="margin:0;white-space:pre-wrap;">${escapeHtml(tasksText)}</pre></td>
        </tr>`;
      }).join("");
    }

    async function loadAgents() {
      try {
        const res = await fetch("/api/cluster/agents");
        const payload = await res.json();
        renderSummary(payload.summary || {});
        renderAgents(payload.datas || []);
      } catch (err) {
        renderSummary({});
        agentsBody.innerHTML = `<tr><td colspan="7">Failed loading agents: ${escapeHtml(err)}</td></tr>`;
      }
    }

    function buildAgentOnboardingText(credential) {
      if (!credential) return "";
      const masterBase = `${location.protocol}//${location.host}`;
      const agentId = String(credential.agent_id || "");
      const agentKey = String(credential.agent_key || "");
      return [
        "MASTER WEB -> AGREGAR AGENTE (copiar y guardar):",
        `master: ${masterBase}`,
        `agent_id: ${agentId}`,
        `agent_key: ${agentKey}`,
        "",
        "En el agente ejecuta:",
        "python manage.py --interactive --role agent",
        "",
        "Si quieres por variables de entorno:",
        `export PORTHOUND_ROLE='agent'`,
        `export PORTHOUND_MASTER='${masterBase}'`,
        `export PORTHOUND_AGENT_ID='${agentId}'`,
        `export PORTHOUND_AGENT_SHARED_KEY='${agentKey}'`,
        "python manage.py",
      ].join("\\n");
    }

    function renderCredentials(rows) {
      const data = Array.isArray(rows) ? rows : [];
      credentialsBody.innerHTML = data.map((row) => {
        const active = Boolean(row.active);
        return `<tr>
          <td>${escapeHtml(row.id)}</td>
          <td>${escapeHtml(row.agent_id)}</td>
          <td><span class="badge">${escapeHtml(active ? "active" : "inactive")}</span></td>
          <td>${escapeHtml(row.last_used_at || "-")}</td>
          <td>${escapeHtml(row.updated_at || "-")}</td>
          <td>${active ? `<button data-revoke-id="${escapeHtml(row.id)}">Disable</button>` : "-"}</td>
        </tr>`;
      }).join("");
    }

    async function loadCredentials() {
      try {
        const res = await fetch("/api/cluster/agent/credentials");
        const payload = await res.json();
        renderCredentials(payload.datas || []);
      } catch (err) {
        credentialsBody.innerHTML = `<tr><td colspan="6">Failed loading credentials: ${escapeHtml(err)}</td></tr>`;
      }
    }

    async function createCredential() {
      const agentId = String(newAgentIdEl.value || "").trim();
      const body = agentId ? { agent_id: agentId } : {};
      const res = await fetch("/api/cluster/agent/credentials", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const payload = await res.json();
      if (!res.ok) {
        throw new Error(payload.status || `HTTP ${res.status}`);
      }
      const credential = payload.credential || {};
      newAgentOutputEl.value = buildAgentOnboardingText(credential);
      await loadCredentials();
    }

    async function revokeCredentialById(credentialId) {
      const res = await fetch("/api/cluster/agent/credentials", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: credentialId }),
      });
      const payload = await res.json();
      if (!res.ok) {
        throw new Error(payload.status || `HTTP ${res.status}`);
      }
      await loadCredentials();
    }

    async function loadCA() {
      try {
        const res = await fetch("/api/cluster/ca");
        const payload = await res.json();
        caOneLineEl.value = payload.ca_oneline || "";
        caExportEl.value = payload.export_command || "";
      } catch (err) {
        caOneLineEl.value = "";
        caExportEl.value = "";
      }
    }

    async function copyText(value) {
      if (!value) return;
      try {
        await navigator.clipboard.writeText(value);
      } catch (err) {}
    }

    document.getElementById("copy-oneline").addEventListener("click", () => copyText(caOneLineEl.value));
    document.getElementById("copy-export").addEventListener("click", () => copyText(caExportEl.value));
    document.getElementById("copy-agent-output").addEventListener("click", () => copyText(newAgentOutputEl.value));
    document.getElementById("create-agent-credential").addEventListener("click", async () => {
      try {
        await createCredential();
      } catch (err) {
        newAgentOutputEl.value = `Error: ${String(err)}`;
      }
    });
    credentialsBody.addEventListener("click", async (event) => {
      const target = event.target;
      if (!(target instanceof HTMLElement)) return;
      const revokeId = target.getAttribute("data-revoke-id");
      if (!revokeId) return;
      try {
        await revokeCredentialById(Number(revokeId));
      } catch (err) {
        newAgentOutputEl.value = `Error: ${String(err)}`;
      }
    });

    loadAgents();
    loadCredentials();
    loadCA();
    setInterval(loadAgents, 4000);
    setInterval(loadCredentials, 15000);
  </script>
</body>
</html>
"""

API_ENDPOINTS = [
    {"method": "GET", "path": "/api/dashboard/", "desc": "Frontend dashboard snapshot."},
    {"method": "GET", "path": "/api/charts/analytics", "desc": "Aggregated analytics series for chart dashboards."},
    {"method": "GET", "path": "/api/endpoints/", "desc": "Endpoint catalog."},
    {"method": "GET", "path": "/api/map/scan", "desc": "Geolocated scan map snapshot."},
    {"method": "GET", "path": "/api/catalog/banner-rules/", "desc": "List regex banner rules (builtin + custom)."},
    {"method": "POST", "path": "/api/catalog/banner-rules/", "desc": "Create custom regex banner rule."},
    {"method": "PUT", "path": "/api/catalog/banner-rules/", "desc": "Update custom regex banner rule."},
    {"method": "DELETE", "path": "/api/catalog/banner-rules/", "desc": "Delete custom regex banner rule."},
    {"method": "GET", "path": "/api/catalog/banner-requests/", "desc": "List banner probe requests (builtin + custom)."},
    {"method": "POST", "path": "/api/catalog/banner-requests/", "desc": "Create custom banner probe request."},
    {"method": "PUT", "path": "/api/catalog/banner-requests/", "desc": "Update custom banner probe request."},
    {"method": "DELETE", "path": "/api/catalog/banner-requests/", "desc": "Delete custom banner probe request."},
    {"method": "GET", "path": "/api/catalog/ip-presets/", "desc": "List IP presets (builtin + custom)."},
    {"method": "POST", "path": "/api/catalog/ip-presets/", "desc": "Create custom IP preset."},
    {"method": "PUT", "path": "/api/catalog/ip-presets/", "desc": "Update custom IP preset."},
    {"method": "DELETE", "path": "/api/catalog/ip-presets/", "desc": "Delete custom IP preset."},
    {"method": "GET", "path": "/", "desc": "Counts summary."},
    {"method": "GET", "path": "/protocols/", "desc": "Supported target protocols."},
    {"method": "GET", "path": "/targets/", "desc": "List targets."},
    {"method": "POST", "path": "/target/", "desc": "Create target."},
    {"method": "PUT", "path": "/target/", "desc": "Update target."},
    {"method": "DELETE", "path": "/target/", "desc": "Delete target."},
    {"method": "POST", "path": "/target/action/", "desc": "Start/restart/stop/delete target."},
    {"method": "POST", "path": "/target/action/bulk/", "desc": "Bulk start/restart/stop targets by protocol."},
    {"method": "POST", "path": "/port/action/", "desc": "Start/restart/stop a specific endpoint scan."},
    {"method": "POST", "path": "/banner/action/", "desc": "Start/restart/stop banner collection for a specific endpoint."},
    {"method": "GET", "path": "/count/ports/icmp/", "desc": "Count ICMP hosts."},
    {"method": "GET", "path": "/count/ports/sctp/", "desc": "Count SCTP ports."},
    {"method": "GET", "path": "/ports/tcp/", "desc": "List TCP ports."},
    {"method": "GET", "path": "/ports/udp/", "desc": "List UDP ports."},
    {"method": "GET", "path": "/ports/icmp/", "desc": "List ICMP hosts."},
    {"method": "GET", "path": "/ports/sctp/", "desc": "List SCTP ports."},
    {"method": "GET", "path": "/banners/", "desc": "List banners."},
    {"method": "GET", "path": "/favicons/", "desc": "List captured favicons."},
    {"method": "GET", "path": "/favicons/raw/?id=<id>", "desc": "Raw favicon content by id."},
    {"method": "GET", "path": "/tags/", "desc": "List tags."},
    {"method": "GET", "path": "/tags/icmp/", "desc": "List ICMP tags."},
    {"method": "GET", "path": "/tags/sctp/", "desc": "List SCTP tags."},
    {"method": "GET", "path": "/api/ip/domains/?ip=<ipv4>", "desc": "Discover domains associated with an IPv4 target."},
    {"method": "GET", "path": "/api/ip/ttl-path/?ip=<ipv4>", "desc": "Estimate hop count and intermediate devices with TTL."},
    {"method": "GET", "path": "/api/ip/intel/?ip=<ipv4>", "desc": "Combined IP intel (domains + TTL path + host profile with HTTP/TLS metrics)."},
    {"method": "GET", "path": "/api/ws/clients", "desc": "List WS clients."},
    {"method": "POST", "path": "/api/ws/broadcast", "desc": "Broadcast WS message."},
    {"method": "POST", "path": "/api/ws/ping", "desc": "Ping WS clients."},
    {"method": "POST", "path": "/api/ws/close", "desc": "Close WS client(s)."},
    {"method": "GET", "path": "/api/chat/messages", "desc": "List chat messages."},
    {"method": "POST", "path": "/api/chat/clear", "desc": "Clear chat messages."},
    {"method": "GET", "path": "/cluster/agents/", "desc": "Cluster agents web view."},
    {"method": "GET", "path": "/api/cluster/agents", "desc": "List agents and status."},
    {"method": "GET", "path": "/api/cluster/agent/credentials", "desc": "List agent shared-key credentials."},
    {"method": "POST", "path": "/api/cluster/agent/credentials", "desc": "Create or rotate an agent shared-key credential."},
    {"method": "DELETE", "path": "/api/cluster/agent/credentials", "desc": "Disable an agent shared-key credential."},
    {"method": "GET", "path": "/api/cluster/ca", "desc": "CA payload + one-line env value."},
    {"method": "GET", "path": "/api/cluster/ca/raw", "desc": "Download CA certificate PEM file."},
    {"method": "GET", "path": "/api/cluster/ca/oneline", "desc": "Plain-text CA one-line value."},
    {"method": "POST", "path": "/api/cluster/agent/register", "desc": "Register an agent (mTLS or shared key)."},
    {"method": "POST", "path": "/api/cluster/agent/task/pull", "desc": "Agent pulls next scan task."},
    {"method": "POST", "path": "/api/cluster/agent/task/submit", "desc": "Agent submits scan results."},
]


_scanner_threads = []
attack_telemetry = AttackTelemetry(registry)
scan_map_telemetry = ScanMapTelemetry(registry)
cluster_lock = threading.Lock()
cluster_agents = {}
cluster_leases = {}
inline_ca_lock = threading.Lock()
inline_ca_tempfile_path = ""


def start_scanners():
    threads = [
        TCP(db=scan_db),
        UDP(db=scan_db),
        ICMP(db=scan_db),
        BannerTCP(db=scan_db),
        BannerUDP(db=scan_db),
    ]
    if "sctp" in TARGET_PROTOS:
        threads.insert(2, SCTP(db=scan_db))
    for t in threads:
        t.start()
    _scanner_threads.extend(threads)


def start_geoip_blocks_db():
    scan_db.create_tables()


def start_scan_map_telemetry():
    scan_map_telemetry.start()


def start_attack_telemetry():
    attack_telemetry.start()


def dist_file_response(file_path: Path, cache_control="public, max-age=300"):
    try:
        body = file_path.read_bytes()
    except Exception:
        return Response.text("Not Found", status=404)

    suffix = file_path.suffix.lower()
    content_type = STATIC_CONTENT_TYPE_OVERRIDES.get(suffix)
    if not content_type:
        guessed, _ = mimetypes.guess_type(str(file_path))
        content_type = guessed or "application/octet-stream"
        if content_type.startswith("text/") and "charset=" not in content_type:
            content_type += "; charset=utf-8"

    headers = {"Content-Type": content_type}
    if cache_control:
        headers["Cache-Control"] = cache_control
    return Response(status=200, body=body, headers=headers)


def frontend_index_response():
    index_path = FRONTEND_DIST_DIR / "index.html"
    if index_path.is_file():
        return dist_file_response(index_path, cache_control="no-cache")
    return Response.html(INDEX_HTML)


def register_frontend_dist_routes():
    global _frontend_dist_routes_registered
    if _frontend_dist_routes_registered:
        return
    if not FRONTEND_DIST_DIR.is_dir():
        print(f"[frontend] dist not found: {FRONTEND_DIST_DIR}")
        _frontend_dist_routes_registered = True
        return

    for file_path in sorted(FRONTEND_DIST_DIR.rglob("*")):
        if not file_path.is_file():
            continue
        route_path = "/" + file_path.relative_to(FRONTEND_DIST_DIR).as_posix()
        if app.router.resolve(route_path, method="GET"):
            continue

        def static_handler(request, _file_path=file_path):
            return dist_file_response(_file_path)

        app.router.add(Route(route_path, ("GET",), static_handler, "plain"))

    _frontend_dist_routes_registered = True


def wants_html(request):
    fmt = request.query.get("format")
    if fmt == "html":
        return True
    if fmt == "json":
        return False
    accept = request.headers.get("accept", "")
    return "text/html" in accept


def json_error(message, status=500):
    return Response.json({"status": str(message)}, status=status)


def current_role():
    value = str(getattr(settings, "ROLE", "master") or "master").strip().lower()
    if value in {"master", "agent", "standalone"}:
        return value
    return "master"


def is_master_role():
    return current_role() in {"master", "standalone"}


def _request_client_ip(request):
    client = getattr(request, "client", None)
    if isinstance(client, (list, tuple)) and client:
        return str(client[0] or "").strip()
    return str(client or "").strip()


def _is_loopback_client(request):
    raw_ip = _request_client_ip(request)
    if not raw_ip:
        return False
    try:
        return ip_address(raw_ip).is_loopback
    except Exception:
        return raw_ip in {"localhost"}


def _extract_request_token(request):
    headers = getattr(request, "headers", {}) or {}
    auth = str(
        headers.get("authorization", "")
        or headers.get("Authorization", "")
    ).strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return str(headers.get("x-api-key", "") or headers.get("X-API-Key", "")).strip()


def require_admin_access(request):
    configured_token = str(getattr(settings, "API_TOKEN", "") or "").strip()
    require_token = bool(getattr(settings, "API_REQUIRE_TOKEN", False))

    if configured_token:
        provided_token = _extract_request_token(request)
        if provided_token == configured_token:
            return None
        return json_error("Unauthorized", status=401)

    if require_token:
        return json_error("Unauthorized", status=401)

    if _is_loopback_client(request):
        return None
    return json_error(
        "Admin access denied for non-loopback client. Configure PORTHOUND_API_TOKEN.",
        status=403,
    )


def _request_peer_cert(request):
    tls_meta = getattr(request, "tls", {}) or {}
    cert = tls_meta.get("peer_cert")
    if isinstance(cert, dict):
        return cert
    return {}


def request_peer_common_name(request):
    cert = _request_peer_cert(request)
    subject = cert.get("subject") or ()
    for rdn in subject:
        try:
            pairs = list(rdn)
        except Exception:
            pairs = []
        for key, value in pairs:
            if str(key).strip().lower() == "commonname":
                return str(value or "").strip()
    return ""


def require_agent_mtls(request):
    cert = _request_peer_cert(request)
    if cert:
        return None
    return json_error("Client certificate required", status=401)


def _extract_agent_key(payload):
    if not isinstance(payload, dict):
        return ""
    for key in ("agent_key", "shared_key", "key"):
        value = str(payload.get(key, "") or "").strip()
        if value:
            return value
    return ""


def authenticate_cluster_agent(request, payload, expected_agent_id=""):
    data = payload if isinstance(payload, dict) else {}
    cert_cn = request_peer_common_name(request)
    expected = str(expected_agent_id or "").strip()

    if cert_cn:
        provided_agent_id = str(data.get("agent_id", "") or "").strip()
        if expected and cert_cn != expected:
            return None, json_error("agent_id does not match client certificate", status=403)
        if provided_agent_id and provided_agent_id != cert_cn:
            return None, json_error("agent_id does not match client certificate", status=403)
        return {
            "agent_id": cert_cn,
            "cert_cn": cert_cn,
            "auth_mode": "mtls",
        }, None

    resolved_agent_id = str(data.get("agent_id", "") or "").strip() or expected
    if not resolved_agent_id:
        return None, json_error("agent_id is required", status=400)
    if expected and resolved_agent_id != expected:
        return None, json_error("agent_id mismatch", status=403)

    agent_key = _extract_agent_key(data)
    if not agent_key:
        return None, json_error(
            "agent_key is required when client certificate is not provided",
            status=401,
        )
    if not scan_db.verify_cluster_agent_shared_key(
        resolved_agent_id,
        agent_key,
        touch_last_used=True,
    ):
        return None, json_error("Invalid agent_id or agent_key", status=401)
    return {
        "agent_id": resolved_agent_id,
        "cert_cn": "",
        "auth_mode": "shared_key",
    }, None


def ca_pem_to_oneline(pem_text):
    raw = str(pem_text or "").strip()
    if not raw:
        return ""
    return raw.replace("\r", "").replace("\n", "\\n")


def ca_oneline_to_pem(oneline_text):
    raw = str(oneline_text or "").strip()
    if not raw:
        return ""
    pem = raw.replace("\r", "").replace("\\n", "\n").strip()
    if not pem:
        return ""
    return pem + "\n"


def load_ca_pem_text(raise_if_missing=False):
    configured_path = str(getattr(settings, "PORTHOUND_CA", "") or "").strip()
    if configured_path:
        ca_path = Path(configured_path)
        if ca_path.is_file():
            return ca_path.read_text(encoding="utf-8", errors="ignore")
        if raise_if_missing:
            raise RuntimeError(f"CA file not found: {configured_path}")
    inline = str(getattr(settings, "PORTHOUND_CA_ONELINE", "") or "").strip()
    if inline:
        pem_text = ca_oneline_to_pem(inline)
        if pem_text:
            return pem_text
    if raise_if_missing:
        raise RuntimeError("PORTHOUND_CA or PORTHOUND_CA_ONELINE is required")
    return ""


def resolve_ca_file_path(required=False):
    global inline_ca_tempfile_path
    configured_path = str(getattr(settings, "PORTHOUND_CA", "") or "").strip()
    if configured_path and Path(configured_path).is_file():
        return configured_path

    inline = str(getattr(settings, "PORTHOUND_CA_ONELINE", "") or "").strip()
    if inline:
        pem_text = ca_oneline_to_pem(inline)
        if pem_text:
            with inline_ca_lock:
                cached = str(inline_ca_tempfile_path or "").strip()
                if cached and Path(cached).is_file():
                    try:
                        cached_text = Path(cached).read_text(
                            encoding="utf-8",
                            errors="ignore",
                        )
                    except Exception:
                        cached_text = ""
                    if cached_text == pem_text:
                        return cached

                temp_handle = tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    prefix="porthound-ca-inline-",
                    suffix=".pem",
                    delete=False,
                )
                try:
                    temp_handle.write(pem_text)
                    temp_handle.flush()
                    new_temp_path = str(temp_handle.name)
                finally:
                    temp_handle.close()
                try:
                    Path(new_temp_path).chmod(0o600)
                except Exception:
                    pass

                old_path = str(inline_ca_tempfile_path or "").strip()
                inline_ca_tempfile_path = new_temp_path
                if old_path and old_path != new_temp_path:
                    try:
                        Path(old_path).unlink(missing_ok=True)
                    except Exception:
                        pass
                return new_temp_path

    if required:
        if configured_path:
            raise RuntimeError(f"CA file not found: {configured_path}")
        raise RuntimeError("PORTHOUND_CA or PORTHOUND_CA_ONELINE is required")
    return ""


def _cluster_cleanup_expired_leases(now_ts=None):
    now_value = time.time() if now_ts is None else float(now_ts)
    expired = [
        target_id
        for target_id, lease in list(cluster_leases.items())
        if float(lease.get("lease_until", 0.0)) <= now_value
    ]
    for target_id in expired:
        cluster_leases.pop(target_id, None)


def _is_target_schedulable(target_row):
    if not isinstance(target_row, dict):
        return False
    status = str(target_row.get("status", "")).strip().lower()
    if status not in {"active", "restarting"}:
        return False
    try:
        progress = float(target_row.get("progress", 0.0) or 0.0)
    except Exception:
        progress = 0.0
    return progress < 100.0


def _serialize_target_task(target_row):
    return {
        "master_target_id": int(target_row["id"]),
        "network": str(target_row.get("network", "")).strip(),
        "type": str(target_row.get("type", "")).strip().lower(),
        "proto": (
            "sctp"
            if str(target_row.get("proto", "")).strip().lower() == "stcp"
            else str(target_row.get("proto", "")).strip().lower()
        ),
        "timesleep": float(target_row.get("timesleep", 1.0) or 1.0),
        "port_mode": str(target_row.get("port_mode", "preset")).strip().lower() or "preset",
        "port_start": int(target_row.get("port_start", 0) or 0),
        "port_end": int(target_row.get("port_end", 0) or 0),
    }


def claim_task_for_agent(agent_id):
    agent_value = str(agent_id or "").strip()
    if not agent_value:
        return None
    with cluster_lock:
        now_ts = time.time()
        _cluster_cleanup_expired_leases(now_ts)

        # Keep assignment sticky while lease is active.
        for target_id, lease in list(cluster_leases.items()):
            if str(lease.get("agent_id", "")) != agent_value:
                continue
            if float(lease.get("lease_until", 0.0)) <= now_ts:
                continue
            target = scan_db.select_target_by_id(int(target_id))
            if target and _is_target_schedulable(target):
                return {
                    "task_id": str(lease.get("task_id")),
                    "lease_seconds": max(
                        1,
                        int(float(lease.get("lease_until", now_ts)) - now_ts),
                    ),
                    "target": _serialize_target_task(target),
                }

        candidates = [row for row in scan_db.select_targets() if _is_target_schedulable(row)]
        candidates.sort(
            key=lambda row: (
                float((row or {}).get("progress", 0.0) or 0.0),
                int((row or {}).get("id", 0) or 0),
            )
        )
        for row in candidates:
            target_id = int(row["id"])
            current = cluster_leases.get(target_id)
            if current and float(current.get("lease_until", 0.0)) > now_ts:
                continue
            lease_seconds = int(getattr(settings, "AGENT_TASK_LEASE_SECONDS", 300) or 300)
            task_id = uuid.uuid4().hex
            cluster_leases[target_id] = {
                "task_id": task_id,
                "agent_id": agent_value,
                "assigned_at": now_ts,
                "lease_until": now_ts + lease_seconds,
            }
            return {
                "task_id": task_id,
                "lease_seconds": lease_seconds,
                "target": _serialize_target_task(row),
            }
    return None


def release_task_lease(target_id, task_id="", agent_id=""):
    try:
        target_int = int(target_id)
    except Exception:
        return
    with cluster_lock:
        lease = cluster_leases.get(target_int)
        if not lease:
            return
        if task_id and str(lease.get("task_id", "")) != str(task_id):
            return
        if agent_id and str(lease.get("agent_id", "")) != str(agent_id):
            return
        cluster_leases.pop(target_int, None)


def _agent_status_from_age(seconds_since_seen):
    poll_seconds = max(2, int(getattr(settings, "AGENT_POLL_SECONDS", 8) or 8))
    online_limit = max(15, poll_seconds * 3)
    stale_limit = max(60, poll_seconds * 8)
    age = max(0.0, float(seconds_since_seen or 0.0))
    if age <= online_limit:
        return "online"
    if age <= stale_limit:
        return "stale"
    return "offline"


def build_cluster_agents_snapshot():
    now_ts = time.time()
    with cluster_lock:
        _cluster_cleanup_expired_leases(now_ts)
        agents_raw = dict(cluster_agents)
        leases_raw = dict(cluster_leases)

    targets_meta = {}
    for target_id in leases_raw.keys():
        try:
            row = scan_db.select_target_by_id(int(target_id))
        except Exception:
            row = None
        if not row:
            continue
        targets_meta[int(target_id)] = {
            "network": str(row.get("network", "")).strip(),
            "proto": str(row.get("proto", "")).strip().lower(),
        }

    leases_by_agent = {}
    for target_id, lease in leases_raw.items():
        agent_id = str((lease or {}).get("agent_id", "")).strip()
        if not agent_id:
            continue
        lease_until = float((lease or {}).get("lease_until", 0.0) or 0.0)
        remaining = max(0, int(lease_until - now_ts))
        task_item = {
            "task_id": str((lease or {}).get("task_id", "")).strip(),
            "master_target_id": int(target_id),
            "lease_seconds_left": remaining,
            "network": targets_meta.get(int(target_id), {}).get("network", ""),
            "proto": targets_meta.get(int(target_id), {}).get("proto", ""),
        }
        leases_by_agent.setdefault(agent_id, []).append(task_item)

    datas = []
    summary = {
        "total_agents": 0,
        "online": 0,
        "stale": 0,
        "offline": 0,
        "active_tasks": 0,
    }
    for agent_id, meta in agents_raw.items():
        last_seen = float((meta or {}).get("last_seen", 0.0) or 0.0)
        age = max(0.0, now_ts - last_seen)
        status = _agent_status_from_age(age)
        tasks = sorted(
            leases_by_agent.get(str(agent_id), []),
            key=lambda item: (
                int((item or {}).get("lease_seconds_left", 0)),
                int((item or {}).get("master_target_id", 0)),
            ),
        )
        record = {
            "agent_id": str(agent_id),
            "status": status,
            "last_seen": last_seen,
            "last_seen_iso": utc_iso(int(last_seen)) if last_seen > 0 else "",
            "seconds_since_seen": round(age, 2),
            "certificate_cn": str((meta or {}).get("cn", "")).strip(),
            "auth_mode": str((meta or {}).get("auth_mode", "mtls") or "mtls").strip().lower(),
            "client": (meta or {}).get("client"),
            "active_tasks": tasks,
            "active_task_count": len(tasks),
        }
        datas.append(record)
        summary["total_agents"] += 1
        summary[status] = int(summary.get(status, 0) or 0) + 1
        summary["active_tasks"] += len(tasks)

    status_order = {"online": 0, "stale": 1, "offline": 2}
    datas.sort(
        key=lambda row: (
            status_order.get(str((row or {}).get("status", "")).strip().lower(), 9),
            -float((row or {}).get("last_seen", 0.0) or 0.0),
            str((row or {}).get("agent_id", "")),
        )
    )

    return {
        "generated_at": utc_iso(int(now_ts)),
        "summary": summary,
        "datas": datas,
    }


def build_ca_distribution_payload():
    pem_text = load_ca_pem_text(raise_if_missing=True)
    oneline = ca_pem_to_oneline(pem_text)
    export_command = f"export PORTHOUND_CA_ONELINE='{oneline}'"
    configured_path = str(getattr(settings, "PORTHOUND_CA", "") or "").strip()
    return {
        "generated_at": utc_iso(int(time.time())),
        "ca_path": configured_path,
        "ca_pem": pem_text,
        "ca_oneline": oneline,
        "export_command": export_command,
    }


def normalize_agent_result_payload(payload):
    if not isinstance(payload, dict):
        raise ValueError("Invalid payload")
    output = dict(payload)
    output["agent_id"] = str(output.get("agent_id", "")).strip()
    if not output["agent_id"]:
        raise ValueError("agent_id is required")
    output["task_id"] = str(output.get("task_id", "")).strip()
    if not output["task_id"]:
        raise ValueError("task_id is required")
    try:
        output["master_target_id"] = int(output.get("master_target_id"))
    except Exception:
        raise ValueError("master_target_id is required")
    result = output.get("result", {})
    if not isinstance(result, dict):
        raise ValueError("result must be an object")
    output["result"] = result
    return output


def _merge_agent_results(result_payload, agent_id=""):
    counters = {"ports": 0, "tags": 0, "banners": 0, "favicons": 0}

    for row in result_payload.get("ports", []) or []:
        try:
            scan_db.insert_port(
                data={
                    "ip": str(row.get("ip", "")).strip(),
                    "port": int(row.get("port", 0)),
                    "proto": str(row.get("proto", "")).strip().lower(),
                    "state": str(row.get("state", "open")).strip().lower(),
                }
            )
            counters["ports"] += 1
        except Exception:
            continue

    for row in result_payload.get("tags", []) or []:
        try:
            scan_db.insert_tags(
                data={
                    "ip": str(row.get("ip", "")).strip(),
                    "port": int(row.get("port", 0)),
                    "proto": str(row.get("proto", "")).strip().lower(),
                    "key": str(row.get("key", "")).strip()[:120],
                    "value": str(row.get("value", ""))[:4096],
                }
            )
            counters["tags"] += 1
        except Exception:
            continue

    for row in result_payload.get("banners", []) or []:
        try:
            plain = str(row.get("response_plain", "") or "")
            encoded = str(row.get("response_b64", "") or "").strip()
            if encoded:
                response_blob = base64.b64decode(encoded.encode("ascii"), validate=False)
            else:
                response_blob = plain.encode("utf-8", errors="ignore")
            scan_db.insert_banners(
                data={
                    "ip": str(row.get("ip", "")).strip(),
                    "port": int(row.get("port", 0)),
                    "proto": str(row.get("proto", "tcp")).strip().lower(),
                    "response": response_blob,
                    "response_plain": plain,
                }
            )
            counters["banners"] += 1
        except Exception:
            continue

    for row in result_payload.get("favicons", []) or []:
        try:
            blob_b64 = str(row.get("icon_blob_b64", "")).strip()
            if not blob_b64:
                continue
            icon_blob = base64.b64decode(blob_b64.encode("ascii"), validate=False)
            scan_db.insert_favicon(
                data={
                    "ip": str(row.get("ip", "")).strip(),
                    "port": int(row.get("port", 0)),
                    "proto": str(row.get("proto", "tcp")).strip().lower() or "tcp",
                    "icon_url": str(row.get("icon_url", "/favicon.ico")).strip() or "/favicon.ico",
                    "mime_type": str(row.get("mime_type", "application/octet-stream")).strip()
                    or "application/octet-stream",
                    "icon_blob": icon_blob,
                    "size": int(row.get("size", len(icon_blob)) or len(icon_blob)),
                    "sha256": str(row.get("sha256", "")).strip(),
                }
            )
            counters["favicons"] += 1
        except Exception:
            continue

    return counters


def normalize_target_item(item, require_id=False):
    if not isinstance(item, dict):
        raise ValueError("Invalid target body")
    output = dict(item)

    if require_id:
        try:
            output["id"] = int(output.get("id"))
        except Exception:
            raise ValueError("Invalid target id")

    network = str(output.get("network", "")).strip()
    if not REGEX_IPV4_CIDR.match(network):
        raise ValueError("Invalid CIDR format")
    try:
        network_obj = ip_network(network, strict=False)
    except Exception:
        raise ValueError("Invalid CIDR format")
    if not isinstance(network_obj.network_address, IPv4Address):
        raise ValueError("Only IPv4 CIDR is supported")
    output["network"] = str(network_obj)

    target_type = str(output.get("type", "")).strip().lower()
    if target_type not in TARGET_TYPES:
        raise ValueError("Invalid type. Use common, not_common or full")
    output["type"] = target_type

    proto = str(output.get("proto", "")).strip().lower()
    if proto == "stcp":
        proto = "sctp"
    if proto not in TARGET_PROTOS:
        allowed = ", ".join(sorted(TARGET_PROTOS))
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
    if target_status not in TARGET_STATUSES:
        allowed = ", ".join(sorted(TARGET_STATUSES))
        raise ValueError(f"Invalid status. Use {allowed}")
    output["status"] = target_status

    port_config = normalize_target_port_config(output, proto=proto)
    if port_config["port_mode"] not in TARGET_PORT_MODES:
        allowed = ", ".join(sorted(TARGET_PORT_MODES))
        raise ValueError(f"Invalid port_mode. Use {allowed}")
    output["port_mode"] = port_config["port_mode"]
    output["port_start"] = port_config["port_start"]
    output["port_end"] = port_config["port_end"]

    return output


def normalize_target_action(item):
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


def normalize_target_bulk_action(item):
    if not isinstance(item, dict):
        raise ValueError("Invalid target bulk action body")
    output = dict(item)

    action = str(output.get("action", "")).strip().lower()
    if action not in {"start", "restart", "stop"}:
        raise ValueError("Invalid action. Use start, restart or stop")
    output["action"] = action

    proto = str(output.get("proto", "")).strip().lower()
    if proto == "stcp":
        proto = "sctp"
    if not proto:
        raise ValueError("proto is required for bulk target actions")
    if proto not in TARGET_PROTOS:
        allowed = ", ".join(sorted(TARGET_PROTOS))
        raise ValueError(f"Invalid proto. Use {allowed}")
    output["proto"] = proto

    output["clean_results"] = bool(output.get("clean_results", True))
    return output


def normalize_port_action(item):
    if not isinstance(item, dict):
        raise ValueError("Invalid port action body")
    output = dict(item)

    try:
        output["id"] = int(output.get("id"))
    except Exception:
        raise ValueError("Invalid port id")

    action = str(output.get("action", "")).strip().lower()
    if action not in {"start", "restart", "stop"}:
        raise ValueError("Invalid action. Use start, restart or stop")
    output["action"] = action
    output["clean_results"] = bool(output.get("clean_results", True))
    return output


def target_proto_matches(current_value, expected_value):
    current = str(current_value or "").strip().lower()
    expected = str(expected_value or "").strip().lower()
    if expected == "sctp":
        return current in {"sctp", "stcp"}
    return current == expected


def apply_target_action(current_target, action, clean_results=True):
    if not current_target:
        return None
    target_id = int(current_target["id"])
    try:
        current_progress = float(current_target.get("progress", 0.0) or 0.0)
    except Exception:
        current_progress = 0.0

    if action == "start":
        if current_progress >= 100.0:
            scan_db.set_target_progress(data={"id": target_id, "progress": 0.0})
            scan_db.set_target_status(data={"id": target_id, "status": "restarting"})
        else:
            scan_db.set_target_status(data={"id": target_id, "status": "active"})
    elif action == "restart":
        if clean_results:
            scan_db.clear_target_artifacts(data={"id": target_id})
        scan_db.set_target_progress(data={"id": target_id, "progress": 0.0})
        scan_db.set_target_status(data={"id": target_id, "status": "restarting"})
    elif action == "stop":
        scan_db.set_target_status(data={"id": target_id, "status": "stopped"})
    elif action == "delete":
        scan_db.set_target_status(data={"id": target_id, "status": "stopped"})
        if clean_results:
            scan_db.clear_target_artifacts(data={"id": target_id})
        scan_db.delete_target(data={"id": target_id})
        return None
    else:
        raise ValueError("Unsupported target action")
    return scan_db.select_target_by_id(target_id)


def apply_port_action(current_port, action, clean_results=True):
    if not current_port:
        return None
    port_id = int(current_port["id"])
    try:
        current_progress = float(current_port.get("progress", 0.0) or 0.0)
    except Exception:
        current_progress = 0.0

    if action == "start":
        if current_progress >= 100.0:
            scan_db.ports_progress(data={"id": port_id, "progress": 0.0})
        scan_db.set_port_scan_state(data={"id": port_id, "scan_state": "active"})
    elif action == "restart":
        if clean_results:
            scan_db.clear_port_artifacts(data={"id": port_id})
        scan_db.ports_progress(data={"id": port_id, "progress": 0.0})
        scan_db.set_port_scan_state(data={"id": port_id, "scan_state": "active"})
    elif action == "stop":
        scan_db.set_port_scan_state(data={"id": port_id, "scan_state": "stopped"})
    else:
        raise ValueError("Unsupported port action")
    return scan_db.select_port_by_id(port_id)


def is_example(request):
    # Example/demo mode is disabled in the public UI/API.
    return False


def example_counts():
    return {
        "count_ports": len(EXAMPLE_PORTS),
        "count_banners": len(EXAMPLE_BANNERS),
        "count_targets": len(EXAMPLE_TARGETS),
    }


def build_dashboard(example=False):
    if example:
        targets = EXAMPLE_TARGETS
        ports_tcp = [p for p in EXAMPLE_PORTS if p["proto"] == "tcp"]
        ports_udp = [p for p in EXAMPLE_PORTS if p["proto"] == "udp"]
        ports_icmp = [p for p in EXAMPLE_PORTS if p["proto"] == "icmp"]
        ports_sctp = [p for p in EXAMPLE_PORTS if p["proto"] == "sctp"]
        banners = EXAMPLE_BANNERS
        tags = EXAMPLE_TAGS
        ws_clients = EXAMPLE_WS_CLIENTS
        counts = example_counts()
        attacks_feed = EXAMPLE_ATTACK_EVENTS[-20:]
        attacks_summary = EXAMPLE_ATTACK_SUMMARY
        cluster_snapshot = {
            "generated_at": utc_iso(int(time.time())),
            "summary": {
                "total_agents": 0,
                "online": 0,
                "stale": 0,
                "offline": 0,
                "active_tasks": 0,
            },
            "datas": [],
        }
    else:
        targets = scan_db.select_targets()
        ports_tcp = scan_db.select_ports_where_tcp()
        ports_udp = scan_db.select_ports_where_udp()
        ports_icmp = scan_db.select_ports_where_icmp()
        ports_sctp = scan_db.select_ports_where_sctp()
        banners = scan_db.select_banners()
        tags = scan_db.select_tags()
        ws_clients = registry.list_clients_info()
        counts = {
            "count_ports": scan_db.count_ports(),
            "count_banners": scan_db.count_banners(),
            "count_targets": scan_db.count_targets(),
        }
        attacks_feed = attack_telemetry.latest(20)
        attacks_summary = attack_telemetry.summary()
        cluster_snapshot = build_cluster_agents_snapshot()
    return {
        "counts": counts,
        "targets": targets,
        "ports": {
            "tcp": ports_tcp,
            "udp": ports_udp,
            "icmp": ports_icmp,
            "sctp": ports_sctp,
        },
        "banners": banners,
        "tags": tags,
        "ws_clients": ws_clients,
        "attacks": {
            "feed": attacks_feed,
            "summary": attacks_summary,
        },
        "cluster": cluster_snapshot,
    }


def _safe_float_value(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return float(default)


def _extract_day_key(raw_timestamp):
    text = str(raw_timestamp or "").strip()
    if len(text) >= 10 and text[4] == "-" and text[7] == "-":
        return text[:10]
    return ""


def _counter_to_series(counter_obj, limit=0):
    entries = [
        (str(key), int(value))
        for key, value in dict(counter_obj or {}).items()
        if str(key).strip() and int(value or 0) > 0
    ]
    entries.sort(key=lambda item: (-int(item[1]), str(item[0])))
    if int(limit or 0) > 0:
        entries = entries[: int(limit)]
    return [{"label": key, "value": value} for key, value in entries]


def build_chart_analytics(example=False):
    if example:
        targets = list(EXAMPLE_TARGETS)
        ports = list(EXAMPLE_PORTS)
        banners = list(EXAMPLE_BANNERS)
        tags = list(EXAMPLE_TAGS)
        favicons = list(EXAMPLE_FAVICONS)
    else:
        targets = scan_db.select_targets()
        ports = scan_db.select_ports()
        banners = scan_db.select_banners()
        tags = scan_db.select_tags()
        favicons = scan_db.select_favicons()

    unique_hosts = set()
    port_proto_counter = Counter()
    port_state_by_proto = {}
    open_ports_counter = Counter()
    open_ip_counter = Counter()
    risk_port_counter = Counter()
    day_ports_counter = Counter()
    day_targets_counter = Counter()
    open_ports_total = 0
    filtered_ports_total = 0

    risky_ports = {
        20,
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        111,
        135,
        139,
        143,
        389,
        443,
        445,
        1433,
        1521,
        3306,
        3389,
        5432,
        5900,
        6379,
        8080,
        9200,
    }

    for row in ports:
        proto = str((row or {}).get("proto", "") or "unknown").strip().lower() or "unknown"
        state = str((row or {}).get("state", "") or "unknown").strip().lower() or "unknown"
        ip_value = str((row or {}).get("ip", "") or "").strip()
        if ip_value:
            unique_hosts.add(ip_value)
        port_proto_counter[proto] += 1
        bucket = port_state_by_proto.setdefault(
            proto,
            {"proto": proto, "open": 0, "filtered": 0, "other": 0},
        )
        if state == "open":
            bucket["open"] += 1
            open_ports_total += 1
            try:
                port_number = int((row or {}).get("port", 0) or 0)
            except Exception:
                port_number = 0
            if port_number > 0:
                open_ports_counter[str(port_number)] += 1
                if ip_value:
                    open_ip_counter[ip_value] += 1
                if port_number in risky_ports:
                    risk_port_counter[str(port_number)] += 1
        elif state == "filtered":
            bucket["filtered"] += 1
            filtered_ports_total += 1
        else:
            bucket["other"] += 1

        day_key = _extract_day_key((row or {}).get("created_at"))
        if day_key:
            day_ports_counter[day_key] += 1

    target_status_counter = Counter()
    target_type_counter = Counter()
    target_proto_counter = Counter()
    target_progress_buckets = {
        "0-24": 0,
        "25-49": 0,
        "50-74": 0,
        "75-99": 0,
        "100": 0,
    }
    for row in targets:
        status = str((row or {}).get("status", "") or "active").strip().lower() or "active"
        target_type = str((row or {}).get("type", "") or "common").strip().lower() or "common"
        target_proto = str((row or {}).get("proto", "") or "tcp").strip().lower() or "tcp"
        target_status_counter[status] += 1
        target_type_counter[target_type] += 1
        target_proto_counter[target_proto] += 1

        progress = _safe_float_value((row or {}).get("progress"), default=0.0)
        if progress >= 100.0:
            target_progress_buckets["100"] += 1
        elif progress >= 75.0:
            target_progress_buckets["75-99"] += 1
        elif progress >= 50.0:
            target_progress_buckets["50-74"] += 1
        elif progress >= 25.0:
            target_progress_buckets["25-49"] += 1
        else:
            target_progress_buckets["0-24"] += 1

        day_key = _extract_day_key((row or {}).get("created_at"))
        if day_key:
            day_targets_counter[day_key] += 1

    banner_proto_counter = Counter()
    banner_length_buckets = {
        "0-64": 0,
        "65-128": 0,
        "129-256": 0,
        "257-512": 0,
        "513+": 0,
    }
    day_banners_counter = Counter()
    for row in banners:
        proto = str((row or {}).get("proto", "") or "unknown").strip().lower() or "unknown"
        banner_proto_counter[proto] += 1
        plain = str((row or {}).get("response_plain", "") or "")
        length = len(plain)
        if length <= 64:
            banner_length_buckets["0-64"] += 1
        elif length <= 128:
            banner_length_buckets["65-128"] += 1
        elif length <= 256:
            banner_length_buckets["129-256"] += 1
        elif length <= 512:
            banner_length_buckets["257-512"] += 1
        else:
            banner_length_buckets["513+"] += 1
        day_key = _extract_day_key((row or {}).get("created_at"))
        if day_key:
            day_banners_counter[day_key] += 1

    tag_key_counter = Counter()
    tag_service_value_counter = Counter()
    for row in tags:
        key = str((row or {}).get("key", "") or "").strip().lower()
        value = str((row or {}).get("value", "") or "").strip()
        if not key:
            continue
        tag_key_counter[key] += 1
        if key in {"service", "product", "server", "vendor", "framework", "runtime"} and value:
            normalized = value if len(value) <= 60 else f"{value[:57]}..."
            tag_service_value_counter[normalized] += 1

    all_days = sorted(
        set(day_ports_counter.keys())
        | set(day_banners_counter.keys())
        | set(day_targets_counter.keys())
    )
    if len(all_days) > 30:
        all_days = all_days[-30:]
    timeline = [
        {
            "day": day_value,
            "ports": int(day_ports_counter.get(day_value, 0)),
            "banners": int(day_banners_counter.get(day_value, 0)),
            "targets": int(day_targets_counter.get(day_value, 0)),
        }
        for day_value in all_days
    ]

    ports_state_matrix = sorted(
        list(port_state_by_proto.values()),
        key=lambda item: str((item or {}).get("proto", "")),
    )

    return {
        "generated_at": utc_iso(int(time.time())),
        "summary": {
            "targets": len(targets),
            "ports": len(ports),
            "banners": len(banners),
            "tags": len(tags),
            "favicons": len(favicons),
            "unique_hosts": len(unique_hosts),
            "open_ports": int(open_ports_total),
            "filtered_ports": int(filtered_ports_total),
        },
        "ports_by_proto": _counter_to_series(port_proto_counter),
        "ports_state_by_proto": ports_state_matrix,
        "top_open_ports": _counter_to_series(open_ports_counter, limit=12),
        "top_ips_by_open_ports": _counter_to_series(open_ip_counter, limit=12),
        "risk_ports": _counter_to_series(risk_port_counter, limit=12),
        "targets_by_status": _counter_to_series(target_status_counter),
        "targets_by_type": _counter_to_series(target_type_counter),
        "targets_by_proto": _counter_to_series(target_proto_counter),
        "target_progress_buckets": [
            {"label": label, "value": int(target_progress_buckets.get(label, 0))}
            for label in ["0-24", "25-49", "50-74", "75-99", "100"]
        ],
        "banners_by_proto": _counter_to_series(banner_proto_counter),
        "banner_length_buckets": [
            {"label": label, "value": int(banner_length_buckets.get(label, 0))}
            for label in ["0-64", "65-128", "129-256", "257-512", "513+"]
        ],
        "top_tag_keys": _counter_to_series(tag_key_counter, limit=10),
        "top_service_signatures": _counter_to_series(tag_service_value_counter, limit=10),
        "timeline": timeline,
    }


@app.view("/")
def root_view(request):
    if is_example(request):
        return Response.json(example_counts())
    if wants_html(request):
        return frontend_index_response()
    data = {
        "count_ports": scan_db.count_ports(),
        "count_banners": scan_db.count_banners(),
        "count_targets": scan_db.count_targets(),
    }
    return Response.json(data)


def spa_shell_view(request):
    return frontend_index_response()


for _spa_path in SPA_ROUTES:
    app.view(_spa_path)(spa_shell_view)


@app.view("/attacks/raw/")
def attacks_raw_view(request):
    return Response.html(RAW_ATTACK_HTML)


@app.view("/cluster/agents/")
def cluster_agents_view(request):
    if not is_master_role():
        return Response.text("Only master role exposes cluster view", status=403)
    admin_error = require_admin_access(request)
    if admin_error:
        return admin_error
    return Response.html(CLUSTER_AGENTS_HTML)


@app.api("/protocols/", methods=["GET"])
def list_protocols(request):
    return {"datas": sorted(TARGET_PROTOS)}


@app.api("/count/targets/", methods=["GET"])
def count_targets(request):
    if is_example(request):
        return {"count": len(EXAMPLE_TARGETS)}
    return {"count": scan_db.count_targets()}


@app.api("/count/ports/", methods=["GET"])
def count_ports(request):
    if is_example(request):
        return {"count": len(EXAMPLE_PORTS)}
    return {"count": scan_db.count_ports()}


@app.api("/count/ports/udp/", methods=["GET"])
def count_ports_udp(request):
    if is_example(request):
        return {"count": len([p for p in EXAMPLE_PORTS if p["proto"] == "udp"])}
    return {"count": scan_db.count_ports_where_udp()}


@app.api("/count/ports/tcp/", methods=["GET"])
def count_ports_tcp(request):
    if is_example(request):
        return {"count": len([p for p in EXAMPLE_PORTS if p["proto"] == "tcp"])}
    return {"count": scan_db.count_ports_where_tcp()}


@app.api("/count/ports/icmp/", methods=["GET"])
def count_ports_icmp(request):
    if is_example(request):
        return {"count": len([p for p in EXAMPLE_PORTS if p["proto"] == "icmp"])}
    return {"count": scan_db.count_ports_where_icmp()}


@app.api("/count/ports/sctp/", methods=["GET"])
def count_ports_sctp(request):
    if is_example(request):
        return {"count": len([p for p in EXAMPLE_PORTS if p["proto"] == "sctp"])}
    return {"count": scan_db.count_ports_where_sctp()}


@app.api("/count/ports/stcp/", methods=["GET"])
def count_ports_stcp_alias(request):
    return count_ports_sctp(request)


@app.api("/count/banners/", methods=["GET"])
def count_banners(request):
    if is_example(request):
        return {"count": len(EXAMPLE_BANNERS)}
    return {"count": scan_db.count_banners()}


@app.api("/targets/", methods=["GET"])
def list_targets(request):
    if is_example(request):
        return {"datas": EXAMPLE_TARGETS}
    return {"datas": scan_db.select_targets()}


@app.api("/target/", methods=["POST", "PUT", "DELETE"])
def target_handler(request):
    try:
        admin_error = require_admin_access(request)
        if admin_error:
            return admin_error
        item = request.json() or {}
        if is_example(request):
            if request.method == "POST":
                return {**EXAMPLE_TARGETS[0], "example": True}
            if request.method == "PUT":
                return {**EXAMPLE_TARGETS[0], "example": True}
            if request.method == "DELETE":
                return {"status": "200", "example": True}
        if request.method == "POST":
            item = normalize_target_item(item)
            scan_db.insert_targets(data=item)
            return item
        if request.method == "PUT":
            item = normalize_target_item(item, require_id=True)
            scan_db.update_targets(data=item)
            return item
        if request.method == "DELETE":
            item["id"] = int(item["id"])
            scan_db.delete_target(data=item)
            return item
        return json_error("Method not allowed", status=405)
    except Exception as e:
        return json_error(e, status=500)


@app.api("/target/action/", methods=["POST"])
def target_action_handler(request):
    try:
        admin_error = require_admin_access(request)
        if admin_error:
            return admin_error
        item = normalize_target_action(request.json() or {})
        if is_example(request):
            return {
                "status": "200",
                "example": True,
                "action": item["action"],
                "id": item["id"],
            }

        current_target = scan_db.select_target_by_id(item["id"])
        if not current_target:
            return json_error("Target not found", status=404)

        action = item["action"]
        clean_results = bool(item.get("clean_results", True))
        updated_target = apply_target_action(current_target, action, clean_results=clean_results)
        return {
            "status": "200",
            "action": action,
            "id": int(item["id"]),
            "target": updated_target,
        }
    except ValueError as e:
        return json_error(e, status=400)
    except Exception as e:
        return json_error(e, status=500)


@app.api("/target/action/bulk/", methods=["POST"])
def target_bulk_action_handler(request):
    try:
        admin_error = require_admin_access(request)
        if admin_error:
            return admin_error
        item = normalize_target_bulk_action(request.json() or {})
        if is_example(request):
            return {
                "status": "200",
                "example": True,
                "action": item["action"],
                "proto": item["proto"],
                "affected": 0,
                "targets": [],
            }

        proto = item["proto"]
        action = item["action"]
        clean_results = bool(item.get("clean_results", True))
        matching_targets = [
            row
            for row in scan_db.select_targets()
            if target_proto_matches((row or {}).get("proto"), proto)
        ]
        if not matching_targets:
            return json_error(f"No targets found for proto {proto}", status=404)

        updated_targets = []
        for row in matching_targets:
            updated = apply_target_action(row, action, clean_results=clean_results)
            if updated:
                updated_targets.append(updated)

        return {
            "status": "200",
            "action": action,
            "proto": proto,
            "affected": len(matching_targets),
            "targets": updated_targets,
        }
    except ValueError as e:
        return json_error(e, status=400)
    except Exception as e:
        return json_error(e, status=500)


@app.api("/port/action/", methods=["POST"])
def port_action_handler(request):
    try:
        admin_error = require_admin_access(request)
        if admin_error:
            return admin_error
        item = normalize_port_action(request.json() or {})
        if is_example(request):
            return {
                "status": "200",
                "example": True,
                "action": item["action"],
                "id": item["id"],
            }

        current_port = scan_db.select_port_by_id(item["id"])
        if not current_port:
            return json_error("Port endpoint not found", status=404)

        updated_port = apply_port_action(
            current_port,
            item["action"],
            clean_results=bool(item.get("clean_results", True)),
        )
        return {
            "status": "200",
            "action": item["action"],
            "id": int(item["id"]),
            "port": updated_port,
        }
    except ValueError as e:
        return json_error(e, status=400)
    except Exception as e:
        return json_error(e, status=500)


@app.api("/banner/action/", methods=["POST"])
def banner_action_handler(request):
    return port_action_handler(request)


@app.api("/ports/", methods=["GET"])
def list_ports(request):
    if is_example(request):
        return {"datas": EXAMPLE_PORTS}
    return {"datas": scan_db.select_ports()}


@app.api("/ports/udp/", methods=["GET", "DELETE"])
def list_ports_udp(request):
    if is_example(request):
        if request.method == "GET":
            return {"datas": [p for p in EXAMPLE_PORTS if p["proto"] == "udp"]}
        return {"status": "200", "example": True}
    if request.method == "GET":
        return {"datas": scan_db.select_ports_where_udp()}
    admin_error = require_admin_access(request)
    if admin_error:
        return admin_error
    scan_db.delete_ports_where_udp()
    return {"status": "200"}


@app.api("/ports/tcp/", methods=["GET", "DELETE"])
def list_ports_tcp(request):
    if is_example(request):
        if request.method == "GET":
            return {"datas": [p for p in EXAMPLE_PORTS if p["proto"] == "tcp"]}
        return {"status": "200", "example": True}
    if request.method == "GET":
        return {"datas": scan_db.select_ports_where_tcp()}
    admin_error = require_admin_access(request)
    if admin_error:
        return admin_error
    scan_db.delete_ports_where_tcp()
    return {"status": "200"}


@app.api("/ports/icmp/", methods=["GET", "DELETE"])
def list_ports_icmp(request):
    if is_example(request):
        if request.method == "GET":
            return {"datas": [p for p in EXAMPLE_PORTS if p["proto"] == "icmp"]}
        return {"status": "200", "example": True}
    if request.method == "GET":
        return {"datas": scan_db.select_ports_where_icmp()}
    admin_error = require_admin_access(request)
    if admin_error:
        return admin_error
    scan_db.delete_ports_where_icmp()
    return {"status": "200"}


@app.api("/ports/sctp/", methods=["GET", "DELETE"])
def list_ports_sctp(request):
    if is_example(request):
        if request.method == "GET":
            return {"datas": [p for p in EXAMPLE_PORTS if p["proto"] == "sctp"]}
        return {"status": "200", "example": True}
    if request.method == "GET":
        return {"datas": scan_db.select_ports_where_sctp()}
    admin_error = require_admin_access(request)
    if admin_error:
        return admin_error
    scan_db.delete_ports_where_sctp()
    return {"status": "200"}


@app.api("/ports/stcp/", methods=["GET", "DELETE"])
def list_ports_stcp_alias(request):
    return list_ports_sctp(request)


@app.api("/tags/", methods=["GET"])
def list_tags(request):
    if is_example(request):
        return {"datas": EXAMPLE_TAGS}
    return {"datas": scan_db.select_tags()}


@app.api("/tags/tcp/", methods=["GET"])
def list_tags_tcp(request):
    if is_example(request):
        return {"datas": [t for t in EXAMPLE_TAGS if t["proto"] == "tcp"]}
    return {"datas": scan_db.select_tags_tcp()}


@app.api("/tags/udp/", methods=["GET"])
def list_tags_udp(request):
    if is_example(request):
        return {"datas": [t for t in EXAMPLE_TAGS if t["proto"] == "udp"]}
    return {"datas": scan_db.select_tags_udp()}


@app.api("/tags/icmp/", methods=["GET"])
def list_tags_icmp(request):
    if is_example(request):
        return {"datas": [t for t in EXAMPLE_TAGS if t["proto"] == "icmp"]}
    return {"datas": scan_db.select_tags_icmp()}


@app.api("/tags/sctp/", methods=["GET"])
def list_tags_sctp(request):
    if is_example(request):
        return {"datas": [t for t in EXAMPLE_TAGS if t["proto"] == "sctp"]}
    return {"datas": scan_db.select_tags_sctp()}


@app.api("/tags/stcp/", methods=["GET"])
def list_tags_stcp_alias(request):
    return list_tags_sctp(request)


@app.api("/banners/", methods=["GET", "DELETE"])
def list_banners(request):
    if is_example(request):
        if request.method == "GET":
            return {"datas": EXAMPLE_BANNERS}
        return {"status": "200", "example": True}
    if request.method == "GET":
        return {"datas": scan_db.select_banners()}
    admin_error = require_admin_access(request)
    if admin_error:
        return admin_error
    scan_db.delete_banners()
    return {"status": "200"}


@app.api("/favicons/", methods=["GET", "DELETE"])
def list_favicons(request):
    if is_example(request):
        if request.method == "GET":
            return {"datas": EXAMPLE_FAVICONS}
        return {"status": "200", "example": True}
    if request.method == "GET":
        return {"datas": scan_db.select_favicons()}
    admin_error = require_admin_access(request)
    if admin_error:
        return admin_error
    scan_db.delete_favicons()
    return {"status": "200"}


@app.view("/favicons/raw/", methods=["GET"])
def view_favicon_raw(request):
    if is_example(request):
        icon_id = clamp_int(request.query.get("id", 0), 0, 0, 10_000_000)
        if icon_id != EXAMPLE_FAVICONS[0]["id"]:
            return Response.text("Not Found", status=404)
        return Response(
            status=200,
            body=EXAMPLE_FAVICON_BYTES,
            headers={
                "Content-Type": "image/gif",
                "Cache-Control": "public, max-age=60",
            },
        )

    icon_id = clamp_int(request.query.get("id", 0), 0, 0, 10_000_000)
    if icon_id <= 0:
        return Response.text("Invalid id", status=400)
    row = scan_db.get_favicon_by_id(icon_id)
    if not row:
        return Response.text("Not Found", status=404)
    body = row.get("icon_blob") or b""
    return Response(
        status=200,
        body=body,
        headers={
            "Content-Type": row.get("mime_type") or "application/octet-stream",
            "Cache-Control": "public, max-age=300",
        },
    )


def parse_ip_intel_request(request):
    ip_value = normalize_ipv4_input(request.query.get("ip", ""))
    refresh = clamp_int(request.query.get("refresh", 0), 0, 0, 1) == 1
    return ip_value, refresh


def build_example_ip_intel_payload(ip_value):
    sample_domain = f"host-{ip_value.replace('.', '-')}.example.local"
    return {
        "ip": ip_value,
        "cached": False,
        "generated_at": utc_iso(int(time.time())),
        "domains": {
            "ip": ip_value,
            "domains": [sample_domain, f"www.{sample_domain}"],
            "sources": {
                "reverse_dns": {
                    "domains": [sample_domain],
                    "reverse_host": sample_domain,
                    "aliases": [],
                    "error": "",
                },
                "tls_certificate": {
                    "domains": [sample_domain, f"www.{sample_domain}"],
                    "ports": [443],
                    "errors": [],
                },
            },
        },
        "ttl_path": {
            "method": "socket_traceroute",
            "available": True,
            "reached": True,
            "hops_to_target": 9,
            "devices_in_path": 8,
            "route": [
                {"hop": 1, "ip": "192.168.1.1", "resolved": True, "rtt_ms": 1.2},
                {"hop": 2, "ip": "10.10.0.1", "resolved": True, "rtt_ms": 3.4},
                {"hop": 3, "ip": ip_value, "resolved": True, "rtt_ms": 18.8},
            ],
            "raw": "",
            "error": "",
            "initial_ttl_guess": 64,
        },
        "host_profile": {
            "target": {
                "ip": ip_value,
                "ip_version": 4,
                "scope": "public",
                "geo": {
                    "found": True,
                    "cidr": "203.0.113.0/24",
                    "rir": "ARIN",
                    "area": "North America",
                    "country": "US",
                    "lat": 38.9072,
                    "lon": -77.0369,
                },
            },
            "transport": {
                "protocols": ["tcp"],
                "open_port_count": 3,
                "filtered_port_count": 1,
                "open_ports": [22, 80, 443],
                "filtered_ports": [25],
                "services": [
                    {
                        "ip": ip_value,
                        "port": 22,
                        "proto": "tcp",
                        "state": "open",
                        "service": ["ssh"],
                        "product": ["openssh"],
                        "server": ["OpenSSH"],
                        "version": ["9.6"],
                        "runtime": [],
                        "framework": [],
                        "vendor": ["openbsd"],
                        "protocol": ["SSH"],
                        "protocol_version": [],
                        "http_status": [],
                        "auth_scheme": [],
                        "realm": [],
                        "powered_by": [],
                        "server_header": [],
                        "time_ms": {"count": 1, "min": 8.4, "max": 8.4, "avg": 8.4, "stddev": 0.0, "jitter": 0.0},
                        "tag_count": 4,
                        "tag_samples": ["service=ssh", "product=openssh"],
                        "banner_preview": "SSH-2.0-OpenSSH_9.6",
                        "banner_updated_at": utc_iso(int(time.time())),
                        "favicon": None,
                    },
                    {
                        "ip": ip_value,
                        "port": 443,
                        "proto": "tcp",
                        "state": "open",
                        "service": ["https"],
                        "product": ["nginx"],
                        "server": ["Nginx"],
                        "version": ["1.25.5"],
                        "runtime": [],
                        "framework": [],
                        "vendor": ["nginx"],
                        "protocol": ["HTTP"],
                        "protocol_version": ["HTTP/1.1"],
                        "http_status": ["200"],
                        "auth_scheme": [],
                        "realm": [],
                        "powered_by": [],
                        "server_header": ["nginx/1.25.5"],
                        "time_ms": {"count": 1, "min": 21.3, "max": 21.3, "avg": 21.3, "stddev": 0.0, "jitter": 0.0},
                        "tag_count": 6,
                        "tag_samples": ["service=https", "product=nginx"],
                        "banner_preview": "HTTP/1.1 200 OK Server: nginx/1.25.5",
                        "banner_updated_at": utc_iso(int(time.time())),
                        "favicon": {"id": 1, "mime_type": "image/x-icon", "size": 5430, "sha256": "example", "icon_url": "/favicon.ico"},
                    },
                ],
                "firewall": {
                    "status": "mixed_filtering",
                    "filtered_ratio": 0.25,
                    "summary": "Mixed open and filtered exposure suggests selective packet filtering.",
                    "evidence": ["open=3", "filtered=1", "total_observed=4"],
                },
            },
            "application": {
                "http": {
                    "ports": [80, 443],
                    "methods": ["GET", "HEAD", "OPTIONS"],
                    "server_headers": ["nginx/1.25.5"],
                    "status_codes": [200, 301],
                    "auth_schemes": [],
                    "redirects": [f"https://{sample_domain}/"],
                    "titles": ["Example Portal"],
                    "timing_ms": {"count": 2, "min": 18.3, "max": 24.9, "avg": 21.6, "stddev": 3.3, "jitter": 6.6},
                    "responses": [],
                    "errors": [],
                },
                "tls": {
                    "available": True,
                    "ports": [443],
                    "versions": ["TLSv1.3"],
                    "ciphers": ["TLS_AES_256_GCM_SHA384"],
                    "certificate_domains": [sample_domain, f"www.{sample_domain}"],
                    "handshake_ms": {"count": 1, "min": 32.1, "max": 32.1, "avg": 32.1, "stddev": 0.0, "jitter": 0.0},
                    "certificates": [
                        {
                            "port": 443,
                            "sni": sample_domain,
                            "tls_version": "TLSv1.3",
                            "cipher": "TLS_AES_256_GCM_SHA384",
                            "handshake_ms": 32.1,
                            "subject_cn": sample_domain,
                            "subject_org": "Example Corp",
                            "issuer_cn": "Example Issuing CA",
                            "issuer_org": "Example PKI",
                            "san_dns": [sample_domain, f"www.{sample_domain}"],
                            "not_before": "2026-01-01T00:00:00Z",
                            "not_after": "2026-12-31T23:59:59Z",
                            "days_remaining": 300,
                            "serial_number": "01A2B3C4",
                        }
                    ],
                    "errors": [],
                },
                "fingerprint": {
                    "services": ["https", "ssh"],
                    "products": ["nginx", "openssh"],
                    "servers": ["Nginx", "OpenSSH"],
                    "vendors": ["nginx", "openbsd"],
                    "frameworks": [],
                    "runtimes": [],
                    "versions": ["1.25.5", "9.6"],
                    "protocols": ["HTTP", "SSH"],
                    "ttl_os_hint": {
                        "initial_ttl_guess": 64,
                        "label": "unix-like",
                        "description": "Typical of Linux, BSD and many embedded stacks.",
                    },
                },
            },
            "metrics": {
                "scan_time_ms": {"count": 2, "min": 8.4, "max": 21.3, "avg": 14.85, "stddev": 6.45, "jitter": 12.9},
                "route_rtt_ms": {"count": 3, "min": 1.2, "max": 18.8, "avg": 7.8, "stddev": 7.76, "jitter": 8.8},
                "application_response_ms": {"count": 3, "min": 18.3, "max": 32.1, "avg": 24.43, "stddev": 5.73, "jitter": 10.2},
                "timeout_ratio": 0.25,
                "banner_count": 2,
                "favicon_count": 1,
                "domain_count": 2,
                "service_count": 2,
                "hops_to_target": 9,
            },
            "notes": [
                "Traceroute raw socket mode requires root/CAP_NET_RAW; TCP fallback was used when possible."
            ],
        },
    }


@app.api("/api/ip/domains/", methods=["GET"])
def api_ip_domains(request):
    try:
        ip_value, refresh = parse_ip_intel_request(request)
        if is_example(request):
            example_payload = build_example_ip_intel_payload(ip_value)
            return {
                "ip": ip_value,
                "cached": False,
                "domains": example_payload["domains"],
                "generated_at": example_payload["generated_at"],
            }
        intel = build_ip_intel(ip_value=ip_value, force_refresh=refresh)
        return {
            "ip": intel.get("ip"),
            "cached": bool(intel.get("cached")),
            "domains": intel.get("domains", {}),
            "generated_at": intel.get("generated_at"),
        }
    except ValueError as exc:
        return json_error(exc, status=400)
    except Exception as exc:
        return json_error(exc, status=500)


@app.api("/api/ip/ttl-path/", methods=["GET"])
def api_ip_ttl_path(request):
    try:
        ip_value, refresh = parse_ip_intel_request(request)
        if is_example(request):
            return {
                "ip": ip_value,
                "cached": False,
                "ttl_path": {
                    "method": "traceroute",
                    "available": True,
                    "reached": True,
                    "hops_to_target": 9,
                    "devices_in_path": 8,
                    "route": [
                        {"hop": 1, "ip": "192.168.1.1", "resolved": True},
                        {"hop": 2, "ip": "10.10.0.1", "resolved": True},
                        {"hop": 3, "ip": ip_value, "resolved": True},
                    ],
                    "raw": "",
                    "error": "",
                },
                "generated_at": utc_iso(int(time.time())),
            }
        intel = build_ip_intel(ip_value=ip_value, force_refresh=refresh)
        return {
            "ip": intel.get("ip"),
            "cached": bool(intel.get("cached")),
            "ttl_path": intel.get("ttl_path", {}),
            "generated_at": intel.get("generated_at"),
        }
    except ValueError as exc:
        return json_error(exc, status=400)
    except Exception as exc:
        return json_error(exc, status=500)


@app.api("/api/ip/intel/", methods=["GET"])
def api_ip_intel(request):
    try:
        ip_value, refresh = parse_ip_intel_request(request)
        if is_example(request):
            return build_example_ip_intel_payload(ip_value)
        return build_ip_intel(ip_value=ip_value, force_refresh=refresh)
    except ValueError as exc:
        return json_error(exc, status=400)
    except Exception as exc:
        return json_error(exc, status=500)


@app.api("/api/dashboard/", methods=["GET"])
def api_dashboard(request):
    return build_dashboard(example=is_example(request))


@app.api("/api/charts/analytics", methods=["GET"])
def api_charts_analytics(request):
    try:
        return build_chart_analytics(example=is_example(request))
    except Exception as exc:
        return json_error(exc, status=500)


@app.api("/api/endpoints/", methods=["GET"])
def api_endpoints(request):
    return {"datas": API_ENDPOINTS}


def _catalog_exception_response(exc):
    if isinstance(exc, PermissionError):
        return json_error(exc, status=403)
    if isinstance(exc, sqlite3.IntegrityError):
        return json_error("Duplicate value", status=409)
    if isinstance(exc, ValueError):
        message = str(exc)
        if "not found" in message.lower():
            return json_error(message, status=404)
        return json_error(message, status=400)
    return json_error(exc, status=500)


@app.api("/api/catalog/banner-rules/", methods=["GET", "POST", "PUT", "DELETE"])
def api_catalog_banner_rules(request):
    try:
        if request.method == "GET":
            include_inactive = request.query.get("include_inactive", "1")
            include_inactive = bool(str(include_inactive).strip() not in {"0", "false", "no"})
            return {"datas": scan_db.select_banner_regex_rules(include_inactive=include_inactive)}

        admin_error = require_admin_access(request)
        if admin_error:
            return admin_error
        payload = request.json() or {}
        if request.method == "POST":
            row = scan_db.insert_banner_regex_rule(payload)
            return {"status": "ok", "data": row}
        if request.method == "PUT":
            row = scan_db.update_banner_regex_rule(payload)
            return {"status": "ok", "data": row}
        if request.method == "DELETE":
            scan_db.delete_banner_regex_rule(payload)
            return {"status": "ok"}
        return json_error("Method not allowed", status=405)
    except Exception as exc:
        return _catalog_exception_response(exc)


@app.api("/api/catalog/banner-requests/", methods=["GET", "POST", "PUT", "DELETE"])
def api_catalog_banner_requests(request):
    try:
        if request.method == "GET":
            include_inactive = request.query.get("include_inactive", "1")
            include_inactive = bool(str(include_inactive).strip() not in {"0", "false", "no"})
            proto = str(request.query.get("proto", "") or "").strip().lower()
            return {
                "datas": scan_db.select_banner_probe_requests(
                    proto=proto,
                    include_inactive=include_inactive,
                )
            }

        admin_error = require_admin_access(request)
        if admin_error:
            return admin_error
        payload = request.json() or {}
        if request.method == "POST":
            row = scan_db.insert_banner_probe_request(payload)
            return {"status": "ok", "data": row}
        if request.method == "PUT":
            row = scan_db.update_banner_probe_request(payload)
            return {"status": "ok", "data": row}
        if request.method == "DELETE":
            scan_db.delete_banner_probe_request(payload)
            return {"status": "ok"}
        return json_error("Method not allowed", status=405)
    except Exception as exc:
        return _catalog_exception_response(exc)


@app.api("/api/catalog/ip-presets/", methods=["GET", "POST", "PUT", "DELETE"])
def api_catalog_ip_presets(request):
    try:
        if request.method == "GET":
            include_inactive = request.query.get("include_inactive", "1")
            include_inactive = bool(str(include_inactive).strip() not in {"0", "false", "no"})
            return {"datas": scan_db.select_ip_presets(include_inactive=include_inactive)}

        admin_error = require_admin_access(request)
        if admin_error:
            return admin_error
        payload = request.json() or {}
        if request.method == "POST":
            row = scan_db.insert_ip_preset(payload)
            return {"status": "ok", "data": row}
        if request.method == "PUT":
            row = scan_db.update_ip_preset(payload)
            return {"status": "ok", "data": row}
        if request.method == "DELETE":
            scan_db.delete_ip_preset(payload)
            return {"status": "ok"}
        return json_error("Method not allowed", status=405)
    except Exception as exc:
        return _catalog_exception_response(exc)


@app.api("/api/map/scan", methods=["GET"])
def api_map_scan(request):
    limit = clamp_int(request.query.get("limit", 300), 300, 1, 2000)
    return {"data": build_scan_map_snapshot(limit_hosts=limit)}


@app.api("/api/attacks/feed", methods=["GET"])
def api_attacks_feed(request):
    limit = clamp_int(request.query.get("limit", 40), 40, 1, 250)
    if is_example(request):
        return {
            "datas": EXAMPLE_ATTACK_EVENTS[-limit:],
            "summary": summarize_attacks(EXAMPLE_ATTACK_EVENTS[-limit:]),
            "simulator": {"running": False, "mode": "example"},
        }
    return {
        "datas": attack_telemetry.latest(limit),
        "summary": attack_telemetry.summary(),
        "simulator": attack_telemetry.status(),
    }


@app.api("/api/attacks/summary", methods=["GET"])
def api_attacks_summary(request):
    if is_example(request):
        return {
            "summary": EXAMPLE_ATTACK_SUMMARY,
            "simulator": {"running": False, "mode": "example"},
        }
    return {
        "summary": attack_telemetry.summary(),
        "simulator": attack_telemetry.status(),
    }


@app.api("/api/attacks/simulate", methods=["POST"])
def api_attacks_simulate(request):
    admin_error = require_admin_access(request)
    if admin_error:
        return admin_error
    payload = request.json() or {}
    if is_example(request):
        event = dict(EXAMPLE_ATTACK_EVENTS[-1])
        return {"status": "ok", "event": event, "example": True}
    event = attack_telemetry.push_custom(payload)
    return {"status": "ok", "event": event}


@app.api("/api/attacks/simulator", methods=["GET", "POST"])
def api_attacks_simulator(request):
    if is_example(request):
        return {
            "status": "ok",
            "simulator": {"running": False, "mode": "example"},
            "generated": 0,
            "event_ids": [],
        }
    if request.method == "GET":
        return {"status": "ok", "simulator": attack_telemetry.status()}
    admin_error = require_admin_access(request)
    if admin_error:
        return admin_error
    payload = request.json() or {}
    if "running" in payload:
        attack_telemetry.set_running(bool(payload.get("running")))
    burst = clamp_int(payload.get("burst", 0), 0, 0, 30)
    generated_events = attack_telemetry.burst(burst) if burst else []
    return {
        "status": "ok",
        "simulator": attack_telemetry.status(),
        "generated": len(generated_events),
        "event_ids": [row["id"] for row in generated_events],
    }


@app.api("/api/hello", methods=["GET"])
def api_hello(request):
    return {"message": "Hello from server"}


@app.api("/api/echo", methods=["POST"])
def api_echo(request):
    return {"received": request.text()}


@app.api("/api/ws/clients", methods=["GET"])
def api_ws_clients(request):
    admin_error = require_admin_access(request)
    if admin_error:
        return admin_error
    if is_example(request):
        return EXAMPLE_WS_CLIENTS
    return registry.list_clients_info()


@app.api("/api/ws/broadcast", methods=["POST"])
def api_ws_broadcast(request):
    admin_error = require_admin_access(request)
    if admin_error:
        return admin_error
    if is_example(request):
        return {"status": "ok", "example": True}
    data = request.json() or {}
    t = data.get("type", "text")
    message = data.get("message", "")
    if t == "text":
        payload = str(message).encode("utf-8")
        failed = registry.broadcast(1, payload)
    else:
        b = data.get("binary")
        if isinstance(b, list):
            payload = bytes(b)
        else:
            payload = str(message).encode("utf-8")
        failed = registry.broadcast(2, payload)
    if failed:
        return Response.json({"status": "partial", "failed": failed}, status=500)
    return {"status": "ok"}


@app.api("/api/ws/ping", methods=["POST"])
def api_ws_ping(request):
    admin_error = require_admin_access(request)
    if admin_error:
        return admin_error
    if is_example(request):
        return {"status": "ok", "example": True}
    data = request.json() or {}
    payload = str(data.get("payload", "")).encode("utf-8")
    failed = registry.broadcast(9, payload)
    if failed:
        return Response.json({"status": "partial", "failed": failed}, status=500)
    return {"status": "ok"}


@app.api("/api/ws/close", methods=["POST"])
def api_ws_close(request):
    admin_error = require_admin_access(request)
    if admin_error:
        return admin_error
    if is_example(request):
        return {"status": "ok", "example": True}
    data = request.json() or {}
    client_id = data.get("client_id")
    try:
        code = int(data.get("code", 1000))
    except Exception:
        code = 1000
    if code < 0 or code > 65535:
        return json_error("Invalid close code. Use 0-65535", status=400)
    reason = data.get("reason", "")
    payload = code.to_bytes(2, "big") + (reason.encode("utf-8") if reason else b"")
    if client_id:
        ok, msg = registry.send_to_client(client_id, 8, payload)
        if ok:
            return {"status": "ok"}
        return Response.json({"status": "error", "msg": msg}, status=500)
    failed = registry.broadcast(8, payload)
    if failed:
        return Response.json({"status": "partial", "failed": failed}, status=500)
    return {"status": "ok"}


@app.api("/api/chat/messages", methods=["GET"])
def api_chat_messages(request):
    if is_example(request):
        try:
            limit = int(request.query.get("limit", "50"))
        except Exception:
            limit = 50
        if limit <= 0:
            limit = 50
        if limit > 500:
            limit = 500
        return EXAMPLE_CHAT_MESSAGES[:limit]
    try:
        limit = int(request.query.get("limit", "50"))
    except Exception:
        limit = 50
    if limit <= 0:
        limit = 50
    if limit > 500:
        limit = 500
    msgs = ChatMessage.objects(ws_db).order_by("id DESC").limit(limit).all()
    data = [m.to_dict() for m in msgs]
    return data


@app.api("/api/chat/clear", methods=["POST"])
def api_chat_clear(request):
    admin_error = require_admin_access(request)
    if admin_error:
        return admin_error
    if is_example(request):
        return {"status": "ok", "deleted": len(EXAMPLE_CHAT_MESSAGES), "example": True}
    with ws_db.transaction():
        deleted = ChatMessage.objects(ws_db).delete()
    return {"status": "ok", "deleted": deleted}


@app.api("/api/cluster/agents", methods=["GET"])
def api_cluster_agents(request):
    if not is_master_role():
        return json_error("Only master role exposes cluster state", status=403)
    admin_error = require_admin_access(request)
    if admin_error:
        return admin_error
    return build_cluster_agents_snapshot()


@app.api("/api/cluster/agent/credentials", methods=["GET"])
def api_cluster_agent_credentials_list(request):
    if not is_master_role():
        return json_error("Only master role manages agent credentials", status=403)
    admin_error = require_admin_access(request)
    if admin_error:
        return admin_error
    scan_db.create_tables()
    return {"datas": scan_db.select_cluster_agent_credentials(include_inactive=True)}


@app.api("/api/cluster/agent/credentials", methods=["POST"])
def api_cluster_agent_credentials_create(request):
    if not is_master_role():
        return json_error("Only master role manages agent credentials", status=403)
    admin_error = require_admin_access(request)
    if admin_error:
        return admin_error
    scan_db.create_tables()
    payload = request.json() or {}
    try:
        item = scan_db.create_cluster_agent_credential(payload)
    except ValueError as exc:
        return json_error(exc, status=400)
    except Exception as exc:
        return json_error(exc, status=500)
    return {"status": "ok", "credential": item}


@app.api("/api/cluster/agent/credentials", methods=["DELETE"])
def api_cluster_agent_credentials_revoke(request):
    if not is_master_role():
        return json_error("Only master role manages agent credentials", status=403)
    admin_error = require_admin_access(request)
    if admin_error:
        return admin_error
    scan_db.create_tables()
    payload = request.json() or {}
    try:
        item = scan_db.revoke_cluster_agent_credential(payload)
    except ValueError as exc:
        return json_error(exc, status=400)
    except Exception as exc:
        return json_error(exc, status=500)
    return {"status": "ok", "credential": item}


@app.api("/api/cluster/ca", methods=["GET"])
def api_cluster_ca(request):
    if not is_master_role():
        return json_error("Only master role exposes CA distribution", status=403)
    admin_error = require_admin_access(request)
    if admin_error:
        return admin_error
    try:
        return build_ca_distribution_payload()
    except Exception as exc:
        return json_error(exc, status=404)


@app.view("/api/cluster/ca/raw", methods=["GET"])
def api_cluster_ca_raw(request):
    if not is_master_role():
        return Response.text("Forbidden", status=403)
    admin_error = require_admin_access(request)
    if admin_error:
        return admin_error
    try:
        payload = build_ca_distribution_payload()
        pem_text = str(payload.get("ca_pem", "") or "")
        if not pem_text:
            return Response.text("CA not configured", status=404)
        return Response(
            status=200,
            body=pem_text.encode("utf-8"),
            headers={
                "Content-Type": "application/x-pem-file; charset=utf-8",
                "Content-Disposition": 'attachment; filename="porthound-ca.pem"',
                "Cache-Control": "no-store",
            },
        )
    except Exception as exc:
        return Response.text(str(exc), status=404)


@app.view("/api/cluster/ca/oneline", methods=["GET"])
def api_cluster_ca_oneline(request):
    if not is_master_role():
        return Response.text("Forbidden", status=403)
    admin_error = require_admin_access(request)
    if admin_error:
        return admin_error
    try:
        payload = build_ca_distribution_payload()
        one_line = str(payload.get("ca_oneline", "") or "")
        if not one_line:
            return Response.text("CA not configured", status=404)
        return Response.text(one_line, status=200)
    except Exception as exc:
        return Response.text(str(exc), status=404)


@app.api("/api/cluster/agent/register", methods=["POST"])
def api_cluster_agent_register(request):
    if not is_master_role():
        return json_error("Only master role accepts agent registration", status=403)
    payload = request.json() or {}
    auth, auth_error = authenticate_cluster_agent(request, payload)
    if auth_error:
        return auth_error
    agent_id = str(auth.get("agent_id", "")).strip()
    cert_cn = str(auth.get("cert_cn", "")).strip()
    auth_mode = str(auth.get("auth_mode", "")).strip().lower()

    now_ts = time.time()
    with cluster_lock:
        cluster_agents[agent_id] = {
            "agent_id": agent_id,
            "cn": cert_cn,
            "auth_mode": auth_mode,
            "last_seen": now_ts,
            "client": request.client,
        }
        _cluster_cleanup_expired_leases(now_ts)

    return {
        "status": "ok",
        "agent_id": agent_id,
        "lease_seconds": int(getattr(settings, "AGENT_TASK_LEASE_SECONDS", 300) or 300),
    }


@app.api("/api/cluster/agent/task/pull", methods=["POST"])
def api_cluster_agent_task_pull(request):
    if not is_master_role():
        return json_error("Only master role schedules agent tasks", status=403)
    payload = request.json() or {}
    auth, auth_error = authenticate_cluster_agent(request, payload)
    if auth_error:
        return auth_error
    agent_id = str(auth.get("agent_id", "")).strip()
    cert_cn = str(auth.get("cert_cn", "")).strip()
    auth_mode = str(auth.get("auth_mode", "")).strip().lower()

    with cluster_lock:
        cluster_agents[agent_id] = {
            "agent_id": agent_id,
            "cn": cert_cn,
            "auth_mode": auth_mode,
            "last_seen": time.time(),
            "client": request.client,
        }

    task = claim_task_for_agent(agent_id)
    if not task:
        return {"status": "empty", "task": None}
    return {"status": "ok", "task": task}


@app.api("/api/cluster/agent/task/submit", methods=["POST"])
def api_cluster_agent_task_submit(request):
    if not is_master_role():
        return json_error("Only master role accepts task results", status=403)

    try:
        payload = normalize_agent_result_payload(request.json() or {})
    except ValueError as exc:
        return json_error(exc, status=400)
    auth, auth_error = authenticate_cluster_agent(
        request,
        payload,
        expected_agent_id=payload.get("agent_id", ""),
    )
    if auth_error:
        return auth_error

    target_id = int(payload["master_target_id"])
    target = scan_db.select_target_by_id(target_id)
    if not target:
        return json_error("Target not found", status=404)

    submitted_agent_id = str(auth.get("agent_id", payload["agent_id"])).strip()
    cert_cn = str(auth.get("cert_cn", "")).strip()
    auth_mode = str(auth.get("auth_mode", "")).strip().lower()

    with cluster_lock:
        cluster_agents[submitted_agent_id] = {
            "agent_id": submitted_agent_id,
            "cn": cert_cn,
            "auth_mode": auth_mode,
            "last_seen": time.time(),
            "client": request.client,
        }

    counters = _merge_agent_results(payload.get("result", {}), agent_id=submitted_agent_id)

    result_data = payload.get("result", {})
    try:
        progress = float(result_data.get("progress", 100.0) or 100.0)
    except Exception:
        progress = 100.0
    if progress < 0.0:
        progress = 0.0
    if progress > 100.0:
        progress = 100.0
    scan_db.set_target_progress(data={"id": target_id, "progress": progress})

    state = str(result_data.get("status", "active") or "active").strip().lower()
    if state in TARGET_STATUSES:
        scan_db.set_target_status(data={"id": target_id, "status": state})
    elif progress >= 100.0:
        scan_db.set_target_status(data={"id": target_id, "status": "active"})

    release_task_lease(target_id, task_id=payload["task_id"], agent_id=submitted_agent_id)

    return {
        "status": "ok",
        "master_target_id": target_id,
        "stored": counters,
        "progress": progress,
    }


def _send_ws_json(ws, payload):
    ws.send_text(json.dumps(payload))


def _send_attack_snapshot(ws, limit=30, example=False):
    limit = clamp_int(limit, 30, 1, 200)
    events = EXAMPLE_ATTACK_EVENTS[-limit:] if example else attack_telemetry.latest(limit)
    _send_ws_json(ws, {"type": "attack_snapshot", "data": events})


def _send_attack_summary(ws, example=False):
    summary = EXAMPLE_ATTACK_SUMMARY if example else attack_telemetry.summary()
    _send_ws_json(ws, {"type": "attack_summary", "data": summary})


def _handle_ws_control_message(ws, text, example=False):
    try:
        payload = json.loads(text)
    except Exception:
        return False
    if not isinstance(payload, dict):
        return False
    action = str(payload.get("action", "")).strip().lower()
    if not action:
        return False
    if action in {"scan_map_snapshot", "map_snapshot"}:
        limit = clamp_int(payload.get("limit", 300), 300, 1, 2000)
        snapshot = scan_map_telemetry.snapshot(limit=limit)
        _send_ws_json(ws, {"type": "scan_map_snapshot", "data": snapshot})
        return True
    if action in {"scan_map_refresh", "map_refresh"}:
        limit = clamp_int(payload.get("limit", 300), 300, 1, 2000)
        snapshot = scan_map_telemetry.snapshot(limit=limit)
        _send_ws_json(ws, {"type": "scan_map_update", "data": snapshot})
        return True
    if action == "attacks_snapshot":
        _send_attack_snapshot(ws, limit=payload.get("limit", 30), example=example)
        return True
    if action == "attacks_summary":
        _send_attack_summary(ws, example=example)
        return True
    if action == "attacks_pause":
        if not example:
            attack_telemetry.set_running(False)
        _send_ws_json(
            ws,
            {"type": "attack_simulator_status", "data": attack_telemetry.status()},
        )
        return True
    if action == "attacks_resume":
        if not example:
            attack_telemetry.set_running(True)
        _send_ws_json(
            ws,
            {"type": "attack_simulator_status", "data": attack_telemetry.status()},
        )
        return True
    if action == "attacks_burst":
        count = clamp_int(payload.get("count", 5), 5, 1, 20)
        if example:
            for row in EXAMPLE_ATTACK_EVENTS[-count:]:
                _send_ws_json(ws, {"type": "attack_event", "data": row})
            _send_attack_summary(ws, example=True)
            return True
        generated = attack_telemetry.burst(count)
        _send_ws_json(
            ws,
            {
                "type": "attack_burst_ack",
                "count": len(generated),
                "event_ids": [row["id"] for row in generated],
            },
        )
        return True
    if action == "attacks_push":
        if example:
            _send_ws_json(ws, {"type": "attack_push_ack", "status": "ignored_example_mode"})
            return True
        event = attack_telemetry.push_custom(payload.get("event"))
        _send_ws_json(ws, {"type": "attack_push_ack", "status": "ok", "event_id": event["id"]})
        return True
    return False


def _handle_text_message(ws, client_id, text, fragmented=False, example=False):
    if _handle_ws_control_message(ws, text, example=example):
        return
    alias, msg = parse_chat_line(text)
    ts = int(time.time())
    if msg.strip():
        try:
            ChatMessage.objects(ws_db).create(
                client_id=client_id,
                alias=alias or "anon",
                message=msg,
                created_at=ts,
            )
        except Exception as e:
            print(f"[chat] db error: {e}")
    reply = "Server echo (frag): " + text if fragmented else "Server echo: " + text
    try:
        ws.send_text(reply)
    except Exception as e:
        print(f"[ws] send error: {e}")


@app.ws("/ws/")
def ws_handler(ws, request):
    example_session = is_example(request)
    client_id = str(uuid.uuid4())
    registry.register_client(
        client_id=client_id,
        sock=ws.sock,
        addr=ws.addr,
        thread=threading.current_thread(),
        subprotocol=ws.subprotocol,
    )

    try:
        _send_ws_json(
            ws,
            {
                "type": "welcome",
                "client_id": client_id,
                "subprotocol": ws.subprotocol,
            },
        )
        _send_ws_json(
            ws,
            {
                "type": "scan_map_snapshot",
                "data": scan_map_telemetry.snapshot(limit=300),
            },
        )
        _send_attack_snapshot(ws, limit=30, example=example_session)
        _send_attack_summary(ws, example=example_session)
    except Exception as e:
        print(f"[ws] welcome error: {e}")

    fragmented_msg_opcode = None
    fragmented_parts = []

    try:
        while True:
            fin, opcode, payload, masked, mask = ws.recv_frame()
            plen = len(payload)

            if opcode == 0x8:
                code, reason = parse_close_payload(payload)
                try:
                    ws.send_frame(0x8, payload if payload else b"")
                except Exception as e:
                    print(f"[ws] close reply error: {e}")
                break

            if opcode == 0x9:
                try:
                    ws.send_pong(payload)
                except Exception as e:
                    print(f"[ws] pong error: {e}")
                continue

            if opcode == 0xA:
                continue

            if opcode == 0x0:
                if fragmented_msg_opcode is None:
                    fragmented_parts = []
                    fragmented_msg_opcode = None
                    continue
                fragmented_parts.append(payload)
                if fin:
                    full = b"".join(fragmented_parts)
                    if fragmented_msg_opcode == 1:
                        try:
                            text = full.decode("utf-8", errors="ignore")
                        except Exception:
                            text = ""
                        _handle_text_message(
                            ws,
                            client_id,
                            text,
                            fragmented=True,
                            example=example_session,
                        )
                    elif fragmented_msg_opcode == 2:
                        prefix = b"BIN ECHO:"
                        ws.send_frame(2, prefix + full)
                    fragmented_parts = []
                    fragmented_msg_opcode = None
                continue

            if opcode == 0x1 or opcode == 0x2:
                if fin:
                    if opcode == 0x1:
                        text = payload.decode("utf-8", errors="ignore")
                        _handle_text_message(
                            ws,
                            client_id,
                            text,
                            fragmented=False,
                            example=example_session,
                        )
                    else:
                        prefix = b"BIN ECHO:"
                        ws.send_frame(2, prefix + payload)
                else:
                    fragmented_msg_opcode = opcode
                    fragmented_parts = [payload]
                continue
    except ConnectionError:
        pass
    except Exception as e:
        print(f"[ws] loop error: {e}")
    finally:
        registry.unregister_client(client_id)
        try:
            ws.sock.close()
        except Exception:
            pass


def build_master_ssl_context():
    if not bool(getattr(settings, "TLS_ENABLED", True)):
        return None
    cert_file = str(getattr(settings, "TLS_CERT_FILE", "") or "").strip()
    key_file = str(getattr(settings, "TLS_KEY_FILE", "") or "").strip()
    if not cert_file or not key_file:
        raise RuntimeError("PORTHOUND_TLS_CERT_FILE and PORTHOUND_TLS_KEY_FILE are required")
    if not Path(cert_file).is_file():
        raise RuntimeError(f"Master cert file not found: {cert_file}")
    if not Path(key_file).is_file():
        raise RuntimeError(f"Master key file not found: {key_file}")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if hasattr(ssl, "OP_NO_COMPRESSION"):
        context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)

    require_client_cert = bool(getattr(settings, "TLS_REQUIRE_CLIENT_CERT", True))
    ca_file = resolve_ca_file_path(required=require_client_cert)
    if require_client_cert:
        context.load_verify_locations(cafile=ca_file)
        context.verify_mode = ssl.CERT_REQUIRED
    elif ca_file:
        context.load_verify_locations(cafile=ca_file)
        context.verify_mode = ssl.CERT_OPTIONAL
    else:
        context.verify_mode = ssl.CERT_NONE
    return context


def normalize_master_base_url(value):
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = f"http://{raw}"
    parsed = urlsplit(raw)
    scheme = str(parsed.scheme or "").strip().lower()
    if scheme not in {"http", "https"}:
        raise ValueError("PORTHOUND_MASTER must use http:// or https://")
    netloc = str(parsed.netloc or "").strip()
    if not netloc:
        raise ValueError("PORTHOUND_MASTER host is missing")
    base_path = str(parsed.path or "").rstrip("/")
    return f"{scheme}://{netloc}{base_path}"


def build_agent_ssl_context(allow_missing_client_cert=False):
    ca_file = resolve_ca_file_path(required=False)
    if ca_file:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    else:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    cert_file = str(getattr(settings, "AGENT_CERT_FILE", "") or "").strip()
    key_file = str(getattr(settings, "AGENT_KEY_FILE", "") or "").strip()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = bool(getattr(settings, "AGENT_TLS_CHECK_HOSTNAME", True))
    if not ca_file and not context.check_hostname:
        context.verify_mode = ssl.CERT_NONE

    if cert_file or key_file:
        if not cert_file or not key_file:
            if not allow_missing_client_cert:
                raise RuntimeError("PORTHOUND_AGENT_CERT and PORTHOUND_AGENT_KEY must be set together")
        elif Path(cert_file).is_file() and Path(key_file).is_file():
            context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        elif not allow_missing_client_cert:
            if not Path(cert_file).is_file():
                raise RuntimeError(f"Agent cert file not found: {cert_file}")
            raise RuntimeError(f"Agent key file not found: {key_file}")
    return context


def post_json_over_tls(url, payload, ssl_context, timeout_seconds):
    parsed = urlsplit(str(url))
    scheme = str(parsed.scheme or "").strip().lower()
    if scheme not in {"http", "https"}:
        raise RuntimeError("Only http:// or https:// URLs are supported")
    use_tls = scheme == "https"
    host = str(parsed.hostname or "").strip()
    if not host:
        raise RuntimeError("Invalid URL host")
    port = int(parsed.port or (443 if use_tls else 80))
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    body = json.dumps(payload).encode("utf-8")
    default_port = 443 if use_tls else 80
    host_header = host if port == default_port else f"{host}:{port}"
    request_blob = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii", errors="ignore") + body

    raw_sock = None
    conn_sock = None
    response_blob = b""
    try:
        raw_sock = socket.create_connection((host, port), timeout=float(timeout_seconds))
        if use_tls:
            if ssl_context is None:
                raise RuntimeError("SSL context is required for https:// URLs")
            conn_sock = ssl_context.wrap_socket(raw_sock, server_hostname=host)
            raw_sock = None
        else:
            conn_sock = raw_sock
            raw_sock = None
        conn_sock.settimeout(float(timeout_seconds))
        conn_sock.sendall(request_blob)
        while True:
            chunk = conn_sock.recv(4096)
            if not chunk:
                break
            response_blob += chunk
    except Exception as exc:
        raise RuntimeError(str(exc))
    finally:
        try:
            if conn_sock:
                conn_sock.close()
        except Exception:
            pass
        try:
            if raw_sock:
                raw_sock.close()
        except Exception:
            pass

    header_blob, separator, body_blob = response_blob.partition(b"\r\n\r\n")
    if not separator:
        raise RuntimeError("Invalid HTTP response")
    lines = header_blob.decode("iso-8859-1", errors="ignore").split("\r\n")
    if not lines:
        raise RuntimeError("Invalid HTTP response")
    status_parts = lines[0].split(" ", 2)
    if len(status_parts) < 2:
        raise RuntimeError("Invalid HTTP status line")
    try:
        status_code = int(status_parts[1])
    except Exception:
        status_code = 0

    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    if "content-length" in headers:
        try:
            expected = int(headers.get("content-length", "0") or "0")
            if expected >= 0:
                body_blob = body_blob[:expected]
        except Exception:
            pass

    if status_code >= 400:
        message = body_blob.decode("utf-8", errors="ignore").strip() or f"HTTP {status_code}"
        raise RuntimeError(f"HTTP {status_code}: {message}")

    if not body_blob:
        return {}
    try:
        return json.loads(body_blob.decode("utf-8", errors="ignore"))
    except Exception:
        return {}


def _target_proto_set(proto_value):
    proto = str(proto_value or "").strip().lower()
    if proto == "sctp":
        return {"sctp", "stcp"}
    return {proto}


class AgentRuntime:
    def __init__(self, db):
        self.db = db
        self.master_base_url = normalize_master_base_url(
            getattr(settings, "PORTHOUND_MASTER", "")
        )
        if not self.master_base_url:
            raise RuntimeError("PORTHOUND_MASTER is required in agent mode")
        parsed_master = urlsplit(self.master_base_url)
        self.master_scheme = str(parsed_master.scheme or "").strip().lower()
        master_host = str(urlsplit(self.master_base_url).hostname or "").strip().lower()
        if master_host in {"127.0.0.1", "localhost", "::1"}:
            print(
                "[agent] warning: PORTHOUND_MASTER uses loopback "
                f"({master_host}); this only works when master and agent run on the same host"
            )
        self.agent_shared_key = str(getattr(settings, "AGENT_SHARED_KEY", "") or "").strip()
        cert_file = str(getattr(settings, "AGENT_CERT_FILE", "") or "").strip()
        key_file = str(getattr(settings, "AGENT_KEY_FILE", "") or "").strip()
        self.has_client_cert = bool(
            cert_file and key_file and Path(cert_file).is_file() and Path(key_file).is_file()
        )
        if self.master_scheme == "https":
            self.ssl_context = build_agent_ssl_context(
                allow_missing_client_cert=bool(self.agent_shared_key)
            )
        else:
            self.ssl_context = None
        if self.master_scheme == "http" and not self.agent_shared_key:
            raise RuntimeError(
                "PORTHOUND_AGENT_SHARED_KEY is required when PORTHOUND_MASTER uses http://"
            )
        if self.master_scheme == "https" and not self.agent_shared_key and not self.has_client_cert:
            raise RuntimeError(
                "Configure PORTHOUND_AGENT_SHARED_KEY or valid "
                "PORTHOUND_AGENT_CERT/PORTHOUND_AGENT_KEY in agent mode"
            )
        if self.agent_shared_key and self.has_client_cert:
            self.auth_mode = "mtls+shared_key"
        elif self.agent_shared_key:
            self.auth_mode = "shared_key"
        else:
            self.auth_mode = "mtls"
        self.poll_seconds = int(getattr(settings, "AGENT_POLL_SECONDS", 8) or 8)
        self.http_timeout = float(getattr(settings, "AGENT_HTTP_TIMEOUT", 20.0) or 20.0)
        configured_agent_id = str(getattr(settings, "AGENT_ID", "") or "").strip()
        if configured_agent_id:
            self.agent_id = configured_agent_id
        else:
            hostname = socket.gethostname() or "agent"
            self.agent_id = f"{hostname}-{uuid.uuid4().hex[:10]}"
        self.registered = False
        self.failure_streak = 0
        self.waiting_master = False

    def _endpoint(self, path):
        return f"{self.master_base_url.rstrip('/')}/{str(path).lstrip('/')}"

    def _auth_payload(self):
        payload = {"agent_id": self.agent_id}
        if self.agent_shared_key:
            payload["agent_key"] = self.agent_shared_key
        return payload

    def _post(self, path, payload):
        response = post_json_over_tls(
            url=self._endpoint(path),
            payload=payload,
            ssl_context=self.ssl_context,
            timeout_seconds=self.http_timeout,
        )
        self._mark_master_reachable()
        return response

    def _mark_master_reachable(self):
        if self.waiting_master:
            print("[agent] master connection restored")
        self.waiting_master = False
        self.failure_streak = 0

    def _is_transient_master_error(self, exc):
        message = str(exc or "").strip().lower()
        if not message:
            return False
        if message.startswith("http 5"):
            return True
        markers = (
            "connection refused",
            "timed out",
            "timeout",
            "temporary failure",
            "temporarily unavailable",
            "name or service not known",
            "network is unreachable",
            "no route to host",
            "connection reset by peer",
            "eof occurred in violation of protocol",
        )
        return any(marker in message for marker in markers)

    def _next_retry_delay(self):
        base = max(2, int(self.poll_seconds))
        exponent = min(max(self.failure_streak - 1, 0), 5)
        return min(60, base * (2 ** exponent))

    def register(self):
        response = self._post(
            "/api/cluster/agent/register",
            self._auth_payload(),
        )
        if str(response.get("status", "")).strip().lower() != "ok":
            raise RuntimeError(f"Agent register failed: {response}")
        self.registered = True
        return response

    def pull_task(self):
        response = self._post(
            "/api/cluster/agent/task/pull",
            self._auth_payload(),
        )
        status = str(response.get("status", "")).strip().lower()
        if status == "ok":
            return response.get("task")
        if status == "empty":
            return None
        raise RuntimeError(f"Agent pull task failed: {response}")

    def submit_task(self, payload):
        outbound = dict(payload or {})
        if self.agent_shared_key:
            outbound["agent_key"] = self.agent_shared_key
        response = self._post("/api/cluster/agent/task/submit", outbound)
        if str(response.get("status", "")).strip().lower() != "ok":
            raise RuntimeError(f"Agent submit failed: {response}")
        return response

    def _find_target_row(self, target_item):
        target_proto = str(target_item.get("proto", "")).strip().lower()
        target_proto_set = _target_proto_set(target_proto)
        for row in self.db.select_targets():
            proto_value = str((row or {}).get("proto", "")).strip().lower()
            if proto_value not in target_proto_set:
                continue
            if str((row or {}).get("network", "")) != str(target_item.get("network", "")):
                continue
            if str((row or {}).get("type", "")) != str(target_item.get("type", "")):
                continue
            if str((row or {}).get("port_mode", "")) != str(target_item.get("port_mode", "")):
                continue
            if int((row or {}).get("port_start", 0) or 0) != int(target_item.get("port_start", 0) or 0):
                continue
            if int((row or {}).get("port_end", 0) or 0) != int(target_item.get("port_end", 0) or 0):
                continue
            try:
                if float((row or {}).get("timesleep", 1.0) or 1.0) != float(
                    target_item.get("timesleep", 1.0) or 1.0
                ):
                    continue
            except Exception:
                continue
            return row
        return None

    def ensure_local_target(self, target_payload):
        target_candidate = normalize_target_item(
            {
                "network": target_payload.get("network"),
                "type": target_payload.get("type"),
                "proto": target_payload.get("proto"),
                "timesleep": target_payload.get("timesleep", 1.0),
                "status": "active",
                "port_mode": target_payload.get("port_mode", "preset"),
                "port_start": target_payload.get("port_start", 0),
                "port_end": target_payload.get("port_end", 0),
            }
        )
        self.db.insert_targets(data=target_candidate)
        row = self._find_target_row(target_candidate)
        if not row:
            raise RuntimeError("Agent failed to materialize local target")

        target_id = int(row["id"])
        self.db.clear_target_artifacts(data={"id": target_id})
        self.db.set_target_progress(data={"id": target_id, "progress": 0.0})
        self.db.set_target_status(data={"id": target_id, "status": "active"})
        return target_id, target_candidate

    def wait_target_completion(self, target_id, timeout_seconds=86400):
        started_at = time.time()
        last_progress = 0.0
        last_status = "active"
        while True:
            row = self.db.select_target_by_id(target_id)
            if not row:
                return 0.0, "stopped"
            try:
                last_progress = float(row.get("progress", 0.0) or 0.0)
            except Exception:
                last_progress = 0.0
            last_status = str(row.get("status", "active") or "active").strip().lower()
            if last_progress >= 100.0:
                return 100.0, "active"
            if last_status == "stopped":
                return last_progress, "stopped"
            if time.time() - started_at > float(timeout_seconds):
                raise TimeoutError("scan timeout waiting for target completion")
            time.sleep(1.0)

    def collect_result_payload(self, target_payload):
        network = ip_network(str(target_payload.get("network", "")).strip(), strict=False)
        proto_set = _target_proto_set(target_payload.get("proto"))

        def in_target(ip_value):
            try:
                return ip_address(str(ip_value)) in network
            except Exception:
                return False

        ports = []
        for row in self.db.select_ports():
            proto_value = str((row or {}).get("proto", "")).strip().lower()
            if proto_value not in proto_set:
                continue
            ip_value = str((row or {}).get("ip", "")).strip()
            if not in_target(ip_value):
                continue
            ports.append(
                {
                    "ip": ip_value,
                    "port": int((row or {}).get("port", 0) or 0),
                    "proto": proto_value,
                    "state": str((row or {}).get("state", "open")).strip().lower(),
                }
            )

        tags = []
        for row in self.db.select_tags():
            proto_value = str((row or {}).get("proto", "")).strip().lower()
            if proto_value not in proto_set:
                continue
            ip_value = str((row or {}).get("ip", "")).strip()
            if not in_target(ip_value):
                continue
            tags.append(
                {
                    "ip": ip_value,
                    "port": int((row or {}).get("port", 0) or 0),
                    "proto": proto_value,
                    "key": str((row or {}).get("key", ""))[:120],
                    "value": str((row or {}).get("value", ""))[:4096],
                }
            )

        banners = []
        for row in self.db.select_banners():
            proto_value = str((row or {}).get("proto", "")).strip().lower()
            if proto_value not in proto_set:
                continue
            ip_value = str((row or {}).get("ip", "")).strip()
            if not in_target(ip_value):
                continue
            banners.append(
                {
                    "ip": ip_value,
                    "port": int((row or {}).get("port", 0) or 0),
                    "proto": proto_value,
                    "response_plain": str((row or {}).get("response_plain", ""))[:8192],
                }
            )

        favicons = []
        for row in self.db.select_favicons():
            proto_value = str((row or {}).get("proto", "")).strip().lower()
            if proto_value not in proto_set:
                continue
            ip_value = str((row or {}).get("ip", "")).strip()
            if not in_target(ip_value):
                continue
            raw = self.db.get_favicon_by_id(int((row or {}).get("id", 0) or 0))
            if not raw:
                continue
            icon_blob = bytes(raw.get("icon_blob") or b"")
            if not icon_blob:
                continue
            favicons.append(
                {
                    "ip": str(raw.get("ip", "")).strip(),
                    "port": int(raw.get("port", 0) or 0),
                    "proto": str(raw.get("proto", "tcp")).strip().lower() or "tcp",
                    "icon_url": str(raw.get("icon_url", "/favicon.ico")).strip() or "/favicon.ico",
                    "mime_type": str(raw.get("mime_type", "application/octet-stream")).strip()
                    or "application/octet-stream",
                    "size": int(raw.get("size", len(icon_blob)) or len(icon_blob)),
                    "sha256": str(raw.get("sha256", "")).strip(),
                    "icon_blob_b64": base64.b64encode(icon_blob).decode("ascii"),
                }
            )

        return {
            "ports": ports,
            "tags": tags,
            "banners": banners,
            "favicons": favicons,
        }

    def cleanup_local_target(self, target_id):
        try:
            self.db.clear_target_artifacts(data={"id": int(target_id)})
        except Exception:
            pass
        try:
            self.db.delete_target(data={"id": int(target_id)})
        except Exception:
            pass

    def execute_task(self, task):
        if not isinstance(task, dict):
            return
        target_payload = task.get("target") or {}
        task_id = str(task.get("task_id", "")).strip()
        if not isinstance(target_payload, dict) or not task_id:
            return

        try:
            master_target_id = int(target_payload.get("master_target_id"))
        except Exception:
            raise RuntimeError("Invalid task payload: missing master_target_id")
        local_target_id = None
        started_at = utc_iso(int(time.time()))
        progress = 0.0
        status = "stopped"
        error = ""
        result = {"ports": [], "tags": [], "banners": [], "favicons": []}
        try:
            local_target_id, normalized_target = self.ensure_local_target(target_payload)
            progress, status = self.wait_target_completion(local_target_id)
            result = self.collect_result_payload(normalized_target)
            status = "active" if progress >= 100.0 else status
        except Exception as exc:
            error = str(exc)
        finally:
            if local_target_id:
                self.cleanup_local_target(local_target_id)

        result["progress"] = progress
        result["status"] = status
        if error:
            result["error"] = error
        submission = {
            "agent_id": self.agent_id,
            "task_id": task_id,
            "master_target_id": master_target_id,
            "started_at": started_at,
            "finished_at": utc_iso(int(time.time())),
            "result": result,
        }
        self.submit_task(submission)

    def run_forever(self):
        print(
            "[agent] starting "
            f"agent_id={self.agent_id} master={self.master_base_url} auth={self.auth_mode}"
        )
        while True:
            try:
                if not self.registered:
                    self.register()
                    print("[agent] registration successful")
                task = self.pull_task()
                if not task:
                    time.sleep(self.poll_seconds)
                    continue
                self.execute_task(task)
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                self.registered = False
                if self._is_transient_master_error(exc):
                    self.failure_streak += 1
                    retry_in = self._next_retry_delay()
                    if not self.waiting_master:
                        self.waiting_master = True
                        print(f"[agent] master unreachable: {exc}")
                    elif self.failure_streak % 5 == 0:
                        print(
                            "[agent] still waiting for master "
                            f"(attempt {self.failure_streak}, retry in {retry_in}s): {exc}"
                        )
                    time.sleep(retry_in)
                    continue

                self.failure_streak = 0
                self.waiting_master = False
                print(f"[agent] loop error: {exc}")
                time.sleep(self.poll_seconds)


def run_master_mode(enable_local_scanners=False):
    ssl_context = build_master_ssl_context()
    app.add_startup(register_frontend_dist_routes)
    app.add_startup(start_geoip_blocks_db)
    if enable_local_scanners:
        app.add_startup(start_scanners)
    app.add_startup(start_scan_map_telemetry)
    app.add_startup(start_attack_telemetry)
    role_label = "standalone" if enable_local_scanners else "master"
    if not str(getattr(settings, "API_TOKEN", "") or "").strip():
        bind_host = str(getattr(settings, "HOST", "") or "").strip().lower()
        if bind_host not in {"127.0.0.1", "localhost", "::1"}:
            print(
                "[security] PORTHOUND_API_TOKEN is not set. "
                "Admin endpoints are restricted to loopback clients."
            )
    print(f"[bootstrap] role={role_label} host={settings.HOST} port={settings.PORT}")
    app.run(settings.HOST, settings.PORT, ssl_context=ssl_context)


def run_agent_mode():
    start_geoip_blocks_db()
    start_scanners()
    runtime = AgentRuntime(scan_db)
    runtime.run_forever()


def main():
    role = current_role()
    if role == "agent":
        run_agent_mode()
        return
    run_master_mode(enable_local_scanners=(role == "standalone"))


if __name__ == "__main__":
    main()
