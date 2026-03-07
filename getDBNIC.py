#!/usr/bin/env python3
import gzip
import json
import os
import queue
import shutil
import socket
import sqlite3
import ssl
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from ipaddress import IPv4Address, summarize_address_range
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urljoin, urlsplit

from country_centroids import get_country_centroid
from geoip_seed import GEOIP_SEED_FORMAT, GEOIP_SEED_PATH, ensure_geoip_seed_parent, open_geoip_seed


RIR_SOURCES = {
    "ARIN": "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "RIPE": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "APNIC": "https://ftp.apnic.net/pub/stats/apnic/delegated-apnic-extended-latest",
    "LACNIC": "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "AFRINIC": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}

RIR_REFERENCE_POINTS = {
    "LACNIC": {
        "label": "Latin America and Caribbean",
        "country": "UY",
        "lat": -34.9011,
        "lon": -56.1645,
    },
    "ARIN": {
        "label": "North America",
        "country": "US",
        "lat": 38.9072,
        "lon": -77.0369,
    },
    "RIPE": {
        "label": "Europe, Middle East and Central Asia",
        "country": "NL",
        "lat": 52.3676,
        "lon": 4.9041,
    },
    "APNIC": {
        "label": "Asia Pacific",
        "country": "AU",
        "lat": -33.8688,
        "lon": 151.2093,
    },
    "AFRINIC": {
        "label": "Africa",
        "country": "MU",
        "lat": -20.1609,
        "lon": 57.5012,
    },
}

CANONICAL_RIR = {
    "arin": "ARIN",
    "ripencc": "RIPE",
    "ripe": "RIPE",
    "apnic": "APNIC",
    "lacnic": "LACNIC",
    "afrinic": "AFRINIC",
}

INSERT_SQL = (
    "INSERT OR REPLACE INTO geoip_blocks "
    "(start_int, end_int, cidr, rir, area, country, lat, lon) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?);"
)

LOG_LOCK = threading.Lock()
LOG_CONFIG = {
    "quiet": False,
    "verbose_http": False,
}
TERM_UI = None
DOWNLOAD_RESUME_CACHE = {}
DOWNLOAD_RESUME_LOCK = threading.Lock()

BEST_DEFAULTS = {
    "db": str(Path(tempfile.gettempdir()) / "porthound_geoip_build.db"),
    "seed_file": str(GEOIP_SEED_PATH),
    "rirs": "ARIN,RIPE,APNIC,LACNIC,AFRINIC",
    "workers": 5,
    "timeout": 90.0,
    "retries": 6,
    "max_redirects": 5,
    "batch_size": 2000,
    "append": False,
    "include_reserved": False,
    "log_every_lines": 150000,
    "log_every_rows": 50000,
    "verbose_http": False,
    "quiet": False,
    "retry_failed_passes": 4,
    "retry_workers": 1,
    "retry_delay_sec": 6.0,
    "fail_on_partial": True,
    "download_progress_log_sec": 5.0,
    "download_progress_log_bytes": 2 * 1024 * 1024,
    "download_wait_log_sec": 20.0,
    "read_chunk_timeout_sec": 8.0,
}


def format_bytes_human(value):
    size = float(max(0, int(value or 0)))
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    unit = units[0]
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            break
        size /= 1024.0
    if unit == "B":
        return f"{int(size)} {unit}"
    return f"{size:.1f} {unit}"


def format_duration_human(seconds):
    total = max(0, int(seconds or 0))
    if total < 60:
        return f"{total:02d}s"
    minutes, secs = divmod(total, 60)
    if minutes < 60:
        return f"{minutes:02d}m{secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours:02d}h{minutes:02d}m"


def truncate_text(text, max_len):
    plain = str(text or "")
    if max_len <= 0:
        return ""
    if len(plain) <= max_len:
        return plain
    if max_len <= 3:
        return plain[:max_len]
    return plain[: max_len - 3] + "..."


def download_cache_get(key):
    cache_key = str(key or "").strip()
    if not cache_key:
        return {"body": b"", "total": None, "url": ""}
    with DOWNLOAD_RESUME_LOCK:
        item = DOWNLOAD_RESUME_CACHE.get(cache_key, {})
        return {
            "body": bytes(item.get("body", b"") or b""),
            "total": item.get("total"),
            "url": str(item.get("url", "") or ""),
        }


def download_cache_set(key, body, total=None, url=""):
    cache_key = str(key or "").strip()
    if not cache_key:
        return
    with DOWNLOAD_RESUME_LOCK:
        DOWNLOAD_RESUME_CACHE[cache_key] = {
            "body": bytes(body or b""),
            "total": (int(total) if total is not None else None),
            "url": str(url or ""),
        }


def download_cache_clear(key):
    cache_key = str(key or "").strip()
    if not cache_key:
        return
    with DOWNLOAD_RESUME_LOCK:
        DOWNLOAD_RESUME_CACHE.pop(cache_key, None)


class TerminalUI:
    COLORS = {
        "reset": "\033[0m",
        "dim": "\033[2m",
        "cyan": "\033[36m",
        "blue": "\033[34m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "red": "\033[31m",
        "magenta": "\033[35m",
        "white": "\033[97m",
        "bold": "\033[1m",
    }
    STAGE_THEME = {
        "pending": {"emoji": "⏳", "label": "pending", "color": "dim"},
        "connect": {"emoji": "🔌", "label": "connect", "color": "cyan"},
        "tls": {"emoji": "🔐", "label": "tls", "color": "cyan"},
        "headers": {"emoji": "📥", "label": "headers", "color": "blue"},
        "recv": {"emoji": "⬇️", "label": "download", "color": "green"},
        "parse": {"emoji": "🧠", "label": "parse", "color": "magenta"},
        "queue": {"emoji": "📦", "label": "queue", "color": "yellow"},
        "retry": {"emoji": "🔁", "label": "retry", "color": "yellow"},
        "done": {"emoji": "✅", "label": "done", "color": "green"},
        "error": {"emoji": "❌", "label": "error", "color": "red"},
    }
    LEVEL_THEME = {
        "INFO": {"emoji": "📡", "color": "cyan"},
        "WARNING": {"emoji": "⚠️", "color": "yellow"},
        "ERROR": {"emoji": "💥", "color": "red"},
        "DEBUG": {"emoji": "🧭", "color": "dim"},
    }

    def __init__(self, enabled=True):
        term_name = str(os.environ.get("TERM", "")).lower()
        self.enabled = bool(
            enabled and hasattr(sys.stderr, "isatty") and sys.stderr.isatty() and term_name != "dumb"
        )
        self.use_color = bool(self.enabled and not os.environ.get("NO_COLOR"))
        self.lock = threading.Lock()
        self.source_order = []
        self.sources = {}
        self.last_render_lines = 0
        self.last_render_ts = 0.0
        self.refresh_interval = 0.12
        self.notice_level = "INFO"
        self.notice_message = "initializing terminal monitor"
        self.cursor_hidden = False
        self.finished = False
        self.started_at = time.time()

    def start(self, selected_rirs, args):
        if not self.enabled:
            return
        with self.lock:
            self.started_at = time.time()
            self.finished = False
            self.source_order = list(selected_rirs)
            self.sources = {}
            for rir in self.source_order:
                self.sources[rir] = {
                    "stage": "pending",
                    "received": 0,
                    "total": None,
                    "elapsed": 0.0,
                    "rate": 0.0,
                    "detail": "queued",
                    "attempt": 0,
                    "pulse": 0,
                }
            self.notice_level = "INFO"
            self.notice_message = (
                f"workers={int(args.workers)} | retries={int(args.retries)} "
                f"| db={args.db} | rirs={','.join(selected_rirs)}"
            )
            self._render_locked(force=True)

    def note(self, message, level="INFO", force=False):
        if not self.enabled:
            return False
        with self.lock:
            self.notice_level = str(level or "INFO").upper()
            self.notice_message = str(message or "")
            self._render_locked(force=force)
        return True

    def update_source(
        self,
        rir,
        stage=None,
        received=None,
        total=None,
        elapsed=None,
        rate=None,
        detail=None,
        attempt=None,
        force=False,
    ):
        if not self.enabled:
            return False
        with self.lock:
            state = self.sources.setdefault(
                str(rir),
                {
                    "stage": "pending",
                    "received": 0,
                    "total": None,
                    "elapsed": 0.0,
                    "rate": 0.0,
                    "detail": "",
                    "attempt": 0,
                    "pulse": 0,
                },
            )
            if rir not in self.source_order:
                self.source_order.append(str(rir))
            if stage is not None:
                state["stage"] = str(stage)
            if received is not None:
                state["received"] = max(0, int(received))
            if total is not None:
                total_value = int(total)
                state["total"] = max(0, total_value) if total_value > 0 else None
            if elapsed is not None:
                state["elapsed"] = max(0.0, float(elapsed))
            if rate is not None:
                state["rate"] = max(0.0, float(rate))
            if detail is not None:
                state["detail"] = str(detail)
            if attempt is not None:
                state["attempt"] = max(0, int(attempt))
            state["pulse"] = int(state.get("pulse", 0)) + 1
            self._render_locked(force=force)
        return True

    def finish(self, message="", level="INFO"):
        if not self.enabled:
            return
        with self.lock:
            if message:
                self.notice_level = str(level or "INFO").upper()
                self.notice_message = str(message)
            self._render_locked(force=True)
            sys.stderr.write("\n")
            if self.cursor_hidden:
                sys.stderr.write("\033[?25h")
                self.cursor_hidden = False
            sys.stderr.flush()
            self.finished = True
            self.enabled = False

    def close(self):
        if not self.enabled:
            return
        with self.lock:
            if self.cursor_hidden:
                sys.stderr.write("\033[?25h")
                sys.stderr.flush()
                self.cursor_hidden = False

    def _render_locked(self, force=False):
        now = time.time()
        if not force and (now - self.last_render_ts) < self.refresh_interval:
            return
        lines = self._build_lines_locked()
        if not self.cursor_hidden:
            sys.stderr.write("\033[?25l")
            self.cursor_hidden = True
        if self.last_render_lines:
            sys.stderr.write("\r")
            if self.last_render_lines > 1:
                sys.stderr.write(f"\033[{self.last_render_lines - 1}A")
            for idx in range(self.last_render_lines):
                sys.stderr.write("\033[2K")
                if idx < self.last_render_lines - 1:
                    sys.stderr.write("\033[1B\r")
            if self.last_render_lines > 1:
                sys.stderr.write(f"\033[{self.last_render_lines - 1}A")
            sys.stderr.write("\r")
        for idx, line in enumerate(lines):
            sys.stderr.write("\033[2K")
            sys.stderr.write(line)
            if idx < len(lines) - 1:
                sys.stderr.write("\n")
        sys.stderr.flush()
        self.last_render_lines = len(lines)
        self.last_render_ts = now

    def _build_lines_locked(self):
        term_width = max(80, shutil.get_terminal_size((120, 20)).columns)
        lines = []
        lines.extend(self._banner_lines(term_width))
        lines.append(self._color("🌐 live RIR transfer dashboard", "white", bold=True))
        lines.append(self._divider(term_width))
        for rir in self.source_order:
            lines.append(self._source_line(term_width, rir, self.sources.get(rir, {})))
        lines.append(self._divider(term_width))
        lines.append(self._notice_line(term_width))
        return lines

    def _banner_lines(self, term_width):
        title = "PortHound GeoIP NIC Import"
        subtitle = "clean terminal mode with live bars"
        inner = min(max(len(title), len(subtitle)) + 2, max(38, term_width - 4))
        top = "+" + ("-" * inner) + "+"
        line_1 = "| " + title.center(inner - 2) + " |"
        line_2 = "| " + subtitle.center(inner - 2) + " |"
        return [
            self._color(top, "cyan", bold=True),
            self._color(line_1, "cyan", bold=True),
            self._color(line_2, "cyan", bold=True),
            self._color(top, "cyan", bold=True),
        ]

    def _divider(self, term_width):
        return self._color("-" * min(108, max(40, term_width - 2)), "dim")

    def _notice_line(self, term_width):
        theme = self.LEVEL_THEME.get(self.notice_level, self.LEVEL_THEME["INFO"])
        prefix = f"{theme['emoji']} {self.notice_level:<7} "
        text = truncate_text(self.notice_message, max(18, term_width - len(prefix) - 2))
        return prefix + self._color(text, theme["color"], bold=self.notice_level in {"WARNING", "ERROR"})

    def _source_line(self, term_width, rir, state):
        stage_key = str(state.get("stage", "pending") or "pending")
        theme = self.STAGE_THEME.get(stage_key, self.STAGE_THEME["pending"])
        received = max(0, int(state.get("received", 0) or 0))
        total = state.get("total")
        if total is not None:
            total = max(0, int(total))
        elapsed = max(0.0, float(state.get("elapsed", 0.0) or 0.0))
        rate = max(0.0, float(state.get("rate", 0.0) or 0.0))
        detail = str(state.get("detail", "") or "")
        attempt = max(0, int(state.get("attempt", 0) or 0))
        if attempt > 0 and "attempt" not in detail.lower():
            detail = f"attempt {attempt} | {detail}".strip(" |")
        bar_width = max(14, min(30, term_width - 82))
        bar = self._progress_bar(bar_width, received, total, int(state.get("pulse", 0)))
        percent_text = "--.-%"
        if total:
            percent_text = f"{(100.0 * received / max(1, total)):5.1f}%"
        size_text = format_bytes_human(received)
        if total:
            size_text = f"{size_text}/{format_bytes_human(total)}"
        rate_text = "--"
        if rate > 0:
            rate_text = f"{format_bytes_human(rate)}/s"
        elapsed_text = format_duration_human(elapsed)
        detail_width = max(12, term_width - (bar_width + 58))
        detail_text = truncate_text(detail, detail_width)
        left = f"{theme['emoji']} {str(rir):<7} {theme['label']:<8}"
        line = (
            f"{left} {self._color(bar, theme['color'], bold=stage_key in {'done', 'error'})} "
            f"{percent_text:>6} {size_text:>18} {rate_text:>12} {elapsed_text:>7} {detail_text}"
        )
        return self._color(left, theme["color"], bold=stage_key in {"done", "error"}) + line[len(left) :]

    def _progress_bar(self, width, received, total, pulse):
        if total and total > 0:
            ratio = min(1.0, float(received) / float(total))
            filled = min(width, int(round(ratio * width)))
            if filled >= width:
                return "[" + ("#" * width) + "]"
            return "[" + ("#" * filled) + ("." * (width - filled)) + "]"
        slots = ["."] * width
        center = pulse % max(1, width)
        for idx in range(width):
            distance = abs(idx - center)
            if distance == 0:
                slots[idx] = "#"
            elif distance == 1:
                slots[idx] = "="
        return "[" + "".join(slots) + "]"

    def _color(self, text, color, bold=False):
        plain = str(text)
        if not self.use_color:
            return plain
        parts = []
        if bold:
            parts.append(self.COLORS["bold"])
        parts.append(self.COLORS.get(color, ""))
        parts.append(plain)
        parts.append(self.COLORS["reset"])
        return "".join(parts)


def utc_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(message, level="INFO", force=False):
    if TERM_UI is not None and TERM_UI.enabled:
        if force or str(level or "").upper() in {"WARNING", "ERROR"}:
            TERM_UI.note(message, level=level, force=True)
        return
    if not force and LOG_CONFIG.get("quiet"):
        return
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    thread_name = threading.current_thread().name
    with LOG_LOCK:
        print(
            f"[{stamp}] [{level}] [{thread_name}] {message}",
            file=sys.stderr,
            flush=True,
        )


def canonical_rir(value, fallback=""):
    key = str(value or "").strip().lower()
    if not key:
        return str(fallback or "").strip().upper()
    return CANONICAL_RIR.get(key, str(fallback or "").strip().upper())


def ensure_tables(conn):
    cursor = conn.cursor()
    try:
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
        conn.commit()
    finally:
        cursor.close()


def decode_chunked(body):
    out = bytearray()
    idx = 0
    total = len(body)
    while True:
        line_end = body.find(b"\r\n", idx)
        if line_end < 0:
            raise ValueError("chunked body malformed: missing chunk size line")
        size_line = body[idx:line_end].decode("ascii", "ignore").strip()
        if ";" in size_line:
            size_line = size_line.split(";", 1)[0].strip()
        if not size_line:
            raise ValueError("chunked body malformed: empty chunk size")
        size = int(size_line, 16)
        idx = line_end + 2
        if size == 0:
            trailer_end = body.find(b"\r\n\r\n", idx)
            if trailer_end >= 0:
                return bytes(out)
            return bytes(out)
        if idx + size > total:
            raise ValueError("chunked body malformed: chunk exceeds body size")
        out.extend(body[idx : idx + size])
        idx += size
        if body[idx : idx + 2] != b"\r\n":
            raise ValueError("chunked body malformed: missing chunk CRLF")
        idx += 2


def parse_http_response(raw):
    head_end = raw.find(b"\r\n\r\n")
    if head_end < 0:
        raise ValueError("invalid HTTP response: missing header delimiter")
    head = raw[:head_end]
    body = raw[head_end + 4 :]
    lines = head.split(b"\r\n")
    if not lines:
        raise ValueError("invalid HTTP response: empty status line")
    status_line = lines[0].decode("iso-8859-1", "replace")
    parts = status_line.split(" ", 2)
    if len(parts) < 2:
        raise ValueError(f"invalid HTTP status line: {status_line}")
    status_code = int(parts[1])
    headers = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        headers[name.decode("iso-8859-1", "ignore").strip().lower()] = (
            value.decode("iso-8859-1", "ignore").strip()
        )
    return status_code, headers, body


def parse_content_range_header(value):
    text = str(value or "").strip()
    if not text or not text.lower().startswith("bytes "):
        return None
    try:
        range_part, total_part = text[6:].split("/", 1)
        start_txt, end_txt = range_part.split("-", 1)
        return {
            "start": int(start_txt),
            "end": int(end_txt),
            "total": None if total_part.strip() == "*" else int(total_part),
        }
    except Exception:
        return None


class PartialDownloadError(RuntimeError):
    def __init__(
        self,
        message,
        *,
        status_code=None,
        headers=None,
        body=b"",
        resolved_url="",
        response_meta=None,
    ):
        super().__init__(str(message))
        self.status_code = status_code
        self.headers = dict(headers or {})
        self.body = bytes(body or b"")
        self.resolved_url = str(resolved_url or "")
        self.response_meta = dict(response_meta or {})


def http_get_bytes(
    url,
    timeout=20.0,
    retries=3,
    max_redirects=5,
    source_label="",
    progress_log_sec=5.0,
    progress_log_bytes=(2 * 1024 * 1024),
    wait_log_sec=20.0,
    chunk_timeout_sec=8.0,
):
    cache_key = str(source_label or url or "").strip()
    cached = download_cache_get(cache_key)
    current_url = str(cached.get("url") or url)
    last_error = None
    accumulated_body = bytes(cached.get("body", b"") or b"")
    expected_total = cached.get("total")
    overall_started = time.time()
    for attempt in range(1, retries + 1):
        resume_from = len(accumulated_body)
        try:
            if TERM_UI is not None and source_label:
                TERM_UI.update_source(
                    source_label,
                    stage="retry" if attempt > 1 else "connect",
                    received=resume_from,
                    total=expected_total,
                    elapsed=(time.time() - overall_started),
                    rate=0.0,
                    detail=(
                        f"attempt {attempt}/{retries} | resume from {format_bytes_human(resume_from)}"
                        if resume_from > 0
                        else f"attempt {attempt}/{retries}"
                    ),
                    attempt=attempt,
                    force=True,
                )
            attempt_timeout = float(timeout) * (1.0 + ((attempt - 1) * 0.75))
            if attempt == 1 or LOG_CONFIG.get("verbose_http"):
                log(
                    f"{source_label or 'HTTP'} download attempt {attempt}/{retries} "
                    f"(timeout={attempt_timeout:.1f}s): {current_url}",
                    level="DEBUG" if attempt > 1 else "INFO",
                )
            for _ in range(max_redirects + 1):
                status_code, headers, body, resolved_url, response_meta = _http_get_once(
                    current_url,
                    timeout=attempt_timeout,
                    source_label=source_label,
                    progress_log_sec=progress_log_sec,
                    progress_log_bytes=progress_log_bytes,
                    wait_log_sec=wait_log_sec,
                    chunk_timeout_sec=chunk_timeout_sec,
                    resume_from=resume_from,
                    overall_started=overall_started,
                )
                if status_code in (301, 302, 303, 307, 308):
                    location = headers.get("location", "")
                    if not location:
                        raise RuntimeError(
                            f"redirect without location in {resolved_url} (status {status_code})"
                        )
                    current_url = urljoin(resolved_url, location)
                    if TERM_UI is not None and source_label:
                        TERM_UI.update_source(
                            source_label,
                            stage="connect",
                            detail=f"redirect {status_code} -> {urlsplit(current_url).netloc}",
                            attempt=attempt,
                            force=True,
                        )
                    if LOG_CONFIG.get("verbose_http"):
                        log(
                            f"{source_label or 'HTTP'} redirect {status_code}: {resolved_url} -> {current_url}",
                            level="DEBUG",
                        )
                    continue
                if status_code == 416 and resume_from > 0:
                    range_info = parse_content_range_header(headers.get("content-range", ""))
                    total_from_header = range_info.get("total") if range_info else None
                    if total_from_header is not None and resume_from >= int(total_from_header):
                        download_cache_clear(cache_key)
                        return accumulated_body[: int(total_from_header)]
                    accumulated_body = b""
                    expected_total = total_from_header
                    resume_from = 0
                    current_url = resolved_url
                    download_cache_set(
                        cache_key,
                        accumulated_body,
                        total=expected_total,
                        url=current_url,
                    )
                    log(
                        f"{source_label or 'HTTP'} byte-range resume rejected, restarting from zero",
                        level="WARNING",
                    )
                    continue
                if status_code >= 400:
                    raise RuntimeError(
                        f"HTTP {status_code} while requesting {resolved_url}"
                    )
                expected_total = response_meta.get("total_length") or expected_total
                if resume_from > 0 and response_meta.get("resume_applied"):
                    body = accumulated_body + body
                elif resume_from > 0:
                    accumulated_body = b""
                    log(
                        f"{source_label or 'HTTP'} server ignored resume range, retry data restarted from zero",
                        level="WARNING",
                    )
                if "chunked" in headers.get("transfer-encoding", "").lower():
                    body = decode_chunked(body)
                content_encoding = headers.get("content-encoding", "").lower()
                if "gzip" in content_encoding:
                    body = gzip.decompress(body)
                if TERM_UI is not None and source_label:
                    TERM_UI.update_source(
                        source_label,
                        stage="parse",
                        received=len(body),
                        total=expected_total or len(body),
                        elapsed=(time.time() - overall_started),
                        detail=f"payload ready from {urlsplit(resolved_url).netloc}",
                        attempt=attempt,
                        force=True,
                    )
                log(
                    f"{source_label or 'HTTP'} downloaded {len(body)} bytes from {resolved_url}",
                    level="INFO",
                )
                download_cache_clear(cache_key)
                return body
            raise RuntimeError(f"too many redirects while requesting {url}")
        except PartialDownloadError as exc:
            last_error = exc
            current_url = exc.resolved_url or current_url
            meta = dict(exc.response_meta or {})
            can_resume = bool(meta.get("resume_supported")) and len(exc.body) > 0
            expected_total = meta.get("total_length") or expected_total
            if can_resume and resume_from > 0 and meta.get("resume_applied"):
                accumulated_body += exc.body
            elif can_resume:
                accumulated_body = bytes(exc.body)
            else:
                accumulated_body = b""
                expected_total = None
            saved_bytes = len(accumulated_body)
            download_cache_set(
                cache_key,
                accumulated_body,
                total=expected_total,
                url=current_url,
            )
            resume_note = (
                f"saved {format_bytes_human(saved_bytes)} for resume"
                if saved_bytes > 0
                else "resume unavailable; next retry starts from zero"
            )
            if TERM_UI is not None and source_label:
                TERM_UI.update_source(
                    source_label,
                    stage="retry" if saved_bytes > 0 else "error",
                    received=saved_bytes,
                    total=expected_total,
                    elapsed=(time.time() - overall_started),
                    detail=f"{resume_note} | {exc}",
                    attempt=attempt,
                    force=True,
                )
            log(
                f"{source_label or 'HTTP'} attempt {attempt}/{retries} interrupted: {exc} | {resume_note}",
                level="WARNING",
            )
            time.sleep(min(0.75 * attempt, 2.0))
        except Exception as exc:
            last_error = exc
            download_cache_set(
                cache_key,
                accumulated_body,
                total=expected_total,
                url=current_url,
            )
            if TERM_UI is not None and source_label:
                TERM_UI.update_source(
                    source_label,
                    stage="error",
                    detail=str(exc),
                    attempt=attempt,
                    force=True,
                )
            log(
                f"{source_label or 'HTTP'} attempt {attempt}/{retries} failed: {exc}",
                level="WARNING",
            )
            time.sleep(min(0.75 * attempt, 2.0))
    raise RuntimeError(f"failed to download {url}: {last_error}")


def _http_get_once(
    url,
    timeout=20.0,
    source_label="",
    progress_log_sec=5.0,
    progress_log_bytes=(2 * 1024 * 1024),
    wait_log_sec=20.0,
    chunk_timeout_sec=8.0,
    resume_from=0,
    overall_started=None,
):
    parsed = urlsplit(str(url))
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"unsupported URL scheme: {scheme}")
    host = parsed.hostname
    if not host:
        raise ValueError(f"invalid URL, missing host: {url}")
    port = parsed.port or (443 if scheme == "https" else 80)
    target = parsed.path or "/"
    if parsed.query:
        target += f"?{parsed.query}"

    request_lines = [
        f"GET {target} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: PortHound/getDBNIC.py",
        "Accept: */*",
        "Accept-Encoding: identity",
        "Connection: close",
    ]
    if int(resume_from or 0) > 0:
        request_lines.append(f"Range: bytes={int(resume_from)}-")
    request = ("\r\n".join(request_lines) + "\r\n\r\n").encode("ascii")

    log(
        f"{source_label or 'HTTP'} connecting: host={host}, port={port}, scheme={scheme.upper()}",
        level="INFO",
    )
    if TERM_UI is not None and source_label:
        TERM_UI.update_source(
            source_label,
            stage="connect",
            detail=(
                f"{host}:{port} via {scheme.upper()} | resume {format_bytes_human(resume_from)}"
                if int(resume_from or 0) > 0
                else f"{host}:{port} via {scheme.upper()}"
            ),
            force=True,
        )
    with socket.create_connection((host, port), timeout=timeout) as sock:
        if scheme == "https":
            ctx = ssl.create_default_context()
            log(
                f"{source_label or 'HTTP'} TLS handshake start: {host}:{port}",
                level="INFO",
            )
            if TERM_UI is not None and source_label:
                TERM_UI.update_source(
                    source_label,
                    stage="tls",
                    detail=f"TLS handshake {host}:{port}",
                    force=True,
                )
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                log(
                    f"{source_label or 'HTTP'} TLS handshake complete: version={tls_sock.version()}",
                    level="INFO",
                )
                if TERM_UI is not None and source_label:
                    TERM_UI.update_source(
                        source_label,
                        stage="headers",
                        detail=f"request sent | TLS {tls_sock.version()}",
                        force=True,
                    )
                tls_sock.sendall(request)
                log(
                    f"{source_label or 'HTTP'} request sent, waiting response: {parsed.geturl()}",
                    level="INFO",
                )
                raw = _recv_all(
                    tls_sock,
                    timeout=timeout,
                    source_label=source_label,
                    progress_log_sec=progress_log_sec,
                    progress_log_bytes=progress_log_bytes,
                    wait_log_sec=wait_log_sec,
                    chunk_timeout_sec=chunk_timeout_sec,
                    resume_from=resume_from,
                    request_url=parsed.geturl(),
                    overall_started=overall_started,
                )
        else:
            sock.sendall(request)
            log(
                f"{source_label or 'HTTP'} request sent, waiting response: {parsed.geturl()}",
                level="INFO",
            )
            if TERM_UI is not None and source_label:
                TERM_UI.update_source(
                    source_label,
                    stage="headers",
                    detail=f"request sent | waiting headers",
                    force=True,
                )
            raw = _recv_all(
                sock,
                timeout=timeout,
                source_label=source_label,
                progress_log_sec=progress_log_sec,
                progress_log_bytes=progress_log_bytes,
                wait_log_sec=wait_log_sec,
                chunk_timeout_sec=chunk_timeout_sec,
                resume_from=resume_from,
                request_url=parsed.geturl(),
                overall_started=overall_started,
            )

    status_code, headers, body, response_meta = raw
    log(
        f"{source_label or 'HTTP'} response received: status={status_code}, content-length={headers.get('content-length', 'unknown')}",
        level="INFO",
    )
    return status_code, headers, body, parsed.geturl(), response_meta


def _recv_all(
    sock_obj,
    timeout=20.0,
    source_label="",
    progress_log_sec=5.0,
    progress_log_bytes=(2 * 1024 * 1024),
    wait_log_sec=20.0,
    chunk_timeout_sec=8.0,
    resume_from=0,
    request_url="",
    overall_started=None,
):
    chunks = []
    total_wire = 0
    started = time.time()
    last_progress_log_ts = started
    last_wait_log_ts = started
    last_progress_log_bytes = 0
    label = source_label or "HTTP"
    previous_timeout = None
    header_probe = bytearray()
    headers_ready = False
    status_code = None
    headers = {}
    content_length = None
    total_length = None
    body_received = 0
    chunked = False
    compressed = False
    display_offset = max(0, int(resume_from or 0))
    response_meta = {
        "resume_requested": bool(display_offset > 0),
        "resume_applied": False,
        "resume_supported": False,
        "display_offset": display_offset,
        "total_length": None,
        "content_length": None,
        "chunked": False,
        "content_encoding": "",
    }
    try:
        previous_timeout = sock_obj.gettimeout()
    except Exception:
        previous_timeout = None
    effective_chunk_timeout = max(0.5, min(float(timeout), float(chunk_timeout_sec)))
    try:
        sock_obj.settimeout(effective_chunk_timeout)
    except Exception:
        pass
    log(
        f"{label} stream receive started: overall_timeout={float(timeout):.1f}s, chunk_timeout={effective_chunk_timeout:.1f}s",
        level="INFO",
    )
    try:
        while True:
            now = time.time()
            elapsed = now - started
            if elapsed > float(timeout):
                raise TimeoutError(
                    f"read timeout after {timeout:.1f}s (received={total_wire:,} bytes)"
                )
            try:
                data = sock_obj.recv(65536)
            except socket.timeout:
                if wait_log_sec > 0 and (now - last_wait_log_ts) >= float(wait_log_sec):
                    log(
                        f"{label} waiting for data: elapsed={elapsed:.1f}s, received={total_wire:,} bytes",
                        level="INFO",
                    )
                    last_wait_log_ts = now
                continue
            now = time.time()
            elapsed = now - started
            if not data:
                if not headers_ready:
                    raise RuntimeError("connection closed before HTTP headers were received")
                if (
                    not chunked
                    and content_length is not None
                    and body_received < int(content_length)
                ):
                    raise PartialDownloadError(
                        (
                            f"connection closed early after {display_offset + body_received:,} "
                            f"bytes"
                        ),
                        status_code=status_code,
                        headers=headers,
                        body=b"".join(chunks),
                        resolved_url=request_url,
                        response_meta=response_meta,
                    )
                overall_elapsed = (time.time() - float(overall_started)) if overall_started else elapsed
                if TERM_UI is not None and label:
                    TERM_UI.update_source(
                        label,
                        stage="recv",
                        received=(display_offset + body_received),
                        total=total_length,
                        elapsed=overall_elapsed,
                        rate=(float(display_offset + body_received) / max(0.001, overall_elapsed)),
                        detail="stream closed by peer",
                        force=True,
                    )
                log(
                    f"{label} peer closed stream: total_received={total_wire:,} bytes, sec={elapsed:.3f}",
                    level="INFO",
                )
                break
            total_wire += len(data)
            if not headers_ready:
                header_probe.extend(data)
                marker = header_probe.find(b"\r\n\r\n")
                if marker < 0:
                    if TERM_UI is not None and label:
                        TERM_UI.update_source(
                            label,
                            stage="headers",
                            received=display_offset,
                            total=total_length,
                            elapsed=(time.time() - float(overall_started)) if overall_started else elapsed,
                            detail="waiting response headers",
                        )
                    continue
                headers_ready = True
                status_code, headers, _ = parse_http_response(bytes(header_probe[: marker + 4]))
                body_chunk = bytes(header_probe[marker + 4 :])
                header_value = str(headers.get("content-length", "") or "").strip()
                if header_value:
                    try:
                        content_length = max(0, int(header_value))
                    except Exception:
                        content_length = None
                range_info = parse_content_range_header(headers.get("content-range", ""))
                chunked = "chunked" in headers.get("transfer-encoding", "").lower()
                compressed = "gzip" in headers.get("content-encoding", "").lower()
                if int(resume_from or 0) > 0 and status_code == 206 and range_info:
                    if int(range_info.get("start", -1)) == int(resume_from):
                        response_meta["resume_applied"] = True
                elif int(resume_from or 0) > 0 and status_code == 200:
                    display_offset = 0
                if range_info and range_info.get("total") is not None:
                    total_length = int(range_info["total"])
                elif content_length is not None and response_meta["resume_applied"]:
                    total_length = int(resume_from) + int(content_length)
                else:
                    total_length = content_length
                response_meta["resume_supported"] = bool(
                    status_code in (200, 206)
                    and not chunked
                    and not compressed
                    and content_length is not None
                )
                response_meta["display_offset"] = display_offset
                response_meta["total_length"] = total_length
                response_meta["content_length"] = content_length
                response_meta["chunked"] = bool(chunked)
                response_meta["content_encoding"] = str(headers.get("content-encoding", "") or "").lower()
                if body_chunk:
                    chunks.append(body_chunk)
                    body_received += len(body_chunk)
            else:
                chunks.append(data)
                body_received += len(data)
            if headers_ready:
                overall_elapsed = (time.time() - float(overall_started)) if overall_started else elapsed
                transfer_rate = float(display_offset + body_received) / max(0.001, overall_elapsed)
                if TERM_UI is not None and label:
                    TERM_UI.update_source(
                        label,
                        stage="recv",
                        received=(display_offset + body_received),
                        total=total_length,
                        elapsed=overall_elapsed,
                        rate=transfer_rate,
                        detail=(
                            "streaming response body | resumed"
                            if response_meta.get("resume_applied")
                            else "streaming response body"
                        ),
                    )
            do_log = False
            if progress_log_sec > 0 and (now - last_progress_log_ts) >= float(progress_log_sec):
                do_log = True
            if (
                progress_log_bytes > 0
                and ((display_offset + body_received) - last_progress_log_bytes) >= int(progress_log_bytes)
            ):
                do_log = True
            if do_log:
                shown_bytes = display_offset + body_received
                overall_elapsed = (time.time() - float(overall_started)) if overall_started else elapsed
                kbps = (float(shown_bytes) / 1024.0) / max(0.001, overall_elapsed)
                log(
                    f"{label} download progress: received={shown_bytes:,} bytes ({shown_bytes / (1024 * 1024):.2f} MiB), elapsed={overall_elapsed:.1f}s, avg={kbps:.1f} KiB/s",
                    level="INFO",
                )
                last_progress_log_ts = now
                last_progress_log_bytes = shown_bytes
            if (
                headers_ready
                and not chunked
                and content_length is not None
                and body_received >= int(content_length)
            ):
                break
    except TimeoutError as exc:
        if headers_ready:
            raise PartialDownloadError(
                (
                    f"read timeout after {timeout:.1f}s "
                    f"(received={display_offset + body_received:,} bytes)"
                ),
                status_code=status_code,
                headers=headers,
                body=b"".join(chunks),
                resolved_url=request_url,
                response_meta=response_meta,
            ) from exc
        raise
    finally:
        try:
            if previous_timeout is not None:
                sock_obj.settimeout(previous_timeout)
        except Exception:
            pass
    return status_code, headers, b"".join(chunks), response_meta


def parse_delegated_ipv4_line(line, worker_rir, include_reserved=False):
    txt = str(line or "").strip()
    if not txt or txt.startswith("#"):
        return None
    parts = txt.split("|")
    if len(parts) < 7:
        return None

    rir = canonical_rir(parts[0], fallback=worker_rir)
    if not rir:
        rir = worker_rir
    if rir not in RIR_REFERENCE_POINTS:
        return None

    rec_type = str(parts[2]).strip().lower()
    if rec_type != "ipv4":
        return None

    status = str(parts[6]).strip().lower()
    if status == "available":
        return None
    if status == "reserved" and not include_reserved:
        return None
    if status not in {"allocated", "assigned", "legacy", "reserved"}:
        return None

    start_ip = str(parts[3]).strip()
    count_txt = str(parts[4]).strip()
    try:
        count = int(count_txt)
    except Exception:
        return None
    if count <= 0:
        return None

    try:
        start_addr = IPv4Address(start_ip)
    except Exception:
        return None

    start_int = int(start_addr)
    end_int = start_int + count - 1
    if end_int > 0xFFFFFFFF:
        return None

    country = str(parts[1]).strip().upper() or RIR_REFERENCE_POINTS[rir]["country"]
    return rir, start_int, end_int, country


def build_cidr_rows(rir, start_int, end_int, country):
    geo = RIR_REFERENCE_POINTS[rir]
    centroid = get_country_centroid(country) or (
        float(geo["lat"]),
        float(geo["lon"]),
    )
    start = IPv4Address(start_int)
    end = IPv4Address(end_int)
    for network in summarize_address_range(start, end):
        yield (
            int(network.network_address),
            int(network.broadcast_address),
            str(network),
            rir,
            str(geo["label"]),
            str(country or geo["country"]),
            float(centroid[0]),
            float(centroid[1]),
        )


class ImportStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.ok_sources = {}
        self.failed_sources = {}
        self.total_lines = 0
        self.total_allocations = 0
        self.total_cidr_rows = 0
        self.writer_rows = 0

    def mark_ok(self, rir, payload_bytes, lines, allocations, cidr_rows):
        with self.lock:
            if rir in self.failed_sources:
                self.failed_sources.pop(rir, None)
            self.ok_sources[rir] = {
                "bytes": int(payload_bytes),
                "lines": int(lines),
                "allocations": int(allocations),
                "cidr_rows": int(cidr_rows),
            }
            self.total_lines += int(lines)
            self.total_allocations += int(allocations)
            self.total_cidr_rows += int(cidr_rows)

    def mark_error(self, rir, error_text):
        with self.lock:
            self.failed_sources[rir] = str(error_text)

    def set_writer_rows(self, value):
        with self.lock:
            self.writer_rows = int(value)

    def to_dict(self):
        with self.lock:
            return {
                "ok_sources": dict(self.ok_sources),
                "failed_sources": dict(self.failed_sources),
                "total_lines": int(self.total_lines),
                "total_allocations": int(self.total_allocations),
                "total_cidr_rows": int(self.total_cidr_rows),
                "writer_rows": int(self.writer_rows),
            }


def source_worker(task_queue, out_queue, stats, args):
    while True:
        try:
            rir, url = task_queue.get_nowait()
        except queue.Empty:
            return
        try:
            if TERM_UI is not None:
                TERM_UI.update_source(
                    rir,
                    stage="connect",
                    detail=f"queued from {urlsplit(url).netloc}",
                    force=True,
                )
            log(f"source task started for {rir}: {url}")
            _process_source(rir, url, out_queue, stats, args)
        except Exception as exc:
            stats.mark_error(rir, str(exc))
            if TERM_UI is not None:
                TERM_UI.update_source(
                    rir,
                    stage="error",
                    detail=str(exc),
                    force=True,
                )
            log(f"source task failed for {rir}: {exc}", level="ERROR")
        finally:
            task_queue.task_done()


def _process_source(rir, url, out_queue, stats, args):
    started = time.time()
    if TERM_UI is not None:
        TERM_UI.update_source(
            rir,
            stage="connect",
            detail=f"starting download from {urlsplit(url).netloc}",
            force=True,
        )
    payload = http_get_bytes(
        url=url,
        timeout=float(args.timeout),
        retries=int(args.retries),
        max_redirects=int(args.max_redirects),
        source_label=rir,
        progress_log_sec=float(args.download_progress_log_sec),
        progress_log_bytes=int(args.download_progress_log_bytes),
        wait_log_sec=float(args.download_wait_log_sec),
        chunk_timeout_sec=float(args.read_chunk_timeout_sec),
    )
    text = payload.decode("utf-8", "replace")
    lines = 0
    allocations = 0
    cidr_rows = 0
    batch = []
    next_lines_log = int(args.log_every_lines)
    next_rows_log = int(args.log_every_rows)
    if TERM_UI is not None:
        TERM_UI.update_source(
            rir,
            stage="parse",
            received=len(payload),
            total=len(payload),
            detail="payload decoded | parsing delegated file",
            force=True,
        )

    for raw_line in text.splitlines():
        lines += 1
        if next_lines_log > 0 and lines >= next_lines_log:
            if TERM_UI is not None:
                TERM_UI.update_source(
                    rir,
                    stage="parse",
                    received=len(payload),
                    total=len(payload),
                    elapsed=(time.time() - started),
                    detail=(
                        f"lines={lines:,} | allocations={allocations:,} | "
                        f"cidr_rows={cidr_rows:,}"
                    ),
                )
            log(
                f"{rir} parsing progress: lines={lines:,}, allocations={allocations:,}, cidr_rows={cidr_rows:,}",
                level="INFO",
            )
            next_lines_log += int(args.log_every_lines)
        parsed = parse_delegated_ipv4_line(
            raw_line,
            worker_rir=rir,
            include_reserved=bool(args.include_reserved),
        )
        if not parsed:
            continue
        allocations += 1
        row_rir, start_int, end_int, country = parsed
        for row in build_cidr_rows(row_rir, start_int, end_int, country):
            batch.append(row)
            if len(batch) >= int(args.batch_size):
                out_queue.put(batch)
                cidr_rows += len(batch)
                if next_rows_log > 0 and cidr_rows >= next_rows_log:
                    if TERM_UI is not None:
                        TERM_UI.update_source(
                            rir,
                            stage="queue",
                            received=len(payload),
                            total=len(payload),
                            elapsed=(time.time() - started),
                            detail=f"queued rows={cidr_rows:,}",
                        )
                    log(
                        f"{rir} queued rows: {cidr_rows:,}",
                        level="INFO",
                    )
                    next_rows_log += int(args.log_every_rows)
                batch = []

    if batch:
        out_queue.put(batch)
        cidr_rows += len(batch)

    stats.mark_ok(
        rir=rir,
        payload_bytes=len(payload),
        lines=lines,
        allocations=allocations,
        cidr_rows=cidr_rows,
    )
    elapsed = round(time.time() - started, 3)
    if TERM_UI is not None:
        TERM_UI.update_source(
            rir,
            stage="done",
            received=len(payload),
            total=len(payload),
            elapsed=elapsed,
            detail=f"cidr_rows={cidr_rows:,} | allocations={allocations:,}",
            force=True,
        )
    log(
        f"{rir} finished: bytes={len(payload):,}, lines={lines:,}, allocations={allocations:,}, cidr_rows={cidr_rows:,}, sec={elapsed}",
        level="INFO",
    )


def db_writer(db_path, replace_existing, in_queue, stats, args):
    started = time.time()
    log(f"DB writer starting on {db_path}")
    conn = sqlite3.connect(db_path, timeout=30.0, check_same_thread=False)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    ensure_tables(conn)
    log("DB schema ensured (geoip_blocks, geoip_import_meta)")

    if replace_existing:
        log("replace mode enabled: deleting all existing geoip_blocks rows")
        conn.execute("DELETE FROM geoip_blocks;")
        conn.commit()

    written_rows = 0
    pending = 0
    commit_every = 25000
    next_rows_log = int(args.log_every_rows)

    while True:
        batch = in_queue.get()
        try:
            if batch is None:
                break
            if batch:
                conn.executemany(INSERT_SQL, batch)
                written_rows += len(batch)
                pending += len(batch)
                if pending >= commit_every:
                    conn.commit()
                    if next_rows_log > 0 and written_rows >= next_rows_log:
                        log(
                            f"DB writer committed rows: {written_rows:,}",
                            level="INFO",
                        )
                        next_rows_log += int(args.log_every_rows)
                    pending = 0
        finally:
            in_queue.task_done()

    conn.commit()
    meta_rows = [
        ("last_import_utc", utc_now_iso()),
        ("last_written_rows", str(written_rows)),
    ]
    conn.executemany(
        "INSERT OR REPLACE INTO geoip_import_meta (k, v) VALUES (?, ?);", meta_rows
    )
    conn.commit()
    conn.close()
    stats.set_writer_rows(written_rows)
    elapsed = round(time.time() - started, 3)
    if TERM_UI is not None:
        TERM_UI.note(
            f"db writer flushed {written_rows:,} rows in {elapsed:.1f}s",
            level="INFO",
            force=True,
        )
    log(f"DB writer finished: rows={written_rows:,}, sec={elapsed}")


def count_blocks_in_db(db_path):
    conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM geoip_blocks;")
        row = cursor.fetchone()
        return int(row[0] if row else 0)
    finally:
        conn.close()


def lookup_ipv4(db_path, ip_value):
    try:
        ip_int = int(IPv4Address(str(ip_value).strip()))
    except Exception:
        return {"error": f"invalid IPv4 address: {ip_value}"}

    conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
    try:
        cursor = conn.cursor()
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
        conn.close()

    if not row:
        return {"ip": str(ip_value), "found": False}
    return {
        "ip": str(ip_value),
        "found": True,
        "cidr": row[0],
        "rir": row[1],
        "area": row[2],
        "country": row[3],
        "lat": float(row[4]),
        "lon": float(row[5]),
    }


def export_seed_file(db_path, seed_path, selected_rirs, stats, rows_in_db):
    failed_sources = dict((stats or {}).get("failed_sources", {}) or {})
    if failed_sources:
        log(
            "seed export skipped because import is partial and some RIR sources failed",
            level="WARNING",
            force=True,
        )
        return {
            "path": str(seed_path),
            "exported": False,
            "reason": "partial-import",
        }
    if int(rows_in_db or 0) <= 0:
        log("seed export skipped because there are no rows in the GeoIP DB", level="WARNING", force=True)
        return {
            "path": str(seed_path),
            "exported": False,
            "reason": "empty-db",
        }

    seed_path = ensure_geoip_seed_parent(seed_path)
    started = time.time()
    conn = sqlite3.connect(db_path, timeout=30.0, check_same_thread=False)
    exported_rows = 0
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT start_int, end_int, cidr, rir, area, country, lat, lon "
            "FROM geoip_blocks ORDER BY start_int ASC;"
        )
        meta = {
            "kind": "meta",
            "format": GEOIP_SEED_FORMAT,
            "generated_at": utc_now_iso(),
            "rows": int(rows_in_db),
            "selected_rirs": list(selected_rirs or []),
            "partial": False,
            "failed_rirs": [],
        }
        with open_geoip_seed(seed_path, "wt") as handle:
            handle.write(json.dumps(meta, ensure_ascii=False, separators=(",", ":")) + "\n")
            while True:
                rows = cursor.fetchmany(5000)
                if not rows:
                    break
                for row in rows:
                    record = {
                        "kind": "block",
                        "start_int": int(row[0]),
                        "end_int": int(row[1]),
                        "cidr": str(row[2]),
                        "rir": str(row[3]),
                        "area": str(row[4]),
                        "country": str(row[5]),
                        "lat": float(row[6]),
                        "lon": float(row[7]),
                    }
                    handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
                    exported_rows += 1
        elapsed = round(time.time() - started, 3)
        log(
            f"seed export finished: rows={exported_rows:,}, path={seed_path}, sec={elapsed}",
            level="INFO",
            force=True,
        )
        return {
            "path": str(seed_path),
            "exported": True,
            "rows": int(exported_rows),
            "duration_sec": elapsed,
        }
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()


def parse_rir_selection(text):
    if not text:
        return list(RIR_SOURCES.keys())
    selected = []
    for token in str(text).split(","):
        name = canonical_rir(token)
        if name and name in RIR_SOURCES and name not in selected:
            selected.append(name)
    return selected


def build_runtime_config():
    cfg = SimpleNamespace(**BEST_DEFAULTS)
    cfg.timeout = max(5.0, float(cfg.timeout))
    cfg.retries = max(1, int(cfg.retries))
    cfg.max_redirects = max(0, int(cfg.max_redirects))
    cfg.batch_size = max(1, int(cfg.batch_size))
    cfg.workers = max(1, int(cfg.workers))
    cfg.retry_failed_passes = max(0, int(cfg.retry_failed_passes))
    cfg.retry_workers = max(1, int(cfg.retry_workers))
    cfg.retry_delay_sec = max(0.0, float(cfg.retry_delay_sec))
    cfg.log_every_lines = max(0, int(cfg.log_every_lines))
    cfg.log_every_rows = max(0, int(cfg.log_every_rows))
    cfg.download_progress_log_sec = max(0.0, float(cfg.download_progress_log_sec))
    cfg.download_progress_log_bytes = max(0, int(cfg.download_progress_log_bytes))
    cfg.download_wait_log_sec = max(0.0, float(cfg.download_wait_log_sec))
    cfg.read_chunk_timeout_sec = max(0.5, float(cfg.read_chunk_timeout_sec))
    return cfg


def _run_source_pass(rirs, stats, args, batch_queue, worker_count, pass_label):
    task_queue = queue.Queue()
    for rir in rirs:
        task_queue.put((rir, RIR_SOURCES[rir]))

    workers = []
    for idx in range(worker_count):
        t = threading.Thread(
            target=source_worker,
            args=(task_queue, batch_queue, stats, args),
            name=f"{pass_label}-worker-{idx + 1}",
            daemon=True,
        )
        t.start()
        workers.append(t)

    log(
        f"{pass_label} launched: rirs={','.join(rirs)}, workers={worker_count}",
        level="INFO",
    )

    task_queue.join()
    for t in workers:
        t.join()


def run_import(args):
    selected_rirs = parse_rir_selection(args.rirs)
    if not selected_rirs:
        raise RuntimeError("no valid RIR selected")
    if TERM_UI is not None:
        TERM_UI.start(selected_rirs, args)

    log(
        "starting import: "
        f"db={args.db}, rirs={','.join(selected_rirs)}, workers={args.workers}, "
        f"append={bool(args.append)}, include_reserved={bool(args.include_reserved)}, "
        f"retry_failed_passes={int(args.retry_failed_passes)}",
        level="INFO",
        force=True,
    )

    stats = ImportStats()
    batch_queue = queue.Queue(maxsize=max(8, int(args.workers) * 2))

    writer = threading.Thread(
        target=db_writer,
        args=(args.db, not args.append, batch_queue, stats, args),
        name="db-writer",
        daemon=True,
    )
    writer.start()

    initial_worker_count = min(max(1, int(args.workers)), len(selected_rirs))
    _run_source_pass(
        rirs=selected_rirs,
        stats=stats,
        args=args,
        batch_queue=batch_queue,
        worker_count=initial_worker_count,
        pass_label="pass-1",
    )

    pending = [rir for rir in selected_rirs if rir in stats.failed_sources]
    retry_passes = max(0, int(args.retry_failed_passes))
    retry_index = 0
    while pending and retry_index < retry_passes:
        retry_index += 1
        log(
            f"retry pass {retry_index}/{retry_passes} for failed RIRs: {','.join(pending)}",
            level="WARNING",
            force=True,
        )
        sleep_for = max(0.0, float(args.retry_delay_sec))
        if sleep_for > 0:
            time.sleep(sleep_for)
        retry_workers = min(max(1, int(args.retry_workers)), len(pending))
        _run_source_pass(
            rirs=pending,
            stats=stats,
            args=args,
            batch_queue=batch_queue,
            worker_count=retry_workers,
            pass_label=f"retry-{retry_index}",
        )
        pending = [rir for rir in pending if rir in stats.failed_sources]

    if pending:
        log(
            f"import completed with unresolved failed RIRs: {','.join(pending)}",
            level="ERROR",
            force=True,
        )
    else:
        log("all requested RIRs imported successfully", level="INFO", force=True)

    batch_queue.put(None)
    batch_queue.join()
    writer.join()
    log("all batches flushed and DB writer joined", level="INFO")

    rows_in_db = count_blocks_in_db(args.db)
    if TERM_UI is not None:
        TERM_UI.note(
            f"import completed | rows_in_db={rows_in_db:,} | partial={bool(stats.failed_sources)}",
            level="ERROR" if stats.failed_sources else "INFO",
            force=True,
        )
    log(f"import finished with rows_in_db={rows_in_db:,}", level="INFO", force=True)
    return selected_rirs, stats.to_dict(), rows_in_db


def main():
    global TERM_UI
    if len(sys.argv) > 1:
        log(
            "se ignoraran los parametros CLI: este script usa configuracion fija interna",
            level="WARNING",
            force=True,
        )
    args = build_runtime_config()
    LOG_CONFIG["quiet"] = bool(args.quiet)
    LOG_CONFIG["verbose_http"] = bool(args.verbose_http)
    TERM_UI = TerminalUI(enabled=(not bool(args.quiet)))

    started_at = time.time()
    started_iso = utc_now_iso()
    try:
        log(
            f"getDBNIC started at {started_iso}",
            level="INFO",
            force=True,
        )

        selected_rirs, stats, rows_in_db = run_import(args)
        seed_export = export_seed_file(
            db_path=args.db,
            seed_path=args.seed_file,
            selected_rirs=selected_rirs,
            stats=stats,
            rows_in_db=rows_in_db,
        )
        finished_iso = utc_now_iso()
        failed_sources = stats.get("failed_sources", {})
        output = {
            "started_at": started_iso,
            "finished_at": finished_iso,
            "duration_sec": round(time.time() - started_at, 3),
            "db_path": args.db,
            "seed_file": args.seed_file,
            "selected_rirs": selected_rirs,
            "rows_in_db": int(rows_in_db),
            "is_partial": bool(failed_sources),
            "seed_export": seed_export,
            "stats": stats,
            "config": {
                "workers": int(args.workers),
                "timeout": float(args.timeout),
                "retries": int(args.retries),
                "retry_failed_passes": int(args.retry_failed_passes),
                "retry_workers": int(args.retry_workers),
                "retry_delay_sec": float(args.retry_delay_sec),
                "download_progress_log_sec": float(args.download_progress_log_sec),
                "download_progress_log_bytes": int(args.download_progress_log_bytes),
                "download_wait_log_sec": float(args.download_wait_log_sec),
                "read_chunk_timeout_sec": float(args.read_chunk_timeout_sec),
                "include_reserved": bool(args.include_reserved),
                "start_from_zero": not bool(args.append),
                "seed_file": str(args.seed_file),
            },
        }
        if TERM_UI is not None:
            TERM_UI.finish(
                message=(
                    f"rows_in_db={int(rows_in_db):,} | duration={round(time.time() - started_at, 1):.1f}s "
                    f"| partial={bool(failed_sources)}"
                ),
                level="ERROR" if failed_sources else "INFO",
            )
        print(json.dumps(output, indent=2, ensure_ascii=False))
        if failed_sources and args.fail_on_partial:
            log(
                "fail-on-partial enabled and there are failed RIRs; exiting with code 2",
                level="ERROR",
                force=True,
            )
            raise SystemExit(2)
    finally:
        if TERM_UI is not None:
            TERM_UI.close()


if __name__ == "__main__":
    main()
