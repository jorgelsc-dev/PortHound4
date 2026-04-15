import argparse
import atexit
import base64
import ctypes
import getpass
import ipaddress
import json
import sqlite3
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit


BOOL_CHOICES = ("0", "1", "false", "true", "no", "yes", "off", "on")
TRUE_CHOICES = {"1", "true", "yes", "on", "y"}
FALSE_CHOICES = {"0", "false", "no", "off", "n"}
FIXED_WEB_HOST = "127.0.0.1"
FIXED_WEB_MASTER_PORT = 45678
FIXED_WEB_AGENT_PORT = 45677
ROLE_DEFAULT_DB_PATHS = {
    "master": "Master.db",
    "agent": "Agent.db",
    "standalone": "Standalone.db",
}
CERT_BLOB_KEY_BY_ENV = {
    "PORTHOUND_TLS_CERT_FILE": "master_tls_cert_pem",
    "PORTHOUND_TLS_KEY_FILE": "master_tls_key_pem",
    "PORTHOUND_CA": "master_ca_pem",
    "PORTHOUND_AGENT_CERT": "agent_tls_cert_pem",
    "PORTHOUND_AGENT_KEY": "agent_tls_key_pem",
}
CERT_SUFFIX_BY_ENV = {
    "PORTHOUND_TLS_CERT_FILE": ".master.cert.pem",
    "PORTHOUND_TLS_KEY_FILE": ".master.key.pem",
    "PORTHOUND_CA": ".ca.pem",
    "PORTHOUND_AGENT_CERT": ".agent.cert.pem",
    "PORTHOUND_AGENT_KEY": ".agent.key.pem",
}
_TEMP_CERT_PATHS = set()
ENV_FLAG_MAP = {
    "role": "PORTHOUND_ROLE",
    "host": "PORTHOUND_HOST",
    "port": "PORTHOUND_PORT",
    "db_path": "PORTHOUND_DB_PATH",
    "debug": "PORTHOUND_DEBUG",
    "api_token": "PORTHOUND_API_TOKEN",
    "api_require_token": "PORTHOUND_API_REQUIRE_TOKEN",
    "cors_allow_origin": "PORTHOUND_CORS_ALLOW_ORIGIN",
    "master": "PORTHOUND_MASTER",
    "master_host": "PORTHOUND_MASTER_HOST",
    "master_ip": "PORTHOUND_MASTER_IP",
    "ip": "PORTHOUND_IP",
    "ca": "PORTHOUND_CA",
    "ca_oneline": "PORTHOUND_CA_ONELINE",
    "tls_enabled": "PORTHOUND_TLS_ENABLED",
    "tls_cert_file": "PORTHOUND_TLS_CERT_FILE",
    "tls_key_file": "PORTHOUND_TLS_KEY_FILE",
    "tls_require_client_cert": "PORTHOUND_TLS_REQUIRE_CLIENT_CERT",
    "agent_cert": "PORTHOUND_AGENT_CERT",
    "agent_key": "PORTHOUND_AGENT_KEY",
    "agent_id": "PORTHOUND_AGENT_ID",
    "agent_token": "PORTHOUND_AGENT_TOKEN",
    "agent_shared_key": "PORTHOUND_AGENT_SHARED_KEY",
    "agent_poll_seconds": "PORTHOUND_AGENT_POLL_SECONDS",
    "agent_http_timeout": "PORTHOUND_AGENT_HTTP_TIMEOUT",
    "agent_task_lease_seconds": "PORTHOUND_AGENT_TASK_LEASE_SECONDS",
    "agent_tls_check_hostname": "PORTHOUND_AGENT_TLS_CHECK_HOSTNAME",
}


class _EnvProxy:
    def __init__(self):
        self._libc = ctypes.CDLL(None)
        self._libc.getenv.argtypes = [ctypes.c_char_p]
        self._libc.getenv.restype = ctypes.c_char_p

        self._setenv_fn = None
        self._uses_setenv = False
        if hasattr(self._libc, "setenv"):
            self._setenv_fn = self._libc.setenv
            self._setenv_fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
            self._setenv_fn.restype = ctypes.c_int
            self._uses_setenv = True
        elif hasattr(self._libc, "_putenv"):
            self._setenv_fn = self._libc._putenv
            self._setenv_fn.argtypes = [ctypes.c_char_p]
            self._setenv_fn.restype = ctypes.c_int
        elif hasattr(self._libc, "putenv"):
            self._setenv_fn = self._libc.putenv
            self._setenv_fn.argtypes = [ctypes.c_char_p]
            self._setenv_fn.restype = ctypes.c_int
        if self._setenv_fn is None:
            raise RuntimeError("Environment setter is unavailable on this platform")
        self._putenv_keepalive = {}

    @staticmethod
    def _encode(value):
        return str(value).encode("utf-8", errors="ignore")

    @staticmethod
    def _decode(value):
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="ignore")
        return str(value)

    @staticmethod
    def _sync_python_os_environ(key, value):
        os_module = sys.modules.get("os")
        if os_module is None:
            return
        env_map = getattr(os_module, "environ", None)
        if env_map is None:
            return
        try:
            env_map[str(key)] = str(value)
        except Exception:
            pass

    def exists(self, key):
        raw = self._libc.getenv(self._encode(key))
        return raw is not None

    def get(self, key, default=None):
        raw = self._libc.getenv(self._encode(key))
        if raw is None:
            return default
        return self._decode(raw)

    def _set(self, key, value):
        key_text = str(key)
        value_text = str(value)
        key_encoded = self._encode(key)
        value_encoded = self._encode(value)
        if self._uses_setenv:
            result = int(self._setenv_fn(key_encoded, value_encoded, 1))
        else:
            pair = key_encoded + b"=" + value_encoded
            self._putenv_keepalive[key_text] = pair
            result = int(self._setenv_fn(self._putenv_keepalive[key_text]))
        if result != 0:
            raise RuntimeError(f"Failed setting env var {key!r}")
        self._sync_python_os_environ(key_text, value_text)

    def __setitem__(self, key, value):
        self._set(key, value)

    def __getitem__(self, key):
        value = self.get(key, None)
        if value is None:
            raise KeyError(key)
        return value

    def setdefault(self, key, default=""):
        if self.exists(key):
            current = self.get(key, "")
            self._sync_python_os_environ(key, current)
            return current
        self._set(key, default)
        return str(default)


environ = _EnvProxy()


def parse_args():
    parser = argparse.ArgumentParser(
        description="PortHound launcher with CLI overrides and env-file fallback."
    )
    parser.add_argument(
        "mode",
        nargs="?",
        help=(
            "Optional enrollment payload (base64/JSON). "
            "`python manage.py` => master, "
            "`python manage.py <BASE64>` => agent."
        ),
    )
    parser.add_argument(
        "enroll_payload",
        nargs="?",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--env-file",
        action="append",
        default=[],
        help="Env file to load (repeatable). Example: certs/master.env",
    )
    parser.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Extra env var override (repeatable).",
    )

    parser.add_argument("--role", choices=("master", "agent", "standalone"))
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--db-path")
    parser.add_argument("--debug", choices=BOOL_CHOICES)
    parser.add_argument("--api-token")
    parser.add_argument("--api-require-token", choices=BOOL_CHOICES)
    parser.add_argument("--cors-allow-origin")

    parser.add_argument("--master")
    parser.add_argument("--master-host")
    parser.add_argument("--master-ip")
    parser.add_argument("--ip")
    parser.add_argument("--ca")
    parser.add_argument("--ca-oneline")

    parser.add_argument("--tls-enabled", choices=BOOL_CHOICES)
    parser.add_argument("--tls-cert-file")
    parser.add_argument("--tls-key-file")
    parser.add_argument("--tls-require-client-cert", choices=BOOL_CHOICES)

    parser.add_argument("--agent-cert")
    parser.add_argument("--agent-key")
    parser.add_argument("--agent-id")
    parser.add_argument("--agent-token")
    parser.add_argument("--agent-shared-key")
    parser.add_argument("--agent-poll-seconds", type=int)
    parser.add_argument("--agent-http-timeout", type=float)
    parser.add_argument("--agent-task-lease-seconds", type=int)
    parser.add_argument("--agent-tls-check-hostname", choices=BOOL_CHOICES)
    parser.add_argument(
        "--agent-enroll",
        "--enroll",
        dest="agent_enroll",
        help="Base64 enrollment payload generated by the master UI.",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Deprecated. Interactive onboarding is disabled and this flag is ignored.",
    )

    return parser.parse_args()


def _apply_positional_mode_and_enroll(args):
    raw_first = str(getattr(args, "mode", "") or "").strip()
    raw_second = str(getattr(args, "enroll_payload", "") or "").strip()

    explicit_role = bool(str(getattr(args, "role", "") or "").strip())
    explicit_enroll = bool(str(getattr(args, "agent_enroll", "") or "").strip())

    # Legacy compatibility: python manage.py <IGNORED> <BASE64>
    if raw_second:
        if not explicit_enroll:
            args.agent_enroll = raw_second
        if not explicit_role:
            args.role = "agent"
        print(
            "[bootstrap] legacy positional format detected: "
            "first positional token ignored, using second token as enroll payload."
        )
        return

    if raw_first:
        normalized_first = raw_first.lower()
        # Backward compatibility for explicit role token in first positional.
        if normalized_first in {"master", "agent", "standalone"}:
            if not explicit_role:
                args.role = normalized_first
            return

        # Preferred path: python manage.py <BASE64|JSON>
        if not explicit_enroll:
            args.agent_enroll = raw_first
        if not explicit_role:
            args.role = "agent"
        return

    # Form: python manage.py
    if not explicit_role:
        args.role = "master"


def _fixed_web_port_for_role(role: str) -> int:
    normalized = normalize_role(role)
    if normalized == "agent":
        return int(FIXED_WEB_AGENT_PORT)
    return int(FIXED_WEB_MASTER_PORT)


def _has_non_interactive_cli_overrides(argv=None):
    tokens = list(argv if argv is not None else sys.argv[1:])
    if not tokens:
        return False
    for token in tokens:
        text = str(token or "").strip()
        if not text:
            continue
        if text == "--interactive":
            continue
        return True
    return False


def _enforce_fixed_web_port(args):
    resolved_role = normalize_role(
        str(getattr(args, "role", "") or "").strip()
        or str(environ.get("PORTHOUND_ROLE", "master") or "").strip()
        or "master"
    )
    fixed_port = _fixed_web_port_for_role(resolved_role)
    requested_host = str(getattr(args, "host", "") or "").strip()
    if requested_host and requested_host != FIXED_WEB_HOST:
        print(
            "[bootstrap] fixed host policy active: "
            f"ignoring requested host '{requested_host}', using {FIXED_WEB_HOST}."
        )
    args.host = str(FIXED_WEB_HOST)
    try:
        requested_port = int(getattr(args, "port", 0) or 0)
    except Exception:
        requested_port = 0
    if requested_port not in {0, int(fixed_port)}:
        print(
            "[bootstrap] fixed port policy active: "
            f"ignoring requested port {requested_port}, "
            f"using {fixed_port} for role '{resolved_role}'."
        )
    args.port = int(fixed_port)


def strip_wrapping_quotes(value: str) -> str:
    value = str(value or "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def load_env_file(path: Path) -> bool:
    if not path.exists():
        return False

    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        if raw.startswith("export "):
            raw = raw[7:].strip()
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        key = key.strip()
        if not key:
            continue
        environ.setdefault(key, strip_wrapping_quotes(value))
    return True


def normalize_role(raw: str) -> str:
    role = str(raw or "").strip().lower()
    if role in {"master", "agent", "standalone"}:
        return role
    return "master"


def default_db_path_for_role(role: str) -> str:
    normalized = normalize_role(role)
    return str(ROLE_DEFAULT_DB_PATHS.get(normalized, "Database.db"))


def _detect_persisted_role_from_db_path(db_path: str, default_role="master") -> str:
    preferred = normalize_role(default_role)
    db_value = str(db_path or "").strip()
    if not db_value:
        return preferred
    found_roles = []
    for role in ("master", "agent", "standalone"):
        profile = load_persisted_role_profile(role, db_value)
        if profile_has_data(profile):
            found_roles.append(role)
    if not found_roles:
        return preferred
    if preferred in found_roles:
        return preferred
    return str(found_roles[0])


def detect_persisted_bootstrap_role(default_role="master") -> str:
    preferred = normalize_role(default_role)
    db_override = str(environ.get("PORTHOUND_DB_PATH", "") or "").strip()
    if db_override:
        return _detect_persisted_role_from_db_path(
            db_override,
            default_role=preferred,
        )

    found_roles = []
    for role in ("master", "agent", "standalone"):
        db_path = default_db_path_for_role(role)
        profile = load_persisted_role_profile(role, db_path)
        if profile_has_data(profile):
            found_roles.append(role)

    if not found_roles:
        return preferred
    if preferred in found_roles:
        return preferred
    return str(found_roles[0])


def resolve_effective_role(args) -> str:
    return normalize_role(
        args.role
        or environ.get("PORTHOUND_ROLE", "master")
    )


def resolve_effective_db_path(args, role: str) -> str:
    arg_value = str(getattr(args, "db_path", "") or "").strip()
    if arg_value:
        return arg_value
    env_value = str(environ.get("PORTHOUND_DB_PATH", "") or "").strip()
    if env_value:
        return env_value
    return default_db_path_for_role(role)


def load_persisted_role_profile(role: str, db_path: str):
    profile = {"env": {}, "blobs": {}}
    db_file = Path(str(db_path or "").strip())
    if not db_file.exists():
        return profile
    conn = None
    cursor = None
    try:
        conn = sqlite3.connect(str(db_file), timeout=3.0)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name = 'launcher_config' LIMIT 1;"
        )
        if cursor.fetchone() is None:
            return profile
        cursor.execute(
            "SELECT env_key, env_value FROM launcher_config WHERE role = ?;",
            (normalize_role(role),),
        )
        for key, value in cursor.fetchall():
            env_key = str(key or "").strip()
            if not env_key:
                continue
            profile["env"][env_key] = str(value or "")

        cursor.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name = 'launcher_blobs' LIMIT 1;"
        )
        if cursor.fetchone() is not None:
            cursor.execute(
                "SELECT blob_key, blob_data FROM launcher_blobs WHERE role = ?;",
                (normalize_role(role),),
            )
            for blob_key, blob_data in cursor.fetchall():
                key = str(blob_key or "").strip()
                if not key:
                    continue
                payload = _safe_b64decode(str(blob_data or ""))
                if payload:
                    profile["blobs"][key] = payload
    except Exception:
        profile = {"env": {}, "blobs": {}}
    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()
    return profile


def apply_persisted_env_defaults(profile: dict):
    env_map = {}
    if isinstance(profile, dict):
        maybe_env = profile.get("env")
        if isinstance(maybe_env, dict):
            env_map = maybe_env
        else:
            env_map = profile
    for env_key, env_value in dict(env_map or {}).items():
        key = str(env_key or "").strip()
        if not key:
            continue
        environ.setdefault(key, str(env_value or ""))


def profile_has_data(profile: dict) -> bool:
    if not isinstance(profile, dict):
        return False
    env_map = profile.get("env")
    blob_map = profile.get("blobs")
    return bool(env_map) or bool(blob_map)


def materialize_persisted_certificate_files(profile: dict):
    blobs = {}
    if isinstance(profile, dict):
        maybe_blobs = profile.get("blobs")
        if isinstance(maybe_blobs, dict):
            blobs = maybe_blobs
    if not blobs:
        return
    for env_key, blob_key in CERT_BLOB_KEY_BY_ENV.items():
        current = str(environ.get(env_key, "") or "").strip()
        if current and Path(current).is_file():
            continue
        payload = bytes(blobs.get(blob_key) or b"")
        if not payload:
            continue
        temp_path = _materialize_temp_cert_file(
            payload,
            suffix=CERT_SUFFIX_BY_ENV.get(env_key, ".pem"),
        )
        if temp_path:
            environ[env_key] = temp_path


def save_persisted_role_profile(role: str, db_path: str):
    role_value = normalize_role(role)
    db_file = Path(str(db_path or "").strip() or default_db_path_for_role(role_value))
    try:
        db_file.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    env_snapshot = {}
    for env_key in set(ENV_FLAG_MAP.values()) | {"PORTHOUND_ROLE"}:
        value = str(environ.get(env_key, "") or "").strip()
        if value:
            env_snapshot[env_key] = value
    env_snapshot["PORTHOUND_ROLE"] = role_value

    blob_snapshot = {}
    for env_key, blob_key in CERT_BLOB_KEY_BY_ENV.items():
        file_value = str(environ.get(env_key, "") or "").strip()
        if not file_value:
            continue
        file_path = Path(file_value)
        if not file_path.is_file():
            continue
        try:
            payload = file_path.read_bytes()
        except Exception:
            payload = b""
        encoded = _safe_b64encode(payload)
        if encoded:
            blob_snapshot[blob_key] = encoded

    if "master_ca_pem" not in blob_snapshot:
        inline_ca = str(environ.get("PORTHOUND_CA_ONELINE", "") or "").strip()
        ca_payload = _ca_oneline_to_pem_bytes(inline_ca)
        encoded_ca = _safe_b64encode(ca_payload)
        if encoded_ca:
            blob_snapshot["master_ca_pem"] = encoded_ca

    conn = None
    cursor = None
    try:
        conn = sqlite3.connect(str(db_file), timeout=3.0)
        cursor = conn.cursor()
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS launcher_config ("
            "role TEXT NOT NULL,"
            "env_key TEXT NOT NULL,"
            "env_value TEXT NOT NULL,"
            "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "PRIMARY KEY (role, env_key)"
            ");"
        )
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS launcher_blobs ("
            "role TEXT NOT NULL,"
            "blob_key TEXT NOT NULL,"
            "blob_data TEXT NOT NULL,"
            "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "PRIMARY KEY (role, blob_key)"
            ");"
        )
        existing_blobs = {}
        cursor.execute(
            "SELECT blob_key, blob_data FROM launcher_blobs WHERE role = ?;",
            (role_value,),
        )
        for blob_key, blob_data in cursor.fetchall():
            key = str(blob_key or "").strip()
            data = str(blob_data or "").strip()
            if key and data:
                existing_blobs[key] = data
        merged_blob_snapshot = dict(existing_blobs)
        merged_blob_snapshot.update(blob_snapshot)

        cursor.execute("DELETE FROM launcher_config WHERE role = ?;", (role_value,))
        for env_key, env_value in sorted(env_snapshot.items()):
            cursor.execute(
                "INSERT INTO launcher_config (role, env_key, env_value) "
                "VALUES (?, ?, ?);",
                (role_value, env_key, env_value),
            )
        cursor.execute("DELETE FROM launcher_blobs WHERE role = ?;", (role_value,))
        for blob_key, blob_data in sorted(merged_blob_snapshot.items()):
            cursor.execute(
                "INSERT INTO launcher_blobs (role, blob_key, blob_data) "
                "VALUES (?, ?, ?);",
                (role_value, blob_key, blob_data),
            )
        conn.commit()
    except Exception as exc:
        print(f"[bootstrap] profile save skipped: {exc}")
    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()


def default_env_files(role: str):
    if role == "agent":
        return [Path("certs/agent.env")]
    if role == "master":
        return [Path("certs/master.env")]
    return []


def load_env_fallbacks(args):
    target_files = [Path(path) for path in args.env_file]
    if not target_files:
        role = normalize_role(args.role or environ.get("PORTHOUND_ROLE", "master"))
        target_files = default_env_files(role)

    for env_path in target_files:
        if not load_env_file(env_path):
            print(f"[bootstrap] env file not found: {env_path}")


def parse_assignment(raw: str):
    if "=" not in raw:
        raise ValueError(f"invalid --env value '{raw}', expected KEY=VALUE")
    key, value = raw.split("=", 1)
    key = key.strip()
    if not key:
        raise ValueError(f"invalid --env value '{raw}', empty key")
    return key, value


def _cleanup_temp_cert_files():
    for temp_path in list(_TEMP_CERT_PATHS):
        try:
            Path(temp_path).unlink(missing_ok=True)
        except Exception:
            continue


atexit.register(_cleanup_temp_cert_files)


def _safe_b64decode(value: str) -> bytes:
    raw = str(value or "").strip()
    if not raw:
        return b""
    try:
        return base64.b64decode(raw.encode("ascii"), validate=True)
    except Exception:
        return b""


def _safe_b64encode(payload: bytes) -> str:
    data = bytes(payload or b"")
    if not data:
        return ""
    return base64.b64encode(data).decode("ascii")


def _load_agent_enroll_payload(raw: str) -> dict:
    text = str(raw or "").strip()
    if not text:
        return {}
    if text.startswith("{"):
        json_text = text
    else:
        decoded = _safe_b64decode(text)
        if not decoded:
            return {}
        json_text = decoded.decode("utf-8", errors="ignore")
    try:
        payload = json.loads(json_text)
    except Exception:
        return {}
    if not isinstance(payload, dict):
        return {}
    return payload


def _apply_agent_enroll_payload(args, payload: dict, allow_override=False) -> bool:
    if not isinstance(payload, dict) or not payload:
        return False

    def _set_arg(name, value):
        if value in (None, ""):
            return
        current = getattr(args, name, None)
        if not allow_override and current not in (None, ""):
            return
        setattr(args, name, value)

    token = (
        payload.get("agent_token")
        or payload.get("token")
        or payload.get("agent_key")
        or payload.get("shared_key")
    )
    agent_id = payload.get("agent_id") or payload.get("id")
    master = payload.get("master") or payload.get("master_url") or payload.get("master_base")
    master_host = payload.get("master_host") or ""
    master_ip = payload.get("master_ip") or ""
    master_port = payload.get("master_port") or 45678

    if not master and (master_host or master_ip):
        host_value = str(master_host or master_ip or "").strip()
        if host_value:
            master = f"http://{host_value}:{int(master_port)}"

    if master and "://" not in str(master):
        master = f"http://{master}"

    if master:
        _set_arg("master", str(master))
        if not master_host or not master_ip:
            host_guess, ip_guess, _ = _master_host_port_defaults(master)
            master_host = master_host or host_guess
            master_ip = master_ip or ip_guess

    _set_arg("agent_id", str(agent_id or ""))
    _set_arg("agent_token", str(token or ""))
    _set_arg("agent_shared_key", str(token or ""))
    _set_arg("master_host", str(master_host or ""))
    _set_arg("master_ip", str(master_ip or ""))

    poll_seconds = payload.get("agent_poll_seconds")
    http_timeout = payload.get("agent_http_timeout")
    if poll_seconds is not None:
        try:
            _set_arg("agent_poll_seconds", int(poll_seconds))
        except Exception:
            pass
    if http_timeout is not None:
        try:
            _set_arg("agent_http_timeout", float(http_timeout))
        except Exception:
            pass

    tls_check_hostname = payload.get("agent_tls_check_hostname")
    if tls_check_hostname is not None:
        _set_arg("agent_tls_check_hostname", _normalize_bool_token(tls_check_hostname, default="0"))

    ip_value = payload.get("ip") or payload.get("agent_ip")
    if ip_value:
        _set_arg("ip", str(ip_value))

    if not str(getattr(args, "role", "") or "").strip():
        args.role = "agent"
    return True


def _ca_oneline_to_pem_bytes(value: str) -> bytes:
    text = str(value or "").strip()
    if not text:
        return b""
    pem = text.replace("\r", "").replace("\\n", "\n").strip()
    if not pem:
        return b""
    return (pem + "\n").encode("utf-8", errors="ignore")


def _materialize_temp_cert_file(blob_data: bytes, suffix=".pem") -> str:
    payload = bytes(blob_data or b"")
    if not payload:
        return ""
    handle = tempfile.NamedTemporaryFile(
        mode="wb",
        prefix="porthound-cert-",
        suffix=str(suffix or ".pem"),
        delete=False,
    )
    try:
        handle.write(payload)
        handle.flush()
        output_path = str(handle.name)
    finally:
        handle.close()
    try:
        Path(output_path).chmod(0o600)
    except Exception:
        pass
    _TEMP_CERT_PATHS.add(output_path)
    return output_path


def _is_interactive_terminal():
    return bool(sys.stdin.isatty() and sys.stdout.isatty())


def _env_or_arg(args, arg_name, fallback=""):
    current = getattr(args, arg_name)
    if current not in (None, ""):
        return str(current)
    env_name = ENV_FLAG_MAP.get(arg_name, "")
    if env_name:
        env_value = environ.get(env_name, "")
        if str(env_value).strip():
            return str(env_value)
    return str(fallback)


def _current_config_value(args, arg_name, fallback=""):
    return str(_env_or_arg(args, arg_name, fallback)).strip()


def _master_host_port_defaults(master_value):
    raw = str(master_value or "").strip()
    if not raw:
        return "", "", 45678
    if "://" not in raw:
        raw = f"http://{raw}"
    try:
        parsed = urlsplit(raw)
    except Exception:
        return "", "", 45678
    host = str(parsed.hostname or "").strip()
    try:
        ipaddress.IPv4Address(host)
        ip_hint = host
    except Exception:
        ip_hint = ""
    try:
        port = int(parsed.port or 45678)
    except Exception:
        port = 45678
    return host, ip_hint, port


def _missing_required_settings(args):
    role = normalize_role(getattr(args, "role", "") or environ.get("PORTHOUND_ROLE", "master"))
    missing = []

    def _has_value(arg_name):
        return bool(_current_config_value(args, arg_name, ""))

    if role in {"master", "standalone"}:
        if not _has_value("host"):
            missing.append("host")
        if not _has_value("port"):
            missing.append("port")
        if not _has_value("db_path"):
            missing.append("db_path")

    if role == "agent":
        if not _has_value("master"):
            missing.append("master")
        if not _has_value("agent_id"):
            missing.append("agent_id")
        if not (_has_value("agent_token") or _has_value("agent_shared_key")):
            missing.append("agent_token")
        if not _has_value("agent_poll_seconds"):
            missing.append("agent_poll_seconds")
        if not _has_value("agent_http_timeout"):
            missing.append("agent_http_timeout")

    return missing


def _normalize_bool_token(value, default="0"):
    raw = str(value if value is not None else "").strip().lower()
    if not raw:
        raw = str(default).strip().lower()
    if raw in TRUE_CHOICES:
        return "1"
    if raw in FALSE_CHOICES:
        return "0"
    if raw in {"1", "0"}:
        return raw
    return "1" if str(default).strip().lower() in TRUE_CHOICES else "0"


def _prompt_text(label, default="", required=False, secret=False):
    default_text = str(default or "")
    if default_text:
        suffix = " [set]" if secret else f" [{default_text}]"
    else:
        suffix = ""
    while True:
        try:
            if secret:
                value = getpass.getpass(f"{label}{suffix}: ")
            else:
                value = input(f"{label}{suffix}: ")
        except EOFError:
            value = ""
        value = str(value or "").strip()
        if value:
            return value
        if default_text:
            return default_text
        if not required:
            return ""
        print(f"[bootstrap] {label} is required.")


def _prompt_int(label, default, min_value=None, max_value=None):
    default_value = str(default)
    while True:
        raw = _prompt_text(label, default=default_value, required=True)
        try:
            number = int(raw)
        except Exception:
            print(f"[bootstrap] {label} must be an integer.")
            continue
        if min_value is not None and number < int(min_value):
            print(f"[bootstrap] {label} must be >= {min_value}.")
            continue
        if max_value is not None and number > int(max_value):
            print(f"[bootstrap] {label} must be <= {max_value}.")
            continue
        return number


def _prompt_float(label, default, min_value=None):
    default_value = str(default)
    while True:
        raw = _prompt_text(label, default=default_value, required=True)
        try:
            number = float(raw)
        except Exception:
            print(f"[bootstrap] {label} must be numeric.")
            continue
        if min_value is not None and number < float(min_value):
            print(f"[bootstrap] {label} must be >= {min_value}.")
            continue
        return number


def _prompt_bool(label, default="0"):
    normalized_default = _normalize_bool_token(default, default=default)
    default_hint = "yes" if normalized_default == "1" else "no"
    while True:
        raw = _prompt_text(label, default=default_hint, required=True).strip().lower()
        if raw in TRUE_CHOICES:
            return "1"
        if raw in FALSE_CHOICES:
            return "0"
        print("[bootstrap] Use yes/no (or 1/0).")


def _select_role(default_role="master"):
    selected_default = normalize_role(default_role)
    while True:
        role = _prompt_text(
            "Role (master/agent/standalone)",
            default=selected_default,
            required=True,
        ).strip().lower()
        if role in {"master", "agent", "standalone"}:
            return role
        print("[bootstrap] Role must be master, agent or standalone.")


def _preload_role_for_env_selection(args):
    if not _is_interactive_terminal():
        return
    if args.role:
        return
    env_role = normalize_role(environ.get("PORTHOUND_ROLE", "master"))
    args.role = _select_role(env_role)


def run_interactive_onboarding(args):
    if not _is_interactive_terminal():
        return

    role = normalize_role(args.role or "")
    if role not in {"master", "agent", "standalone"}:
        role_default = normalize_role(environ.get("PORTHOUND_ROLE", "master"))
        role = _select_role(role_default)
    args.role = role
    if str(getattr(args, "db_path", "") or "").strip() == "":
        args.db_path = default_db_path_for_role(role)

    if role in {"master", "standalone"}:
        args.host = str(FIXED_WEB_HOST)
        args.port = _fixed_web_port_for_role(role)
        if str(getattr(args, "db_path", "") or "").strip() == "":
            args.db_path = _env_or_arg(args, "db_path", default_db_path_for_role(role))
        args.tls_enabled = "0"
        args.tls_require_client_cert = "0"

    if role == "agent":
        if not str(getattr(args, "agent_enroll", "") or "").strip():
            enroll_raw = _prompt_text("Enroll base64 (opcional)", "", required=False)
            if enroll_raw:
                payload = _load_agent_enroll_payload(enroll_raw)
                if payload:
                    _apply_agent_enroll_payload(args, payload, allow_override=True)
                    args.agent_enroll = enroll_raw
                    print("[bootstrap] enrollment payload loaded. Press ENTER to accept defaults.")
                else:
                    print("[bootstrap] invalid enrollment payload, continue manual setup.")
        default_master_raw = _env_or_arg(args, "master", "")
        default_host, default_ip, default_port = _master_host_port_defaults(default_master_raw)
        args.agent_id = _prompt_text(
            "agent_id",
            _env_or_arg(args, "agent_id", ""),
            required=True,
        )
        token_default = _env_or_arg(
            args,
            "agent_token",
            _env_or_arg(args, "agent_shared_key", ""),
        )
        args.agent_token = _prompt_text(
            "token",
            token_default,
            required=True,
            secret=True,
        )
        args.agent_shared_key = str(args.agent_token or "")
        args.master_ip = _prompt_text(
            "master_ip",
            _env_or_arg(args, "master_ip", default_ip),
            required=True,
        )
        args.master_host = _prompt_text(
            "master_host",
            _env_or_arg(args, "master_host", default_host),
            required=True,
        )
        preferred_master_host = str(args.master_host or "").strip() or str(args.master_ip or "").strip()
        args.master = f"http://{preferred_master_host}:{int(default_port)}"
        args.agent_poll_seconds = int(_env_or_arg(args, "agent_poll_seconds", "8") or 8)
        args.agent_http_timeout = float(_env_or_arg(args, "agent_http_timeout", "20") or 20.0)
        args.agent_tls_check_hostname = "0"
        args.host = str(FIXED_WEB_HOST)
        args.port = _fixed_web_port_for_role(role)
        if str(getattr(args, "db_path", "") or "").strip() == "":
            args.db_path = _env_or_arg(args, "db_path", default_db_path_for_role(role))


def _should_auto_interactive(
    args,
    has_profile=False,
    missing_required=None,
    has_non_interactive_cli_overrides=False,
):
    _ = (has_profile, has_non_interactive_cli_overrides)
    if not _is_interactive_terminal() or bool(args.interactive):
        return False
    if list(missing_required or []):
        return True
    return False


def apply_cli_overrides(args):
    for arg_name, env_name in ENV_FLAG_MAP.items():
        value = getattr(args, arg_name)
        if value is None:
            continue
        environ[env_name] = str(value)

    token_value = str(getattr(args, "agent_token", "") or "").strip()
    shared_value = str(getattr(args, "agent_shared_key", "") or "").strip()
    if token_value:
        environ["PORTHOUND_AGENT_TOKEN"] = token_value
        environ["PORTHOUND_AGENT_SHARED_KEY"] = token_value
    elif shared_value:
        environ["PORTHOUND_AGENT_TOKEN"] = shared_value
        environ["PORTHOUND_AGENT_SHARED_KEY"] = shared_value

    for assignment in args.env:
        key, value = parse_assignment(assignment)
        environ[key] = value


def main():
    args = parse_args()
    _apply_positional_mode_and_enroll(args)
    _enforce_fixed_web_port(args)
    if bool(getattr(args, "interactive", False)):
        print(
            "[bootstrap] --interactive is deprecated and ignored. "
            "Use CLI flags, env vars or enroll base64 payload."
        )
    if str(getattr(args, "agent_enroll", "") or "").strip():
        payload = _load_agent_enroll_payload(args.agent_enroll)
        if payload:
            _apply_agent_enroll_payload(args, payload, allow_override=False)
        else:
            print("[bootstrap] invalid enrollment payload, ignoring.")
    if not str(getattr(args, "role", "") or "").strip():
        args.role = "master"

    load_env_fallbacks(args)
    _enforce_fixed_web_port(args)

    initial_role = resolve_effective_role(args)
    if (
        str(getattr(args, "db_path", "") or "").strip() == ""
        and str(environ.get("PORTHOUND_DB_PATH", "") or "").strip() == ""
    ):
        args.db_path = default_db_path_for_role(initial_role)

    initial_db_path = resolve_effective_db_path(args, initial_role)
    persisted_profile = load_persisted_role_profile(initial_role, initial_db_path)
    if profile_has_data(persisted_profile):
        apply_persisted_env_defaults(persisted_profile)

    resolved_role = resolve_effective_role(args)
    resolved_db_path = resolve_effective_db_path(args, resolved_role)
    if (
        (resolved_role != initial_role or resolved_db_path != initial_db_path)
        and not profile_has_data(persisted_profile)
    ):
        persisted_profile = load_persisted_role_profile(resolved_role, resolved_db_path)
        if profile_has_data(persisted_profile):
            apply_persisted_env_defaults(persisted_profile)

    if str(getattr(args, "db_path", "") or "").strip() == "":
        args.db_path = resolve_effective_db_path(args, resolve_effective_role(args))

    missing_required = _missing_required_settings(args)
    if missing_required:
        print(
            "[bootstrap] missing settings detected: "
            + ", ".join(missing_required)
            + "."
        )
        print(
            "[bootstrap] interactive onboarding is disabled. "
            "Provide missing settings via flags, env vars or enroll payload."
        )
        raise SystemExit(2)

    final_role_hint = resolve_effective_role(args)
    if (
        str(getattr(args, "db_path", "") or "").strip() == ""
        and str(environ.get("PORTHOUND_DB_PATH", "") or "").strip() == ""
    ):
        args.db_path = default_db_path_for_role(final_role_hint)

    _enforce_fixed_web_port(args)
    apply_cli_overrides(args)
    final_role = normalize_role(environ.get("PORTHOUND_ROLE", final_role_hint))
    final_db_path = (
        str(environ.get("PORTHOUND_DB_PATH", "") or "").strip()
        or default_db_path_for_role(final_role)
    )
    environ.setdefault("PORTHOUND_TLS_ENABLED", "0")
    if final_role in {"master", "standalone"}:
        environ.setdefault("PORTHOUND_TLS_REQUIRE_CLIENT_CERT", "0")
    environ.setdefault("PORTHOUND_DB_PATH", final_db_path)
    save_persisted_role_profile(final_role, final_db_path)
    startup_profile = load_persisted_role_profile(final_role, final_db_path)
    materialize_persisted_certificate_files(startup_profile)

    from app import main as app_main

    app_main()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[shutdown] interrupted by user (Ctrl+C).")
        raise SystemExit(130)
