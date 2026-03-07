import argparse
import getpass
import os
import sys
from pathlib import Path


BOOL_CHOICES = ("0", "1", "false", "true", "no", "yes", "off", "on")
TRUE_CHOICES = {"1", "true", "yes", "on", "y"}
FALSE_CHOICES = {"0", "false", "no", "off", "n"}
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
    "agent_shared_key": "PORTHOUND_AGENT_SHARED_KEY",
    "agent_poll_seconds": "PORTHOUND_AGENT_POLL_SECONDS",
    "agent_http_timeout": "PORTHOUND_AGENT_HTTP_TIMEOUT",
    "agent_task_lease_seconds": "PORTHOUND_AGENT_TASK_LEASE_SECONDS",
    "agent_tls_check_hostname": "PORTHOUND_AGENT_TLS_CHECK_HOSTNAME",
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="PortHound launcher with CLI overrides and env-file fallback."
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
    parser.add_argument("--agent-shared-key")
    parser.add_argument("--agent-poll-seconds", type=int)
    parser.add_argument("--agent-http-timeout", type=float)
    parser.add_argument("--agent-task-lease-seconds", type=int)
    parser.add_argument("--agent-tls-check-hostname", choices=BOOL_CHOICES)
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Launch interactive onboarding prompts.",
    )

    return parser.parse_args()


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
        os.environ.setdefault(key, strip_wrapping_quotes(value))
    return True


def normalize_role(raw: str) -> str:
    role = str(raw or "").strip().lower()
    if role in {"master", "agent", "standalone"}:
        return role
    return "master"


def default_env_files(role: str):
    if role == "agent":
        return [Path("certs/agent.env")]
    if role == "master":
        return [Path("certs/master.env")]
    return []


def load_env_fallbacks(args):
    target_files = [Path(path) for path in args.env_file]
    if not target_files:
        role = normalize_role(args.role or os.environ.get("PORTHOUND_ROLE", "master"))
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


def _is_interactive_terminal():
    return bool(sys.stdin.isatty() and sys.stdout.isatty())


def _env_or_arg(args, arg_name, fallback=""):
    current = getattr(args, arg_name)
    if current not in (None, ""):
        return str(current)
    env_name = ENV_FLAG_MAP.get(arg_name, "")
    if env_name:
        env_value = os.environ.get(env_name, "")
        if str(env_value).strip():
            return str(env_value)
    return str(fallback)


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
    env_role = normalize_role(os.environ.get("PORTHOUND_ROLE", "master"))
    args.role = _select_role(env_role)


def run_interactive_onboarding(args):
    if not _is_interactive_terminal():
        return

    role_default = normalize_role(args.role or os.environ.get("PORTHOUND_ROLE", "master"))
    args.role = _select_role(role_default)
    role = normalize_role(args.role)

    if role in {"master", "standalone"}:
        args.host = _prompt_text("Host bind", _env_or_arg(args, "host", "0.0.0.0"), required=True)
        args.port = _prompt_int("Port", _env_or_arg(args, "port", "45678"), min_value=1, max_value=65535)
        args.db_path = _prompt_text("SQLite DB path", _env_or_arg(args, "db_path", "Database.db"), required=True)
        args.api_token = _prompt_text(
            "Admin API token (optional)",
            _env_or_arg(args, "api_token", ""),
            required=False,
            secret=True,
        )

        tls_default = _normalize_bool_token(_env_or_arg(args, "tls_enabled", "1"), default="1")
        args.tls_enabled = _prompt_bool("Enable TLS", default=tls_default)
        if args.tls_enabled == "1":
            args.tls_cert_file = _prompt_text(
                "TLS cert file",
                _env_or_arg(args, "tls_cert_file", "certs/master/master.cert.pem"),
                required=True,
            )
            args.tls_key_file = _prompt_text(
                "TLS key file",
                _env_or_arg(args, "tls_key_file", "certs/master/master.key.pem"),
                required=True,
            )
            client_cert_default = _normalize_bool_token(
                _env_or_arg(args, "tls_require_client_cert", "0"),
                default="0",
            )
            args.tls_require_client_cert = _prompt_bool(
                "Require client certificate (mTLS)",
                default=client_cert_default,
            )
        else:
            args.tls_require_client_cert = "0"

    if role == "agent":
        args.master = _prompt_text(
            "Master URL (http://host:port or https://host:port)",
            _env_or_arg(args, "master", ""),
            required=True,
        )
        args.agent_id = _prompt_text(
            "Agent identifier",
            _env_or_arg(args, "agent_id", ""),
            required=True,
        )
        args.agent_shared_key = _prompt_text(
            "Agent shared key",
            _env_or_arg(args, "agent_shared_key", ""),
            required=True,
            secret=True,
        )
        args.agent_poll_seconds = _prompt_int(
            "Poll seconds",
            _env_or_arg(args, "agent_poll_seconds", "8"),
            min_value=2,
        )
        args.agent_http_timeout = _prompt_float(
            "HTTP timeout (seconds)",
            _env_or_arg(args, "agent_http_timeout", "20"),
            min_value=2.0,
        )
        tls_host_default = _normalize_bool_token(
            _env_or_arg(args, "agent_tls_check_hostname", "1"),
            default="1",
        )
        args.agent_tls_check_hostname = _prompt_bool(
            "Validate TLS hostname",
            default=tls_host_default,
        )
        if str(args.master).strip().lower().startswith("https://"):
            args.ca_oneline = _prompt_text(
                "CA one-line (optional)",
                _env_or_arg(args, "ca_oneline", ""),
                required=False,
            )


def _should_auto_interactive(args):
    if not _is_interactive_terminal() or bool(args.interactive):
        return False
    if args.env_file or args.env:
        return False
    for arg_name in ENV_FLAG_MAP.keys():
        if arg_name == "role":
            continue
        value = getattr(args, arg_name)
        if value not in (None, ""):
            return False
    return True


def apply_cli_overrides(args):
    for arg_name, env_name in ENV_FLAG_MAP.items():
        value = getattr(args, arg_name)
        if value is None:
            continue
        os.environ[env_name] = str(value)

    for assignment in args.env:
        key, value = parse_assignment(assignment)
        os.environ[key] = value


def main():
    args = parse_args()
    auto_interactive = _should_auto_interactive(args)
    if args.interactive or auto_interactive:
        _preload_role_for_env_selection(args)
    load_env_fallbacks(args)
    if args.interactive or auto_interactive:
        run_interactive_onboarding(args)
    apply_cli_overrides(args)

    from app import main as app_main

    app_main()


if __name__ == "__main__":
    main()
