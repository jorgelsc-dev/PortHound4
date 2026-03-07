import argparse
import os
from pathlib import Path


BOOL_CHOICES = ("0", "1", "false", "true", "no", "yes", "off", "on")
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
    parser.add_argument("--agent-poll-seconds", type=int)
    parser.add_argument("--agent-http-timeout", type=float)
    parser.add_argument("--agent-task-lease-seconds", type=int)
    parser.add_argument("--agent-tls-check-hostname", choices=BOOL_CHOICES)

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
    load_env_fallbacks(args)
    apply_cli_overrides(args)

    from app import main as app_main

    app_main()


if __name__ == "__main__":
    main()
