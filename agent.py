import base64
import json
import socket
import ssl
import sys
import time
import uuid
from ipaddress import ip_address, ip_network
from pathlib import Path
from urllib.parse import urlsplit

import settings


def _resolve_app_module():
    module = sys.modules.get("app")
    if module is not None:
        return module
    main_module = sys.modules.get("__main__")
    if (
        main_module is not None
        and str(getattr(main_module, "__file__", "") or "").endswith("app.py")
        and hasattr(main_module, "app")
        and hasattr(main_module, "scan_db")
    ):
        return main_module
    import app as imported_app_module

    return imported_app_module


app_module = _resolve_app_module()


def normalize_master_base_url(value):
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = f"http://{raw}"
    parsed = urlsplit(raw)
    scheme = str(parsed.scheme or "").strip().lower()
    if scheme != "http":
        raise ValueError("PORTHOUND_MASTER must use http://")
    netloc = str(parsed.netloc or "").strip()
    if not netloc:
        raise ValueError("PORTHOUND_MASTER host is missing")
    host = str(parsed.hostname or "").strip().lower()
    if host in {"0.0.0.0", "::"}:
        raise ValueError(
            "PORTHOUND_MASTER cannot use 0.0.0.0 or ::. "
            "Use a real master host/IP reachable by the agent."
        )
    base_path = str(parsed.path or "").rstrip("/")
    return f"{scheme}://{netloc}{base_path}"


def post_json_over_http(url, payload, timeout_seconds):
    parsed = urlsplit(str(url))
    scheme = str(parsed.scheme or "").strip().lower()
    if scheme != "http":
        raise RuntimeError("Only http:// URLs are supported")
    host = str(parsed.hostname or "").strip()
    if not host:
        raise RuntimeError("Invalid URL host")
    port = int(parsed.port or 80)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    body = json.dumps(payload).encode("utf-8")
    host_header = host if port == 80 else f"{host}:{port}"
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


def post_json_over_tls(url, payload, ssl_context, timeout_seconds):
    return post_json_over_http(url, payload, timeout_seconds)


def build_agent_ssl_context(allow_missing_client_cert=False, skip_client_cert=False):
    ca_file = app_module.resolve_ca_file_path(required=False)
    if ca_file:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    else:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    cert_file = str(getattr(settings, "AGENT_CERT_FILE", "") or "").strip()
    key_file = str(getattr(settings, "AGENT_KEY_FILE", "") or "").strip()
    if skip_client_cert:
        cert_file = ""
        key_file = ""
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


def _target_proto_set(proto_value):
    proto = str(proto_value or "").strip().lower()
    if proto == "sctp":
        return {"sctp", "stcp"}
    return {proto}


class AgentRuntime:
    def __init__(
        self,
        db,
        master_base_url="",
        agent_id="",
        agent_token="",
        poll_seconds=None,
        http_timeout=None,
    ):
        self.db = db
        configured_master = (
            str(master_base_url).strip()
            or str(getattr(settings, "PORTHOUND_MASTER", "")).strip()
        )
        self.master_base_url = normalize_master_base_url(configured_master)
        if not self.master_base_url:
            raise RuntimeError("PORTHOUND_MASTER is required in agent mode")
        parsed_master = urlsplit(self.master_base_url)
        self.master_scheme = str(parsed_master.scheme or "").strip().lower()
        if self.master_scheme != "http":
            raise RuntimeError("PORTHOUND_MASTER must use http:// (TLS disabled by policy)")
        master_host = str(urlsplit(self.master_base_url).hostname or "").strip().lower()
        if master_host in {"127.0.0.1", "localhost", "::1"}:
            print(
                "[agent] warning: PORTHOUND_MASTER uses loopback "
                f"({master_host}); this only works when master and agent run on the same host"
            )
        self.agent_token = str(agent_token or "").strip()
        if not self.agent_token:
            self.agent_token = str(getattr(settings, "AGENT_TOKEN", "") or "").strip()
        if not self.agent_token:
            self.agent_token = str(getattr(settings, "AGENT_SHARED_KEY", "") or "").strip()
        if not self.agent_token:
            raise RuntimeError("PORTHOUND_AGENT_TOKEN is required in agent mode")
        self.agent_shared_key = self.agent_token
        self.auth_mode = "token"
        if poll_seconds is None:
            poll_seconds = getattr(settings, "AGENT_POLL_SECONDS", 8)
        if http_timeout is None:
            http_timeout = getattr(settings, "AGENT_HTTP_TIMEOUT", 20.0)
        self.poll_seconds = int(poll_seconds or 8)
        self.http_timeout = float(http_timeout or 20.0)
        configured_agent_id = str(agent_id or "").strip()
        if not configured_agent_id:
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
        if self.agent_token:
            payload["token"] = self.agent_token
        return payload

    def _post(self, path, payload):
        response = post_json_over_tls(
            url=self._endpoint(path),
            payload=payload,
            ssl_context=None,
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
        response = self._post("/api/cluster/agent/register", self._auth_payload())
        if str(response.get("status", "")).strip().lower() != "ok":
            raise RuntimeError(f"Agent register failed: {response}")
        self.registered = True
        return response

    def pull_task(self):
        response = self._post("/api/cluster/agent/task/pull", self._auth_payload())
        status = str(response.get("status", "")).strip().lower()
        if status == "ok":
            return response.get("task")
        if status == "empty":
            return None
        raise RuntimeError(f"Agent pull task failed: {response}")

    def submit_task(self, payload):
        outbound = dict(payload or {})
        if self.agent_token:
            outbound["token"] = self.agent_token
        response = self._post("/api/cluster/agent/task/submit", outbound)
        if str(response.get("status", "")).strip().lower() != "ok":
            raise RuntimeError(f"Agent submit failed: {response}")
        return response

    def send_heartbeat(
        self,
        task_id="",
        master_target_id=None,
        progress=0.0,
        status="active",
        result_delta=None,
    ):
        payload = self._auth_payload()
        payload["progress"] = float(progress if progress is not None else 0.0)
        payload["status"] = str(status or "").strip().lower() or "active"
        if task_id:
            payload["task_id"] = str(task_id).strip()
        if master_target_id is not None and str(master_target_id).strip():
            payload["master_target_id"] = int(master_target_id)
        if isinstance(result_delta, dict) and self._result_has_rows(result_delta):
            payload["result"] = result_delta
        return self._post("/api/cluster/agent/heartbeat", payload)

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
        target_candidate = app_module.normalize_target_item(
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

    def _result_has_rows(self, result_payload):
        if not isinstance(result_payload, dict):
            return False
        for key in ("ports", "tags", "banners", "favicons"):
            rows = result_payload.get(key, [])
            if isinstance(rows, list) and rows:
                return True
        return False

    def _new_result_markers(self):
        return {"ports": set(), "tags": set(), "banners": set(), "favicons": set()}

    def _commit_result_markers(self, sent_markers, pending_markers):
        if not isinstance(sent_markers, dict) or not isinstance(pending_markers, dict):
            return
        for key in ("ports", "tags", "banners", "favicons"):
            current = sent_markers.get(key)
            pending = pending_markers.get(key)
            if not isinstance(current, set) or not isinstance(pending, set) or not pending:
                continue
            current.update(pending)

    def wait_target_completion(
        self,
        target_id,
        timeout_seconds=86400,
        task_id="",
        master_target_id=None,
        heartbeat_result_collector=None,
    ):
        started_at = time.time()
        last_progress = 0.0
        last_status = "active"
        abort_action = ""
        heartbeat_interval = float(
            getattr(settings, "AGENT_HEARTBEAT_SECONDS", 2.0) or 2.0
        )
        if heartbeat_interval < 1.0:
            heartbeat_interval = 1.0
        next_heartbeat_at = 0.0
        progress_log_interval = 10.0
        next_progress_log_at = started_at + 5.0
        stall_timeout_seconds = max(
            90.0,
            float(getattr(settings, "AGENT_TASK_STALL_SECONDS", 300.0) or 300.0),
        )
        last_progress_mark = -1.0
        last_progress_change_at = started_at
        while True:
            row = self.db.select_target_by_id(target_id)
            if not row:
                return 0.0, "stopped", abort_action
            try:
                last_progress = float(row.get("progress", 0.0) or 0.0)
            except Exception:
                last_progress = 0.0
            last_status = str(row.get("status", "active") or "active").strip().lower()
            now_ts = time.time()
            if last_progress > (last_progress_mark + 0.0001):
                last_progress_mark = last_progress
                last_progress_change_at = now_ts
            if now_ts >= next_progress_log_at:
                log_task_id = str(task_id or "-").strip()
                log_master_target = (
                    str(master_target_id).strip()
                    if master_target_id not in (None, "")
                    else str(target_id)
                )
                print(
                    "[agent] task progress "
                    f"task_id={log_task_id} target={log_master_target} "
                    f"status={last_status} progress={round(last_progress, 2)}%"
                )
                next_progress_log_at = now_ts + progress_log_interval
            if now_ts >= next_heartbeat_at:
                heartbeat_result = None
                heartbeat_commit = None
                if callable(heartbeat_result_collector):
                    try:
                        collected = heartbeat_result_collector(last_progress, last_status)
                        if (
                            isinstance(collected, tuple)
                            and len(collected) == 2
                        ):
                            heartbeat_result = collected[0]
                            heartbeat_commit = collected[1]
                        elif isinstance(collected, dict):
                            heartbeat_result = collected
                    except Exception:
                        heartbeat_result = None
                        heartbeat_commit = None
                try:
                    response = self.send_heartbeat(
                        task_id=task_id,
                        master_target_id=master_target_id,
                        progress=last_progress,
                        status=last_status,
                        result_delta=heartbeat_result,
                    )
                    if callable(heartbeat_commit):
                        try:
                            heartbeat_commit()
                        except Exception:
                            pass
                    desired_action = (
                        str((response or {}).get("desired_action", "")).strip().lower()
                    )
                    if desired_action in {"stop", "restart", "delete"}:
                        abort_action = desired_action
                        if desired_action == "delete":
                            self.cleanup_local_target(target_id)
                        else:
                            try:
                                self.db.set_target_status(
                                    data={"id": target_id, "status": "stopped"}
                                )
                            except Exception:
                                pass
                        return last_progress, "stopped", abort_action
                    if task_id and (response or {}).get("lease_renewed") is False:
                        abort_action = "lease_lost"
                        try:
                            self.db.set_target_status(
                                data={"id": target_id, "status": "stopped"}
                            )
                        except Exception:
                            pass
                        return last_progress, "stopped", abort_action
                except Exception:
                    pass
                next_heartbeat_at = now_ts + heartbeat_interval
            if last_progress >= 100.0:
                return 100.0, "active", abort_action
            if last_status == "stopped":
                return last_progress, "stopped", abort_action
            if now_ts - last_progress_change_at > stall_timeout_seconds:
                raise TimeoutError(
                    "scan stalled waiting for target completion "
                    f"(no progress for > {int(stall_timeout_seconds)}s)"
                )
            if now_ts - started_at > float(timeout_seconds):
                raise TimeoutError("scan timeout waiting for target completion")
            time.sleep(1.0)

    def collect_result_payload(self, target_payload):
        result, _ = self.collect_result_payload_delta(target_payload, sent_markers=None)
        return result

    def collect_result_payload_delta(self, target_payload, sent_markers=None):
        network = ip_network(str(target_payload.get("network", "")).strip(), strict=False)
        proto_set = _target_proto_set(target_payload.get("proto"))
        pending_markers = self._new_result_markers()
        use_markers = isinstance(sent_markers, dict)

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
            marker = (
                ip_value,
                int((row or {}).get("port", 0) or 0),
                proto_value,
                str((row or {}).get("state", "open")).strip().lower(),
                str((row or {}).get("updated_at", "")),
            )
            if use_markers and marker in sent_markers.get("ports", set()):
                continue
            pending_markers["ports"].add(marker)
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
            marker = (
                ip_value,
                int((row or {}).get("port", 0) or 0),
                proto_value,
                str((row or {}).get("key", ""))[:120],
                str((row or {}).get("value", ""))[:4096],
                str((row or {}).get("updated_at", "")),
            )
            if use_markers and marker in sent_markers.get("tags", set()):
                continue
            pending_markers["tags"].add(marker)
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
            marker = (
                int((row or {}).get("id", 0) or 0),
                str((row or {}).get("updated_at", "")),
            )
            if use_markers and marker in sent_markers.get("banners", set()):
                continue
            pending_markers["banners"].add(marker)
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
            icon_id = int((row or {}).get("id", 0) or 0)
            marker = (icon_id, str((row or {}).get("updated_at", "")))
            if use_markers and marker in sent_markers.get("favicons", set()):
                continue
            raw = self.db.get_favicon_by_id(icon_id)
            if not raw:
                continue
            icon_blob = bytes(raw.get("icon_blob") or b"")
            if not icon_blob:
                continue
            pending_markers["favicons"].add(marker)
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

        return (
            {
                "ports": ports,
                "tags": tags,
                "banners": banners,
                "favicons": favicons,
            },
            pending_markers,
        )

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
        task_network = str(target_payload.get("network", "")).strip()
        task_proto = str(target_payload.get("proto", "")).strip().lower() or "tcp"
        task_type = str(target_payload.get("type", "")).strip().lower() or "common"
        try:
            task_timesleep = float(target_payload.get("timesleep", 1.0) or 1.0)
        except Exception:
            task_timesleep = 1.0
        task_started_ts = time.time()
        print(
            "[agent] executing task "
            f"task_id={task_id} target={master_target_id} "
            f"network={task_network} proto={task_proto} type={task_type} "
            f"timesleep={task_timesleep}"
        )
        local_target_id = None
        started_at = app_module.utc_iso(int(time.time()))
        progress = 0.0
        status = "stopped"
        abort_action = ""
        error = ""
        result = {"ports": [], "tags": [], "banners": [], "favicons": []}
        sent_markers = self._new_result_markers()
        normalized_target = None
        try:
            local_target_id, normalized_target = self.ensure_local_target(target_payload)

            def _collect_heartbeat_result(_progress_value, _status_value):
                if not isinstance(normalized_target, dict):
                    return None, None
                delta_result, pending_markers = self.collect_result_payload_delta(
                    normalized_target,
                    sent_markers=sent_markers,
                )
                if not self._result_has_rows(delta_result):
                    return None, None
                return (
                    delta_result,
                    lambda: self._commit_result_markers(sent_markers, pending_markers),
                )

            progress, status, abort_action = self.wait_target_completion(
                local_target_id,
                task_id=task_id,
                master_target_id=master_target_id,
                heartbeat_result_collector=_collect_heartbeat_result,
            )
            if abort_action in {"restart", "delete"}:
                status = "stopped"
                if not error:
                    error = f"aborted_by_master:{abort_action}"
            else:
                # Keep final submit lightweight: only include rows not already acknowledged by heartbeat sync.
                result, _pending_markers = self.collect_result_payload_delta(
                    normalized_target,
                    sent_markers=sent_markers,
                )
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
            "finished_at": app_module.utc_iso(int(time.time())),
            "result": result,
        }
        skip_submit = abort_action in {"restart", "delete"}
        if not skip_submit:
            self.submit_task(submission)
        else:
            print(
                "[agent] skipping task submit due to master action "
                f"task_id={task_id} action={abort_action}"
            )
        elapsed_seconds = round(max(0.0, time.time() - task_started_ts), 2)
        finish_line = (
            "[agent] task finished "
            f"task_id={task_id} target={master_target_id} "
            f"status={status} progress={round(float(progress or 0.0), 2)}% "
            f"elapsed={elapsed_seconds}s"
        )
        if error:
            finish_line = f"{finish_line} error={error}"
        print(finish_line)

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


def run_agent_mode(db=None):
    app_module.start_geoip_blocks_db()
    app_module.start_scanners()
    runtime = AgentRuntime(db or app_module.scan_db)
    runtime.run_forever()


def main():
    try:
        run_agent_mode()
    except KeyboardInterrupt:
        print("\n[shutdown] interrupted by user (Ctrl+C).")
        raise SystemExit(130)


if __name__ == "__main__":
    main()
