import json
import threading
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import app
import framework
import getDBNIC
import manage
import server


class _MemorySocket:
    def __init__(self, incoming=b"", chunk_size=4096):
        self._incoming = bytes(incoming or b"")
        self._offset = 0
        self._chunk_size = max(1, int(chunk_size))
        self.sent = b""
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def recv(self, size):
        if self._offset >= len(self._incoming):
            return b""
        take = min(int(size), self._chunk_size, len(self._incoming) - self._offset)
        chunk = self._incoming[self._offset : self._offset + take]
        self._offset += take
        return chunk

    def sendall(self, data):
        self.sent += bytes(data)

    def close(self):
        return None


def _make_manage_args(**overrides):
    values = {key: None for key in manage.ENV_FLAG_MAP.keys()}
    values.update(
        {
            "env_file": [],
            "env": [],
            "interactive": False,
        }
    )
    values.update(overrides)
    return SimpleNamespace(**values)


class TestCidrValidation(unittest.TestCase):
    def setUp(self):
        self.base_target = {
            "network": "10.0.0.1/24",
            "type": "common",
            "proto": "tcp",
            "timesleep": 1.0,
        }

    def test_app_normalize_target_rejects_invalid_cidr(self):
        invalid = dict(self.base_target)
        invalid["network"] = "999.999.999.999/99"
        with self.assertRaises(ValueError):
            app.normalize_target_item(invalid)

    def test_server_api_normalize_target_rejects_invalid_cidr(self):
        invalid = dict(self.base_target)
        invalid["network"] = "999.999.999.999/99"
        api = server.API(db=None)
        with self.assertRaises(ValueError):
            api.normalize_target_item(invalid)

    def test_app_normalize_target_canonicalizes_network(self):
        normalized = app.normalize_target_item(dict(self.base_target))
        self.assertEqual(normalized["network"], "10.0.0.0/24")


class TestLegacyHttpRequestRead(unittest.TestCase):
    def test_server_api_reads_full_body_using_content_length(self):
        api = server.API(db=None)
        large_padding = "x" * 9000
        body_obj = {
            "network": "10.10.10.0/24",
            "type": "common",
            "proto": "tcp",
            "timesleep": 1.0,
            "padding": large_padding,
        }
        body = json.dumps(body_obj)
        request = (
            "POST /target/ HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body.encode('utf-8'))}\r\n"
            "\r\n"
            f"{body}"
        ).encode("utf-8")

        conn = _MemorySocket(incoming=request, chunk_size=512)
        raw_request = api._recv_http_request(conn)
        method, path, parsed_body = api.parse_request(raw_request)

        self.assertEqual(method, "POST")
        self.assertEqual(path, "/target/")
        self.assertEqual(len(parsed_body), len(body))
        self.assertIn(large_padding[:256], parsed_body)


class TestGeoIpSeedImport(unittest.TestCase):
    def test_server_db_imports_geoip_seed_into_primary_database(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            db_path = tmp_path / "Database.db"
            seed_path = tmp_path / "geoip_blocks.seed.jsonl"
            with seed_path.open("w", encoding="utf-8", newline="") as handle:
                handle.write(
                    json.dumps(
                        {
                            "kind": "meta",
                            "format": "porthound.geoip.seed.v1",
                            "generated_at": "2026-03-04T00:00:00Z",
                            "rows": 1,
                            "partial": False,
                            "selected_rirs": ["ARIN"],
                            "failed_rirs": [],
                        }
                    )
                    + "\n"
                )
                handle.write(
                    json.dumps(
                        {
                            "kind": "block",
                            "start_int": 167772160,
                            "end_int": 167772415,
                            "cidr": "10.0.0.0/24",
                            "rir": "ARIN",
                            "area": "North America",
                            "country": "US",
                            "lat": 38.9072,
                            "lon": -77.0369,
                        }
                    )
                    + "\n"
                )

            db = server.DB(path=str(db_path), geoip_seed_path=str(seed_path))
            try:
                db.create_tables()
                geo = db.lookup_geoip_ipv4("10.0.0.5")
                status = db.geoip_status()
            finally:
                db.conn.close()

            self.assertIsNotNone(geo)
            self.assertEqual(geo["cidr"], "10.0.0.0/24")
            self.assertEqual(geo["rir"], "ARIN")
            self.assertEqual(status["source"], "repo-seed-file")
            self.assertEqual(status["rows"], 1)


class TestGeoIpCountryCentroids(unittest.TestCase):
    def test_country_centroid_overrides_rir_reference_point(self):
        rows = list(
            getDBNIC.build_cidr_rows(
                rir="LACNIC",
                start_int=167772160,
                end_int=167772415,
                country="CU",
            )
        )

        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row[5], "CU")
        self.assertAlmostEqual(row[6], 21.5, places=3)
        self.assertAlmostEqual(row[7], -80.0, places=3)


class TestFrameworkHttpWs(unittest.TestCase):
    def test_parse_http_and_websocket_handshake(self):
        raw = (
            "GET /ws/ HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        ).encode("ascii")
        conn = _MemorySocket(incoming=raw, chunk_size=128)

        req = framework.parse_http_request(conn)
        self.assertIsNotNone(req)
        self.assertEqual(req["path"], "/ws/")
        self.assertTrue(framework.is_ws_request(req["headers"]))

        ws = framework.handshake_websocket(
            conn,
            ("local", 0),
            req["headers"],
        )
        self.assertIsNotNone(ws)

        response = conn.sent.decode("iso-8859-1")
        self.assertIn("101 Switching Protocols", response)
        self.assertIn("Sec-WebSocket-Accept", response)

    def test_dispatch_converts_handler_exceptions_to_500(self):
        local_app = framework.App()

        @local_app.api("/boom", methods=("GET",))
        def boom(_request):
            raise RuntimeError("boom")

        request = framework.Request(
            method="GET",
            path="/boom",
            query_string="",
            headers={},
            body=b"",
            client=("127.0.0.1", 0),
        )
        response = local_app.dispatch(request)

        self.assertEqual(response.status, 500)
        payload = json.loads(response.body.decode("utf-8"))
        self.assertEqual(payload["status"], "error")


class TestWsCloseValidation(unittest.TestCase):
    def test_ws_close_rejects_out_of_range_code(self):
        request = framework.Request(
            method="POST",
            path="/api/ws/close",
            query_string="",
            headers={"content-type": "application/json"},
            body=b'{"code":70000}',
            client=("127.0.0.1", 0),
        )

        response = app.api_ws_close(request)
        self.assertIsInstance(response, framework.Response)
        self.assertEqual(response.status, 400)
        payload = json.loads(response.body.decode("utf-8"))
        self.assertIn("Invalid close code", payload["status"])


class TestClusterSecurityHelpers(unittest.TestCase):
    def test_normalize_master_base_url_supports_http_only(self):
        self.assertEqual(
            app.normalize_master_base_url("master.local:45678"),
            "http://master.local:45678",
        )
        self.assertEqual(
            app.normalize_master_base_url("http://master.local:45678"),
            "http://master.local:45678",
        )
        with self.assertRaises(ValueError):
            app.normalize_master_base_url("https://master.local:45678")
        with self.assertRaises(ValueError):
            app.normalize_master_base_url("ftp://master.local:45678")
        with self.assertRaises(ValueError):
            app.normalize_master_base_url("http://0.0.0.0:45678")

    def test_require_agent_mtls(self):
        request_no_cert = framework.Request(
            method="POST",
            path="/api/cluster/agent/register",
            query_string="",
            headers={"content-type": "application/json"},
            body=b"{}",
            client=("127.0.0.1", 0),
            tls={"enabled": True, "peer_cert": None},
        )
        deny = app.require_agent_mtls(request_no_cert)
        self.assertIsInstance(deny, framework.Response)
        self.assertEqual(deny.status, 401)

        request_with_cert = framework.Request(
            method="POST",
            path="/api/cluster/agent/register",
            query_string="",
            headers={"content-type": "application/json"},
            body=b"{}",
            client=("127.0.0.1", 0),
            tls={"enabled": True, "peer_cert": {"subject": ((("commonName", "agent-01"),),)}},
        )
        self.assertIsNone(app.require_agent_mtls(request_with_cert))

    def test_ca_oneline_roundtrip(self):
        pem = (
            "-----BEGIN CERTIFICATE-----\n"
            "QUJDREVGRw==\n"
            "-----END CERTIFICATE-----\n"
        )
        one_line = app.ca_pem_to_oneline(pem)
        self.assertIn("\\n", one_line)
        restored = app.ca_oneline_to_pem(one_line)
        self.assertEqual(restored, pem)

    def test_authenticate_cluster_agent_shared_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            db_path = tmp_path / "Database.db"
            seed_path = tmp_path / "geoip_blocks.seed.jsonl"
            seed_path.write_text(
                json.dumps(
                    {
                        "kind": "meta",
                        "format": "porthound.geoip.seed.v1",
                        "generated_at": "2026-03-04T00:00:00Z",
                        "rows": 0,
                        "partial": False,
                        "selected_rirs": [],
                        "failed_rirs": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            db = server.DB(path=str(db_path), geoip_seed_path=str(seed_path))
            db.create_tables()
            credential = db.create_cluster_agent_credential({"agent_id": "agent-auth-unit"})
            request = framework.Request(
                method="POST",
                path="/api/cluster/agent/register",
                query_string="",
                headers={"content-type": "application/json"},
                body=b"{}",
                client=("127.0.0.1", 0),
                tls={"enabled": False, "peer_cert": None},
            )
            original_db = app.scan_db
            app.scan_db = db
            try:
                auth, auth_error = app.authenticate_cluster_agent(
                    request,
                    {
                        "agent_id": credential["agent_id"],
                        "agent_key": credential["agent_key"],
                    },
                )
                self.assertIsNone(auth_error)
                self.assertEqual(auth["agent_id"], credential["agent_id"])
                self.assertEqual(auth["auth_mode"], "token")
            finally:
                app.scan_db = original_db
                db.conn.close()

    def test_authenticate_cluster_agent_prefers_shared_key_when_cert_cn_mismatch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            db_path = tmp_path / "Database.db"
            seed_path = tmp_path / "geoip_blocks.seed.jsonl"
            seed_path.write_text(
                json.dumps(
                    {
                        "kind": "meta",
                        "format": "porthound.geoip.seed.v1",
                        "generated_at": "2026-03-04T00:00:00Z",
                        "rows": 0,
                        "partial": False,
                        "selected_rirs": [],
                        "failed_rirs": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            db = server.DB(path=str(db_path), geoip_seed_path=str(seed_path))
            db.create_tables()
            credential = db.create_cluster_agent_credential({"agent_id": "agent-auth-fallback"})
            request = framework.Request(
                method="POST",
                path="/api/cluster/agent/register",
                query_string="",
                headers={"content-type": "application/json"},
                body=b"{}",
                client=("127.0.0.1", 0),
                tls={
                    "enabled": True,
                    "peer_cert": {"subject": ((("commonName", "legacy-agent-cn"),),)},
                },
            )
            original_db = app.scan_db
            app.scan_db = db
            try:
                auth, auth_error = app.authenticate_cluster_agent(
                    request,
                    {
                        "agent_id": credential["agent_id"],
                        "agent_key": credential["agent_key"],
                    },
                )
                self.assertIsNone(auth_error)
                self.assertEqual(auth["agent_id"], credential["agent_id"])
                self.assertEqual(auth["auth_mode"], "token")
            finally:
                app.scan_db = original_db
                db.conn.close()

    def test_build_cluster_agents_snapshot(self):
        with app.cluster_lock:
            original_agents = dict(app.cluster_agents)
            original_leases = dict(app.cluster_leases)
            app.cluster_agents.clear()
            app.cluster_leases.clear()
            app.cluster_agents["agent-01"] = {
                "agent_id": "agent-01",
                "cn": "agent-01",
                "last_seen": time.time(),
                "client": ("127.0.0.1", 12345),
            }
        try:
            snapshot = app.build_cluster_agents_snapshot()
            self.assertEqual(snapshot["summary"]["total_agents"], 1)
            self.assertEqual(snapshot["summary"]["online"], 1)
            self.assertEqual(len(snapshot["datas"]), 1)
            self.assertEqual(snapshot["datas"][0]["agent_id"], "agent-01")
        finally:
            with app.cluster_lock:
                app.cluster_agents.clear()
                app.cluster_agents.update(original_agents)
                app.cluster_leases.clear()
                app.cluster_leases.update(original_leases)


class TestChartAnalytics(unittest.TestCase):
    def test_build_chart_analytics_example_payload_shape(self):
        payload = app.build_chart_analytics(example=True)
        self.assertIn("summary", payload)
        self.assertIn("ports_by_proto", payload)
        self.assertIn("targets_by_status", payload)
        self.assertIn("timeline", payload)
        self.assertIsInstance(payload["ports_by_proto"], list)
        self.assertIsInstance(payload["targets_by_status"], list)
        self.assertIsInstance(payload["timeline"], list)


class TestManageInteractiveFallback(unittest.TestCase):
    def test_missing_required_settings_no_longer_requires_tls_ca(self):
        args = _make_manage_args(
            role="master",
            host="0.0.0.0",
            port=45678,
            db_path="Master.db",
            tls_enabled="1",
            tls_cert_file="/tmp/master.cert.pem",
            tls_key_file="/tmp/master.key.pem",
            tls_require_client_cert="1",
            ca="",
            ca_oneline="",
        )
        missing = manage._missing_required_settings(args)
        self.assertNotIn("ca", missing)

    def test_auto_interactive_when_profile_exists_but_required_is_missing(self):
        args = _make_manage_args(role="master", host="0.0.0.0", port=45678)
        with mock.patch.object(manage, "_is_interactive_terminal", return_value=True):
            enabled = manage._should_auto_interactive(
                args,
                has_profile=True,
                missing_required=["tls_cert_file"],
            )
        self.assertTrue(enabled)

    def test_auto_interactive_when_no_cli_overrides_even_with_profile(self):
        args = _make_manage_args()
        with mock.patch.object(manage, "_is_interactive_terminal", return_value=True):
            enabled = manage._should_auto_interactive(
                args,
                has_profile=True,
                missing_required=[],
                has_non_interactive_cli_overrides=False,
            )
        self.assertTrue(enabled)

    def test_auto_interactive_disabled_when_cli_overrides_exist(self):
        args = _make_manage_args(role="master")
        with mock.patch.object(manage, "_is_interactive_terminal", return_value=True):
            enabled = manage._should_auto_interactive(
                args,
                has_profile=False,
                missing_required=[],
                has_non_interactive_cli_overrides=True,
            )
        self.assertFalse(enabled)

    def test_detect_non_interactive_cli_overrides(self):
        self.assertFalse(manage._has_non_interactive_cli_overrides([]))
        self.assertFalse(manage._has_non_interactive_cli_overrides(["--interactive"]))
        self.assertTrue(manage._has_non_interactive_cli_overrides(["--role", "master"]))


class TestLauncherProfileCertPersistence(unittest.TestCase):
    def test_launcher_profile_stores_and_materializes_cert_blobs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            db_path = tmp_path / "Master.db"
            cert_path = tmp_path / "master.cert.pem"
            key_path = tmp_path / "master.key.pem"
            cert_path.write_text(
                "-----BEGIN CERTIFICATE-----\nTESTCERT\n-----END CERTIFICATE-----\n",
                encoding="utf-8",
            )
            key_path.write_text(
                "-----BEGIN PRIVATE KEY-----\nTESTKEY\n-----END PRIVATE KEY-----\n",
                encoding="utf-8",
            )

            keys = (
                "PORTHOUND_ROLE",
                "PORTHOUND_DB_PATH",
                "PORTHOUND_TLS_CERT_FILE",
                "PORTHOUND_TLS_KEY_FILE",
                "PORTHOUND_TLS_REQUIRE_CLIENT_CERT",
            )
            previous = {
                key: (manage.environ.exists(key), manage.environ.get(key, ""))
                for key in keys
            }
            try:
                manage.environ["PORTHOUND_ROLE"] = "master"
                manage.environ["PORTHOUND_DB_PATH"] = str(db_path)
                manage.environ["PORTHOUND_TLS_CERT_FILE"] = str(cert_path)
                manage.environ["PORTHOUND_TLS_KEY_FILE"] = str(key_path)
                manage.environ["PORTHOUND_TLS_REQUIRE_CLIENT_CERT"] = "0"
                manage.save_persisted_role_profile("master", str(db_path))

                profile = manage.load_persisted_role_profile("master", str(db_path))
                self.assertTrue(manage.profile_has_data(profile))
                self.assertIn("master_tls_cert_pem", profile["blobs"])
                self.assertIn("master_tls_key_pem", profile["blobs"])

                manage.environ["PORTHOUND_TLS_CERT_FILE"] = ""
                manage.environ["PORTHOUND_TLS_KEY_FILE"] = ""
                manage.materialize_persisted_certificate_files(profile)
                cert_temp = str(
                    Path(str(manage.environ.get("PORTHOUND_TLS_CERT_FILE", "") or ""))
                )
                key_temp = str(
                    Path(str(manage.environ.get("PORTHOUND_TLS_KEY_FILE", "") or ""))
                )
                self.assertTrue(Path(cert_temp).is_file())
                self.assertTrue(Path(key_temp).is_file())
            finally:
                for key, (existed, value) in previous.items():
                    if existed:
                        manage.environ[key] = value
                    else:
                        manage.environ[key] = ""


class _EmptyBannerDB:
    def select_ports_where_udp_for_scan(self):
        return []

    def select_ports_where_tcp_for_scan(self):
        return []

    def is_port_scan_runnable(self, _identifier):
        return True


class _OneShotBannerDB:
    def __init__(self, worker, count):
        self.worker = worker
        self.count = count
        self.calls = 0

    def select_ports_where_udp_for_scan(self):
        self.calls += 1
        if self.calls == 1:
            self.worker.stop_event.set()
            return [
                {
                    "id": idx,
                    "ip": "127.0.0.1",
                    "port": idx + 1,
                    "progress": 0.0,
                }
                for idx in range(self.count)
            ]
        return []

    def is_port_scan_runnable(self, _identifier):
        return True


class TestBannerWorkers(unittest.TestCase):
    def test_banner_workers_shutdown_cleanly(self):
        db = _EmptyBannerDB()
        workers = [server.BannerUDP(db=db), server.BannerTCP(db=db)]
        for worker in workers:
            worker.start()
        time.sleep(0.1)
        for worker in workers:
            worker.stop_event.set()
        for worker in workers:
            worker.join(timeout=2.5)
            self.assertFalse(worker.is_alive(), worker.__class__.__name__)

    def test_banner_udp_pool_limits_concurrency(self):
        worker = server.BannerUDP(db=None)
        db = _OneShotBannerDB(worker=worker, count=worker.MAX_TARGET_WORKERS * 2)
        worker.db = db

        counter = {"active": 0, "max": 0}
        lock = threading.Lock()

        def fake_scan(*_args, **_kwargs):
            with lock:
                counter["active"] += 1
                if counter["active"] > counter["max"]:
                    counter["max"] = counter["active"]
            time.sleep(0.05)
            with lock:
                counter["active"] -= 1

        worker.scan = fake_scan
        worker.start()
        worker.join(timeout=5.0)

        self.assertFalse(worker.is_alive())
        self.assertLessEqual(counter["max"], worker.MAX_TARGET_WORKERS)


class TestPortActionHandlers(unittest.TestCase):
    def test_port_and_banner_actions_update_endpoint_scan_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            db_path = tmp_path / "Database.db"
            seed_path = tmp_path / "geoip_blocks.seed.jsonl"
            seed_path.write_text(
                json.dumps(
                    {
                        "kind": "meta",
                        "format": "porthound.geoip.seed.v1",
                        "generated_at": "2026-03-04T00:00:00Z",
                        "rows": 0,
                        "partial": False,
                        "selected_rirs": [],
                        "failed_rirs": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            db = server.DB(path=str(db_path), geoip_seed_path=str(seed_path))
            db.create_tables()
            db.insert_port(
                data={
                    "ip": "127.0.0.1",
                    "port": 443,
                    "proto": "tcp",
                    "state": "open",
                }
            )
            port_row = db.select_ports_where_tcp()[0]
            db.ports_progress(data={"id": port_row["id"], "progress": 42.0})
            db.insert_banners(
                data={
                    "ip": "127.0.0.1",
                    "port": 443,
                    "proto": "tcp",
                    "response": b"HTTP/1.1 200 OK\r\n",
                    "response_plain": "HTTP/1.1 200 OK",
                }
            )

            original_db = app.scan_db
            app.scan_db = db
            try:
                stop_request = framework.Request(
                    method="POST",
                    path="/port/action/",
                    query_string="",
                    headers={"content-type": "application/json"},
                    body=json.dumps({"id": port_row["id"], "action": "stop"}).encode("utf-8"),
                    client=("127.0.0.1", 0),
                )
                stop_response = app.port_action_handler(stop_request)
                self.assertEqual(stop_response["status"], "200")
                stopped_port = db.select_port_by_id(port_row["id"])
                self.assertEqual(stopped_port["scan_state"], "stopped")

                restart_request = framework.Request(
                    method="POST",
                    path="/banner/action/",
                    query_string="",
                    headers={"content-type": "application/json"},
                    body=json.dumps(
                        {
                            "id": port_row["id"],
                            "action": "restart",
                            "clean_results": True,
                        }
                    ).encode("utf-8"),
                    client=("127.0.0.1", 0),
                )
                restart_response = app.banner_action_handler(restart_request)
                self.assertEqual(restart_response["status"], "200")

                restarted_port = db.select_port_by_id(port_row["id"])
                self.assertEqual(restarted_port["scan_state"], "active")
                self.assertEqual(float(restarted_port["progress"]), 0.0)
                self.assertEqual(db.select_banners(), [])
            finally:
                app.scan_db = original_db
                db.conn.close()


class TestCatalogBootstrap(unittest.TestCase):
    def _build_meta_seed_file(self, directory: Path) -> Path:
        seed_path = directory / "geoip_blocks.seed.jsonl"
        seed_path.write_text(
            json.dumps(
                {
                    "kind": "meta",
                    "format": "porthound.geoip.seed.v1",
                    "generated_at": "2026-03-04T00:00:00Z",
                    "rows": 0,
                    "partial": False,
                    "selected_rirs": [],
                    "failed_rirs": [],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return seed_path

    def test_catalog_tables_bootstrap_from_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            db_path = tmp_path / "Database.db"
            seed_path = self._build_meta_seed_file(tmp_path)
            db = server.DB(path=str(db_path), geoip_seed_path=str(seed_path))
            try:
                db.create_tables()
                rules = db.select_banner_regex_rules(include_inactive=True)
                requests = db.select_banner_probe_requests(include_inactive=True)
                ips = db.select_ip_presets(include_inactive=True)
            finally:
                db.conn.close()

            self.assertGreater(len(rules), 0)
            self.assertGreater(len(requests), 0)
            self.assertGreater(len(ips), 0)
            self.assertTrue(any(not row["mutable"] for row in rules))
            self.assertTrue(any(not row["mutable"] for row in requests))
            self.assertTrue(any(not row["mutable"] for row in ips))

    def test_builtin_catalog_entries_are_immutable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            db_path = tmp_path / "Database.db"
            seed_path = self._build_meta_seed_file(tmp_path)
            db = server.DB(path=str(db_path), geoip_seed_path=str(seed_path))
            try:
                db.create_tables()
                builtin_rule = next(
                    row for row in db.select_banner_regex_rules() if not row["mutable"]
                )
                builtin_request = next(
                    row for row in db.select_banner_probe_requests() if not row["mutable"]
                )
                builtin_ip = next(
                    row for row in db.select_ip_presets() if not row["mutable"]
                )

                with self.assertRaises(PermissionError):
                    db.delete_banner_regex_rule({"id": builtin_rule["id"]})
                with self.assertRaises(PermissionError):
                    db.delete_banner_probe_request({"id": builtin_request["id"]})
                with self.assertRaises(PermissionError):
                    db.delete_ip_preset({"id": builtin_ip["id"]})
            finally:
                db.conn.close()

    def test_user_catalog_entries_support_crud(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            db_path = tmp_path / "Database.db"
            seed_path = self._build_meta_seed_file(tmp_path)
            db = server.DB(path=str(db_path), geoip_seed_path=str(seed_path))
            try:
                db.create_tables()

                custom_rule = db.insert_banner_regex_rule(
                    {
                        "rule_id": "custom_unit_test_rule",
                        "label": "Custom Unit Rule",
                        "pattern": r"UnitTestServer/(?P<version>[0-9.]+)",
                        "flags": 2,
                        "category": "test",
                        "service": "http",
                        "active": True,
                    }
                )
                self.assertTrue(custom_rule["mutable"])
                updated_rule = db.update_banner_regex_rule(
                    {
                        "id": custom_rule["id"],
                        "rule_id": "custom_unit_test_rule",
                        "label": "Custom Unit Rule Updated",
                        "pattern": r"UnitTestServer/(?P<version>[0-9.]+)",
                        "flags": 2,
                        "category": "test",
                        "service": "http",
                        "active": False,
                    }
                )
                self.assertFalse(updated_rule["active"])

                custom_request = db.insert_banner_probe_request(
                    {
                        "name": "Unit Test TCP Probe",
                        "proto": "tcp",
                        "scope": "generic",
                        "payload_format": "text",
                        "payload_encoded": "HELLO UNIT TEST\\r\\n",
                        "description": "test",
                        "active": True,
                    }
                )
                self.assertTrue(custom_request["mutable"])
                updated_request = db.update_banner_probe_request(
                    {
                        "id": custom_request["id"],
                        "name": "Unit Test TCP Probe v2",
                        "proto": "tcp",
                        "scope": "generic",
                        "payload_format": "text",
                        "payload_encoded": "HELLO UNIT TEST v2\\r\\n",
                        "description": "updated",
                        "active": False,
                    }
                )
                self.assertFalse(updated_request["active"])

                custom_ip = db.insert_ip_preset(
                    {
                        "value": "10.9.9.0/24",
                        "label": "Unit Test Net",
                        "description": "test",
                        "active": True,
                    }
                )
                self.assertTrue(custom_ip["mutable"])
                updated_ip = db.update_ip_preset(
                    {
                        "id": custom_ip["id"],
                        "value": "10.9.9.0/24",
                        "label": "Unit Test Net Updated",
                        "description": "updated",
                        "active": False,
                    }
                )
                self.assertFalse(updated_ip["active"])

                db.delete_banner_regex_rule({"id": custom_rule["id"]})
                db.delete_banner_probe_request({"id": custom_request["id"]})
                db.delete_ip_preset({"id": custom_ip["id"]})

                rules_after = db.select_banner_regex_rules()
                requests_after = db.select_banner_probe_requests()
                ips_after = db.select_ip_presets()
                self.assertFalse(any(row["id"] == custom_rule["id"] for row in rules_after))
                self.assertFalse(any(row["id"] == custom_request["id"] for row in requests_after))
                self.assertFalse(any(row["id"] == custom_ip["id"] for row in ips_after))
            finally:
                db.conn.close()


class TestClusterAgentCredentialStorage(unittest.TestCase):
    def test_cluster_agent_credentials_crud(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            db_path = tmp_path / "Database.db"
            seed_path = tmp_path / "geoip_blocks.seed.jsonl"
            seed_path.write_text(
                json.dumps(
                    {
                        "kind": "meta",
                        "format": "porthound.geoip.seed.v1",
                        "generated_at": "2026-03-04T00:00:00Z",
                        "rows": 0,
                        "partial": False,
                        "selected_rirs": [],
                        "failed_rirs": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            db = server.DB(path=str(db_path), geoip_seed_path=str(seed_path))
            try:
                db.create_tables()
                created = db.create_cluster_agent_credential({"agent_id": "agent-crud-unit"})
                self.assertTrue(created["active"])
                self.assertTrue(created.get("agent_key"))
                self.assertTrue(
                    db.verify_cluster_agent_shared_key(
                        created["agent_id"],
                        created["agent_key"],
                    )
                )

                listed = db.select_cluster_agent_credentials(include_inactive=True)
                self.assertEqual(len(listed), 1)
                self.assertEqual(listed[0]["agent_id"], "agent-crud-unit")

                revoked = db.revoke_cluster_agent_credential({"id": created["id"]})
                self.assertFalse(revoked["active"])
                self.assertFalse(
                    db.verify_cluster_agent_shared_key(
                        created["agent_id"],
                        created["agent_key"],
                    )
                )
            finally:
                db.conn.close()

    def test_cluster_agent_credential_delete(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            db_path = tmp_path / "Database.db"
            seed_path = tmp_path / "geoip_blocks.seed.jsonl"
            seed_path.write_text(
                json.dumps(
                    {
                        "kind": "meta",
                        "format": "porthound.geoip.seed.v1",
                        "generated_at": "2026-03-04T00:00:00Z",
                        "rows": 0,
                        "partial": False,
                        "selected_rirs": [],
                        "failed_rirs": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            db = server.DB(path=str(db_path), geoip_seed_path=str(seed_path))
            try:
                db.create_tables()
                created = db.create_cluster_agent_credential({"agent_id": "agent-delete-unit"})
                deleted = db.delete_cluster_agent_credential(
                    {"agent_id": created["agent_id"]}
                )
                self.assertEqual(deleted["agent_id"], created["agent_id"])
                self.assertFalse(
                    db.verify_cluster_agent_shared_key(
                        created["agent_id"],
                        created["agent_key"],
                    )
                )
                listed = db.select_cluster_agent_credentials(include_inactive=True)
                self.assertEqual(listed, [])
            finally:
                db.conn.close()


class TestClusterAgentControlApi(unittest.TestCase):
    def test_control_agent_stop_and_delete(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            db_path = tmp_path / "Database.db"
            seed_path = tmp_path / "geoip_blocks.seed.jsonl"
            seed_path.write_text(
                json.dumps(
                    {
                        "kind": "meta",
                        "format": "porthound.geoip.seed.v1",
                        "generated_at": "2026-03-04T00:00:00Z",
                        "rows": 0,
                        "partial": False,
                        "selected_rirs": [],
                        "failed_rirs": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            db = server.DB(path=str(db_path), geoip_seed_path=str(seed_path))
            db.create_tables()
            credential = db.create_cluster_agent_credential({"agent_id": "agent-control-unit"})
            agent_id = credential["agent_id"]

            original_db = app.scan_db
            with app.cluster_lock:
                original_agents = dict(app.cluster_agents)
                original_leases = dict(app.cluster_leases)
                app.cluster_agents.clear()
                app.cluster_leases.clear()
                app.cluster_agents[agent_id] = {
                    "agent_id": agent_id,
                    "last_seen": time.time(),
                    "cn": "",
                    "auth_mode": "token",
                    "client": ("127.0.0.1", 12345),
                }
                app.cluster_leases[99] = {
                    "task_id": "unit-task-stop",
                    "agent_id": agent_id,
                    "lease_until": time.time() + 60,
                }

            try:
                app.scan_db = db
                stop_request = framework.Request(
                    method="POST",
                    path="/api/cluster/agent/control",
                    query_string="",
                    headers={"content-type": "application/json"},
                    body=json.dumps(
                        {"action": "stop", "agent_id": agent_id}
                    ).encode("utf-8"),
                    client=("127.0.0.1", 0),
                    tls={"enabled": False, "peer_cert": None},
                )
                stop_response = app.api_cluster_agent_control(stop_request)
                self.assertEqual(stop_response.get("status"), "ok")
                self.assertEqual(stop_response.get("action"), "stop")
                self.assertEqual(stop_response.get("released_leases"), 1)
                self.assertFalse(
                    db.verify_cluster_agent_shared_key(
                        agent_id,
                        credential["agent_key"],
                    )
                )

                db.create_cluster_agent_credential(
                    {"agent_id": agent_id, "token": credential["agent_key"]}
                )
                with app.cluster_lock:
                    app.cluster_agents[agent_id] = {
                        "agent_id": agent_id,
                        "last_seen": time.time(),
                        "cn": "",
                        "auth_mode": "token",
                        "client": ("127.0.0.1", 54321),
                    }
                    app.cluster_leases[101] = {
                        "task_id": "unit-task-delete",
                        "agent_id": agent_id,
                        "lease_until": time.time() + 120,
                    }

                delete_request = framework.Request(
                    method="POST",
                    path="/api/cluster/agent/control",
                    query_string="",
                    headers={"content-type": "application/json"},
                    body=json.dumps(
                        {"action": "delete", "agent_id": agent_id}
                    ).encode("utf-8"),
                    client=("127.0.0.1", 0),
                    tls={"enabled": False, "peer_cert": None},
                )
                delete_response = app.api_cluster_agent_control(delete_request)
                self.assertEqual(delete_response.get("status"), "ok")
                self.assertEqual(delete_response.get("action"), "delete")
                self.assertEqual(delete_response.get("released_leases"), 1)
                self.assertTrue(delete_response.get("removed_agent"))
                self.assertEqual(
                    db.select_cluster_agent_credentials(include_inactive=True),
                    [],
                )
            finally:
                app.scan_db = original_db
                with app.cluster_lock:
                    app.cluster_agents.clear()
                    app.cluster_agents.update(original_agents)
                    app.cluster_leases.clear()
                    app.cluster_leases.update(original_leases)
                db.conn.close()


class TestClusterAgentHeartbeatApi(unittest.TestCase):
    def test_heartbeat_updates_last_seen_and_renews_lease(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            db_path = tmp_path / "Database.db"
            seed_path = tmp_path / "geoip_blocks.seed.jsonl"
            seed_path.write_text(
                json.dumps(
                    {
                        "kind": "meta",
                        "format": "porthound.geoip.seed.v1",
                        "generated_at": "2026-03-04T00:00:00Z",
                        "rows": 0,
                        "partial": False,
                        "selected_rirs": [],
                        "failed_rirs": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            db = server.DB(path=str(db_path), geoip_seed_path=str(seed_path))
            db.create_tables()
            credential = db.create_cluster_agent_credential({"agent_id": "agent-heartbeat-unit"})
            agent_id = credential["agent_id"]

            original_db = app.scan_db
            with app.cluster_lock:
                original_agents = dict(app.cluster_agents)
                original_leases = dict(app.cluster_leases)
                app.cluster_agents.clear()
                app.cluster_leases.clear()
                app.cluster_agents[agent_id] = {
                    "agent_id": agent_id,
                    "last_seen": 1.0,
                    "cn": "",
                    "auth_mode": "token",
                    "client": ("127.0.0.1", 1111),
                }
                app.cluster_leases[202] = {
                    "task_id": "hb-task",
                    "agent_id": agent_id,
                    "lease_until": time.time() + 5,
                }

            try:
                app.scan_db = db
                before_lease_until = 0.0
                with app.cluster_lock:
                    before_lease_until = float(app.cluster_leases[202]["lease_until"])

                request = framework.Request(
                    method="POST",
                    path="/api/cluster/agent/heartbeat",
                    query_string="",
                    headers={"content-type": "application/json"},
                    body=json.dumps(
                        {
                            "agent_id": agent_id,
                            "token": credential["agent_key"],
                            "task_id": "hb-task",
                            "master_target_id": 202,
                            "progress": 12.3,
                            "status": "active",
                        }
                    ).encode("utf-8"),
                    client=("127.0.0.1", 0),
                    tls={"enabled": False, "peer_cert": None},
                )
                response = app.api_cluster_agent_heartbeat(request)
                self.assertEqual(response.get("status"), "ok")
                self.assertTrue(response.get("lease_renewed"))

                with app.cluster_lock:
                    updated_agent = app.cluster_agents.get(agent_id, {})
                    updated_lease = app.cluster_leases.get(202, {})
                self.assertGreater(float(updated_agent.get("last_seen", 0.0) or 0.0), 1.0)
                self.assertGreater(
                    float(updated_lease.get("lease_until", 0.0) or 0.0),
                    before_lease_until,
                )
            finally:
                app.scan_db = original_db
                with app.cluster_lock:
                    app.cluster_agents.clear()
                    app.cluster_agents.update(original_agents)
                    app.cluster_leases.clear()
                    app.cluster_leases.update(original_leases)
                db.conn.close()


if __name__ == "__main__":
    unittest.main()
