import json
import threading
import tempfile
import time
import unittest
from pathlib import Path

import app
import framework
import getDBNIC
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
    def test_normalize_master_base_url_enforces_https(self):
        self.assertEqual(
            app.normalize_master_base_url("master.local:45678"),
            "https://master.local:45678",
        )
        with self.assertRaises(ValueError):
            app.normalize_master_base_url("http://master.local:45678")

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


if __name__ == "__main__":
    unittest.main()
