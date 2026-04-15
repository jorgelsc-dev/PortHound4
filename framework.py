import json
import os
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor

MAGIC_WS = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
DEFAULT_CORS_ALLOW_ORIGIN = str(os.getenv("PORTHOUND_CORS_ALLOW_ORIGIN", "")).strip()

STATUS_MESSAGES = {
    100: "Continue",
    101: "Switching Protocols",
    102: "Processing",
    103: "Early Hints",
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
    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    304: "Not Modified",
    305: "Use Proxy",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
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


def parse_query_string(qs):
    params = {}
    if not qs:
        return params
    parts = qs.split("&")
    for part in parts:
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
        else:
            k, v = part, ""
        params[k] = v
    return params


class Request:
    def __init__(self, method, path, query_string, headers, body, client, tls=None):
        self.method = (method or "").upper()
        self.path = path or "/"
        self.query_string = query_string or ""
        self.query = parse_query_string(self.query_string)
        self.headers = headers or {}
        self.body = body or b""
        self.client = client
        self.tls = tls or {}

    def text(self, encoding="utf-8"):
        return self.body.decode(encoding, errors="ignore")

    def json(self):
        try:
            return json.loads(self.text())
        except Exception:
            return None


class Response:
    def __init__(self, status=200, body=b"", headers=None, reason=None):
        self.status = status
        self.reason = reason
        if isinstance(body, (bytes, bytearray)):
            self.body = bytes(body)
        else:
            self.body = str(body).encode("utf-8")
        self.headers = headers or {}

    @classmethod
    def json(cls, data, status=200, headers=None):
        body = json.dumps(data).encode("utf-8")
        hdrs = {"Content-Type": "application/json; charset=utf-8"}
        if headers:
            hdrs.update(headers)
        return cls(status=status, body=body, headers=hdrs)

    @classmethod
    def text(cls, text, status=200, headers=None):
        hdrs = {"Content-Type": "text/plain; charset=utf-8"}
        if headers:
            hdrs.update(headers)
        return cls(status=status, body=text, headers=hdrs)

    @classmethod
    def html(cls, html, status=200, headers=None):
        hdrs = {"Content-Type": "text/html; charset=utf-8"}
        if headers:
            hdrs.update(headers)
        return cls(status=status, body=html, headers=hdrs)


class Route:
    def __init__(self, path, methods, handler, kind):
        self.path = path
        self.methods = {m.upper() for m in methods}
        self.handler = handler
        self.kind = kind


class Router:
    def __init__(self):
        self.routes = []

    def add(self, route):
        self.routes.append(route)

    def resolve(self, path, method=None):
        for route in self.routes:
            if route.path != path:
                continue
            if method is None or method.upper() in route.methods:
                return route
        return None


class App:
    def __init__(self):
        self.router = Router()
        self.ws_routes = {}
        self.startup_hooks = []

    def route(self, path, methods=("GET",), kind="plain"):
        def decorator(func):
            self.router.add(Route(path, methods, func, kind))
            return func
        return decorator

    def view(self, path, methods=("GET",)):
        return self.route(path, methods=methods, kind="plain")

    def api(self, path, methods=("GET",)):
        return self.route(path, methods=methods, kind="api")

    def ws(self, path):
        def decorator(func):
            self.ws_routes[path] = func
            return func
        return decorator

    def add_startup(self, func):
        self.startup_hooks.append(func)

    def dispatch(self, request):
        if request.method == "OPTIONS":
            route = self.router.resolve(request.path, method=None)
            if route:
                allow = sorted(route.methods | {"OPTIONS"})
                headers = {
                    "Access-Control-Allow-Methods": ", ".join(allow),
                    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-API-Key",
                }
                if DEFAULT_CORS_ALLOW_ORIGIN:
                    headers["Access-Control-Allow-Origin"] = DEFAULT_CORS_ALLOW_ORIGIN
                    if DEFAULT_CORS_ALLOW_ORIGIN != "*":
                        headers["Vary"] = "Origin"
                return Response(status=200, body=b"", headers=headers)

        route = self.router.resolve(request.path, request.method)
        if not route:
            return Response.text("Not Found", status=404)

        try:
            result = route.handler(request)
        except Exception as e:
            print(f"[http] handler error {request.method} {request.path}: {e}")
            if route.kind == "api":
                headers = {}
                if DEFAULT_CORS_ALLOW_ORIGIN:
                    headers["Access-Control-Allow-Origin"] = DEFAULT_CORS_ALLOW_ORIGIN
                    if DEFAULT_CORS_ALLOW_ORIGIN != "*":
                        headers["Vary"] = "Origin"
                return Response.json(
                    {"status": "error", "message": "Internal Server Error"},
                    status=500,
                    headers=headers,
                )
            return Response.text("Internal Server Error", status=500)

        if isinstance(result, Response):
            resp = result
        elif route.kind == "api" and isinstance(result, (dict, list)):
            resp = Response.json(result)
        else:
            resp = Response.text("" if result is None else str(result))

        if route.kind == "api":
            if DEFAULT_CORS_ALLOW_ORIGIN:
                resp.headers.setdefault("Access-Control-Allow-Origin", DEFAULT_CORS_ALLOW_ORIGIN)
                if DEFAULT_CORS_ALLOW_ORIGIN != "*":
                    resp.headers.setdefault("Vary", "Origin")

        return resp

    def run(self, host, port, ssl_context=None):
        server = HTTPServer(host, port, self, ssl_context=ssl_context)
        server.serve_forever()


class HTTPServer:
    MAX_CONNECTION_WORKERS = 64
    MAX_REQUEST_HEADER_BYTES = 64 * 1024
    MAX_REQUEST_BODY_BYTES = 2 * 1024 * 1024

    def __init__(self, host, port, app, ssl_context=None):
        self.host = host
        self.port = port
        self.app = app
        self._sock = None
        self.ssl_context = ssl_context

    def serve_forever(self):
        for hook in self.app.startup_hooks:
            try:
                hook()
            except Exception as e:
                print(f"[startup] error: {e}")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(128)
        self._sock = s
        scheme = "https" if self.ssl_context else "http"
        print(f"Server listening on {scheme}://{self.host}:{self.port}/")
        interrupted = False
        try:
            with ThreadPoolExecutor(
                max_workers=self.MAX_CONNECTION_WORKERS,
                thread_name_prefix="framework-http",
            ) as pool:
                while True:
                    conn, addr = s.accept()
                    pool.submit(self.handle_conn, conn, addr)
        except KeyboardInterrupt:
            interrupted = True
            print("\n[shutdown] interrupted by user (Ctrl+C). stopping server...")
        finally:
            s.close()
            if interrupted:
                print("[shutdown] server stopped.")

    def handle_conn(self, conn, addr):
        tls_meta = {
            "enabled": bool(self.ssl_context),
            "peer_cert": None,
            "cipher": None,
            "version": None,
        }
        if self.ssl_context:
            try:
                conn = self.ssl_context.wrap_socket(conn, server_side=True)
                tls_meta["peer_cert"] = conn.getpeercert()
                tls_meta["cipher"] = conn.cipher()
                tls_meta["version"] = conn.version()
            except ssl.SSLError as e:
                print(f"[tls] handshake error from {addr}: {e}")
                try:
                    conn.close()
                except Exception:
                    pass
                return
            except Exception as e:
                print(f"[tls] wrap error from {addr}: {e}")
                try:
                    conn.close()
                except Exception:
                    pass
                return

        with conn:
            try:
                req = parse_http_request(
                    conn,
                    max_header_bytes=self.MAX_REQUEST_HEADER_BYTES,
                )
            except ValueError as e:
                message = str(e).lower()
                status = 431 if "header" in message else 400
                send_http_response(conn, Response.text(str(e), status=status))
                return
            if not req:
                return

            headers = req["headers"]
            body = req["remainder"]

            if "content-length" in headers:
                try:
                    cl = int(headers["content-length"])
                except Exception:
                    cl = 0
                if cl < 0:
                    cl = 0
                if cl > self.MAX_REQUEST_BODY_BYTES:
                    send_http_response(
                        conn,
                        Response.text("Payload Too Large", status=413),
                    )
                    return
                if len(body) < cl:
                    need = cl - len(body)
                    if need > 0:
                        body += recv_exact(conn, need)
                if len(body) > self.MAX_REQUEST_BODY_BYTES:
                    send_http_response(
                        conn,
                        Response.text("Payload Too Large", status=413),
                    )
                    return

            raw_path = req["path"]
            path, _, query = raw_path.partition("?")

            request = Request(
                method=req["method"],
                path=path,
                query_string=query,
                headers=headers,
                body=body,
                client=addr,
                tls=tls_meta,
            )

            if is_ws_request(headers):
                handler = self.app.ws_routes.get(path)
                if not handler:
                    send_http_response(conn, Response.text("Not Found", status=404))
                    return
                ws = handshake_websocket(conn, addr, headers)
                if not ws:
                    return
                try:
                    handler(ws, request)
                except Exception as e:
                    print(f"[ws] error: {e}")
                return

            response = self.app.dispatch(request)
            send_http_response(conn, response)


def parse_http_request(conn, max_header_bytes=65536):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(1024)
        if not chunk:
            break
        data += chunk
        if len(data) > int(max_header_bytes):
            raise ValueError("Request headers too large")
    header_text, _, remainder = data.partition(b"\r\n\r\n")
    lines = header_text.decode("utf-8", errors="ignore").split("\r\n")
    if not lines:
        return None
    request_line = lines[0]
    parts = request_line.split()
    if len(parts) != 3:
        return None
    method, path, version = parts
    if not version.startswith("HTTP/"):
        return None
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {
        "method": method,
        "path": path,
        "version": version,
        "headers": headers,
        "remainder": remainder,
    }


def send_http_response(conn, response):
    status_code = response.status
    reason = response.reason or STATUS_MESSAGES.get(status_code, "OK")
    headers = response.headers or {}
    lowermap = {k.lower(): v for k, v in headers.items()}
    if "content-length" not in lowermap:
        headers["Content-Length"] = str(len(response.body))
    if "connection" not in lowermap:
        headers["Connection"] = "close"
    status_line = f"HTTP/1.1 {status_code} {reason}\r\n"
    hdrs = ""
    for k, v in headers.items():
        hdrs += f"{k}: {v}\r\n"
    resp = status_line + hdrs + "\r\n"
    try:
        conn.sendall(resp.encode("utf-8") + response.body)
    except Exception as e:
        print(f"[http] send error {status_code}: {e}")


def is_ws_request(headers):
    return headers.get("upgrade", "").lower() == "websocket"


def handshake_websocket(conn, addr, headers):
    key = headers.get("sec-websocket-key", "")
    if not key:
        send_http_response(conn, Response.text("Missing Sec-WebSocket-Key", status=400))
        return None

    subprotocol = ""
    offered = headers.get("sec-websocket-protocol", "")
    if offered:
        parts = [p.strip() for p in offered.split(",") if p.strip()]
        if parts:
            subprotocol = parts[0]

    accept_src = (key + MAGIC_WS).encode("utf-8")
    digest = sha1(accept_src)
    accept = base64_encode(digest)

    resp_headers = {
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Accept": accept,
    }
    if subprotocol:
        resp_headers["Sec-WebSocket-Protocol"] = subprotocol

    send_http_response(conn, Response(status=101, body=b"", headers=resp_headers))
    return WebSocket(conn, addr, subprotocol, headers)


class WebSocket:
    def __init__(self, sock, addr, subprotocol, headers):
        self.sock = sock
        self.addr = addr
        self.subprotocol = subprotocol or ""
        self.headers = headers or {}

    def recv_frame(self):
        return read_ws_frame_raw(self.sock)

    def send_frame(self, opcode, payload=b""):
        self.sock.sendall(make_ws_frame_bytes(opcode, payload))

    def send_text(self, text):
        self.send_frame(0x1, text.encode("utf-8"))

    def send_binary(self, data):
        self.send_frame(0x2, data)

    def send_ping(self, payload=b""):
        self.send_frame(0x9, payload)

    def send_pong(self, payload=b""):
        self.send_frame(0xA, payload)

    def close(self, code=1000, reason=""):
        payload = code.to_bytes(2, "big")
        if reason:
            payload += reason.encode("utf-8")
        self.send_frame(0x8, payload)


def recv_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return data


def read_ws_frame_raw(conn):
    hdr = recv_exact(conn, 2)
    b1, b2 = hdr[0], hdr[1]
    fin = (b1 >> 7) & 1
    opcode = b1 & 0x0F
    masked = (b2 >> 7) & 1
    payload_len = b2 & 0x7F

    if payload_len == 126:
        ext = recv_exact(conn, 2)
        payload_len = int.from_bytes(ext, "big")
    elif payload_len == 127:
        ext = recv_exact(conn, 8)
        payload_len = int.from_bytes(ext, "big")

    mask = None
    if masked:
        mask = recv_exact(conn, 4)

    payload = b""
    if payload_len:
        payload = recv_exact(conn, payload_len)
        if masked and mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return fin, opcode, payload, bool(masked), mask


def make_ws_frame_bytes(opcode, payload=b""):
    fin = 0x80
    b1 = fin | (opcode & 0x0F)
    payload_len = len(payload)
    header = bytes([b1])

    if payload_len <= 125:
        header += bytes([payload_len])
    elif payload_len <= 65535:
        header += bytes([126]) + payload_len.to_bytes(2, "big")
    else:
        header += bytes([127]) + payload_len.to_bytes(8, "big")

    return header + payload


def parse_close_payload(payload):
    if not payload:
        return None, None
    if len(payload) >= 2:
        code = int.from_bytes(payload[:2], "big")
        reason = ""
        if len(payload) > 2:
            try:
                reason = payload[2:].decode("utf-8", errors="ignore")
            except Exception:
                reason = ""
        return code, reason
    return None, None


def _left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF


def sha1(data_bytes):
    message = bytearray(data_bytes)
    orig_len_bits = (8 * len(message)) & 0xFFFFFFFFFFFFFFFF
    message.append(0x80)
    while (len(message) * 8) % 512 != 448:
        message.append(0)
    message += orig_len_bits.to_bytes(8, "big")

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    for i in range(0, len(message), 64):
        w = [0] * 80
        chunk = message[i : i + 64]
        for j in range(16):
            w[j] = int.from_bytes(chunk[j * 4 : (j + 1) * 4], "big")
        for j in range(16, 80):
            w[j] = _left_rotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1)

        a, b, c, d, e = h0, h1, h2, h3, h4
        for t in range(80):
            if 0 <= t <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= t <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= t <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            tmp = (_left_rotate(a, 5) + f + e + k + w[t]) & 0xFFFFFFFF
            e = d
            d = c
            c = _left_rotate(b, 30)
            b = a
            a = tmp

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    digest = b"".join(x.to_bytes(4, "big") for x in [h0, h1, h2, h3, h4])
    return digest


B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def base64_encode(data_bytes):
    res = []
    i = 0
    n = len(data_bytes)
    while i < n:
        b = data_bytes[i : i + 3]
        i += 3
        pad = 3 - len(b)
        val = 0
        for x in b:
            val = (val << 8) + x
        val <<= pad * 8
        for j in range(18, -1, -6):
            idx = (val >> j) & 0x3F
            res.append(B64_ALPHABET[idx])
        if pad:
            res[-pad:] = "=" * pad
    return "".join(res)
