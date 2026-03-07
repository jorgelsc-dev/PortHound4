# API Reference

Base URL: `https://HOST:PORT`

If the client requests `Accept: text/html`, `/` returns the demo HTML. Otherwise it returns JSON counts.

Demo mode (`?example=1`) is disabled in the current public API build.

Admin-protected endpoints:
- Mutating endpoints and cluster/WS control endpoints require admin access.
- If `PORTHOUND_API_TOKEN` is configured, send it as `Authorization: Bearer <token>` or `X-API-Key: <token>`.
- Without token, admin operations are only allowed from loopback clients (`127.0.0.1`/`::1`).

## Core endpoints

### GET /
Returns counts.

Response:
```json
{
  "count_ports": 0,
  "count_banners": 0,
  "count_targets": 0
}
```

### GET /protocols/
Returns supported target protocols for the current host/runtime.

### GET /targets/
Returns all targets.

### POST /target/
Create target.

Body:
```json
{
  "network": "10.0.0.0/24",
  "type": "common",
  "proto": "tcp",
  "timesleep": 1.0
}
```

Valid `proto` values: `tcp`, `udp`, `icmp`, and `sctp` when supported.

### PUT /target/
Update target.

### DELETE /target/
Delete target.

### GET /ports/
Returns all ports.

### GET /ports/tcp/
### GET /ports/udp/
### GET /ports/icmp/
### GET /ports/sctp/
### DELETE /ports/tcp/
### DELETE /ports/udp/
### DELETE /ports/icmp/
### DELETE /ports/sctp/

### GET /banners/
### DELETE /banners/

### GET /tags/
### GET /tags/tcp/
### GET /tags/udp/
### GET /tags/icmp/
### GET /tags/sctp/

### GET /count/targets/
### GET /count/ports/
### GET /count/ports/tcp/
### GET /count/ports/udp/
### GET /count/ports/icmp/
### GET /count/ports/sctp/
### GET /count/banners/

## Frontend helper endpoints

### GET /api/dashboard/
Returns a single snapshot payload for the UI:
```json
{
  "counts": {"count_ports": 0, "count_banners": 0, "count_targets": 0},
  "targets": [],
  "ports": {"tcp": [], "udp": [], "icmp": [], "sctp": []},
  "banners": [],
  "tags": [],
  "ws_clients": []
}
```

### GET /api/endpoints/
Returns an endpoint catalog for the UI.

### GET /attacks/raw/
Raw HTML dashboard (no framework) that consumes REST + WS attack telemetry.

### GET /api/attacks/feed?limit=40
Returns recent synthetic attack events.

Response:
```json
{
  "datas": [
    {
      "id": 145,
      "timestamp": 1739050000,
      "timestamp_iso": "2026-02-08T05:12:03Z",
      "attack_type": "credential-stuffing",
      "severity": "high",
      "protocol": "tcp",
      "port": 443,
      "service": "https",
      "action": "blocked",
      "confidence": 0.91,
      "packets": 41,
      "bytes": 28412,
      "src": {"ip": "185.220.101.45", "city": "Berlin", "country": "DE", "lat": 52.52, "lon": 13.405},
      "dst": {"ip": "34.117.59.81", "city": "Ashburn", "country": "US", "lat": 39.0438, "lon": -77.4874, "asset": "api-gateway-prod"}
    }
  ],
  "summary": {},
  "simulator": {}
}
```

### GET /api/attacks/summary
Returns aggregate telemetry metrics (severity, top targets, recent activity).

### POST /api/attacks/simulate
Injects one synthetic event (useful for demos and integration tests).

Body (optional overrides):
```json
{
  "attack_type": "api-path-fuzzing",
  "severity": "medium",
  "protocol": "tcp",
  "port": 443,
  "service": "https",
  "action": "challenged",
  "src": {"ip": "203.0.113.8", "city": "Madrid", "country": "ES", "lat": 40.4168, "lon": -3.7038},
  "dst": {"ip": "34.117.59.81", "city": "Ashburn", "country": "US", "lat": 39.0438, "lon": -77.4874, "asset": "api-gateway-prod"}
}
```

### GET /api/attacks/simulator
Returns simulator status.

### POST /api/attacks/simulator
Controls simulator state and optional burst generation.

Body:
```json
{ "running": true, "burst": 5 }
```

## WebSocket demo API

### GET /api/ws/clients
List connected WS clients.

### POST /api/ws/broadcast
Broadcast a text/binary message to all WS clients.

Body (text):
```json
{ "type": "text", "message": "hello" }
```

### POST /api/ws/ping
Ping all WS clients.

Body:
```json
{ "payload": "ping" }
```

### POST /api/ws/close
Close one client or all clients.

Body:
```json
{ "client_id": "...", "code": 1000, "reason": "bye" }
```

### GET /api/chat/messages?limit=20
Returns chat messages stored in SQLite.

### POST /api/chat/clear
Clears chat messages.

## WebSocket endpoint
- `wss://HOST:PORT/ws/`

The server echoes text messages and supports binary payloads. It also stores chat messages when they match `[alias] message` format.

## Cluster master/agent endpoints

### GET /api/cluster/agents
Returns agents state snapshot (`online|stale|offline`) and active leases.

### GET /api/cluster/ca
Returns CA payload in three forms:
- `ca_pem` (multiline PEM)
- `ca_oneline` (single-line with `\\n`)
- `export_command` (ready for terminal)

### GET /api/cluster/ca/raw
Downloads the CA as `.pem` file.

### GET /api/cluster/ca/oneline
Returns plain-text CA one-line value.

### POST /api/cluster/agent/register
Register an agent over mTLS.

Body:
```json
{ "agent_id": "agent-01" }
```

### POST /api/cluster/agent/task/pull
Pull next scheduled target.

Body:
```json
{ "agent_id": "agent-01" }
```

### POST /api/cluster/agent/task/submit
Submit scan results for a task.

Body (shape):
```json
{
  "agent_id": "agent-01",
  "task_id": "....",
  "master_target_id": 42,
  "result": {
    "progress": 100.0,
    "status": "active",
    "ports": [],
    "tags": [],
    "banners": [],
    "favicons": []
  }
}
```
