# API Reference

Default base URL: `http://HOST:PORT` (default `http://127.0.0.1:45678`).

WebSocket endpoint: `ws://HOST:PORT/ws/`.

If you deploy behind a reverse proxy with TLS, external clients may use `https://`/`wss://`.

## Admin access model

Admin-protected endpoints use this rule:

1. If `PORTHOUND_API_TOKEN` is set: send `Authorization: Bearer <token>` (or `X-API-Key`).
2. If `PORTHOUND_API_TOKEN` is not set: admin calls are allowed only from loopback (`127.0.0.1` / `::1`).
3. If `PORTHOUND_API_REQUIRE_TOKEN=1` and no token is configured: admin calls are rejected.

## Core read endpoints (non-admin)

- `GET /` -> counts summary (JSON) or HTML when `Accept: text/html`.
- `GET /protocols/` -> runtime-supported protocols.
- `GET /targets/`
- `GET /ports/`
- `GET /ports/tcp/` | `GET /ports/udp/` | `GET /ports/icmp/` | `GET /ports/sctp/`
- `GET /tags/`
- `GET /tags/tcp/` | `GET /tags/udp/` | `GET /tags/icmp/` | `GET /tags/sctp/`
- `GET /banners/`
- `GET /favicons/`
- `GET /favicons/raw/?id=<id>`
- `GET /count/targets/`
- `GET /count/ports/`
- `GET /count/ports/tcp/` | `GET /count/ports/udp/` | `GET /count/ports/icmp/` | `GET /count/ports/sctp/`
- `GET /count/banners/`

Compatibility aliases also exist for `stcp` on `ports/tags/count` routes.

## Core write endpoints (admin)

- `POST /target/`
- `PUT /target/`
- `DELETE /target/`
- `POST /target/action/` (`start|restart|stop|delete`)
- `POST /target/action/bulk/`
- `POST /port/action/`
- `POST /banner/action/`
- `DELETE /ports/tcp/` | `DELETE /ports/udp/` | `DELETE /ports/icmp/` | `DELETE /ports/sctp/`
- `DELETE /banners/`
- `DELETE /favicons/`

Create target example:

```json
{
  "network": "10.0.0.0/24",
  "type": "common",
  "proto": "tcp",
  "timesleep": 1.0
}
```

## UI/helper endpoints

Non-admin:
- `GET /api/dashboard/`
- `GET /api/endpoints/`

Catalog endpoints:
- `GET /api/catalog/banner-rules/`
- `GET /api/catalog/banner-requests/`
- `GET /api/catalog/ip-presets/`
- `POST|PUT|DELETE` on those same routes are admin-protected.

IP intel endpoints (non-admin):
- `GET /api/ip/domains/?ip=<ipv4>`
- `GET /api/ip/ttl-path/?ip=<ipv4>`
- `GET /api/ip/intel/?ip=<ipv4>`

## Attack telemetry endpoints

Non-admin:
- `GET /api/attacks/feed?limit=40`
- `GET /api/attacks/summary`
- `GET /api/attacks/simulator`

Admin:
- `POST /api/attacks/simulate`
- `POST /api/attacks/simulator`

## WebSocket control API

Admin:
- `GET /api/ws/clients`
- `POST /api/ws/broadcast`
- `POST /api/ws/ping`
- `POST /api/ws/close`

Chat:
- `GET /api/chat/messages` (non-admin)
- `POST /api/chat/clear` (admin)

## Cluster endpoints

Master-only + admin:
- `GET /cluster/agents/`
- `GET /api/cluster/agents`
- `GET /api/cluster/agent/credentials`
- `POST /api/cluster/agent/credentials`
- `DELETE /api/cluster/agent/credentials`
- `POST /api/cluster/agent/control`

Agent-auth endpoints (token in JSON body):
- `POST /api/cluster/agent/register`
- `POST /api/cluster/agent/heartbeat`
- `POST /api/cluster/agent/task/pull`
- `POST /api/cluster/agent/task/submit`

Agent auth payload shape:

```json
{
  "agent_id": "agent-01",
  "token": "<agent-token>"
}
```

Deprecated (always `410`):
- `GET /api/cluster/ca`
- `GET /api/cluster/ca/raw`
- `GET /api/cluster/ca/oneline`
- `POST /api/cluster/agent/enroll`
