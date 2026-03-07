# Architecture

## Overview
PortHound is a single-process Python application with multiple threads. It exposes a lightweight HTTP API and WebSocket endpoint and runs the scanning engine in parallel threads. Data is stored in a local SQLite database.

## Components
- app.py: Main entrypoint, routes (plain/api/ws), and integration glue.
- framework.py: Minimal internal web framework (router, request/response, WS).
- server.py: Scanning engine (TCP/UDP), banner grabbing, SQLite storage.
- ws_demo.py: WebSocket demo server + lightweight ORM + HTML demo page.
- Attack telemetry simulator: synthetic attack stream over REST + WS for map dashboards.
- settings.py: Host/port configuration.
- frontend/: Vue 3 UI (optional).

## Data flow
1. Targets are created via the API (POST /target/).
2. The scanner threads read targets and scan ports.
3. Results are stored in SQLite tables (ports, tags, banners).
4. API exposes data for external tooling or UI.

## Thread model
- TCP scanner thread spawns one worker per target.
- UDP scanner thread spawns one worker per target.
- ICMP scanner thread spawns one worker per target and records host reachability (`port=0`, `proto=icmp`).
- SCTP scanner thread spawns one worker per target when SCTP is supported by the host.
- Banner threads iterate captured ports and send probe payloads.
- HTTP/WS server runs in the main process and dispatches per connection.

## Storage
SQLite database tables:
- targets: target networks and progress.
- ports: discovered ports and state.
- tags: metadata such as response time.
- banners: raw banner responses and decoded text.

## Networking
- HTTP API and WebSocket run on a single port.
- CORS headers are enabled on API endpoints.

## Frontend
The Vue frontend is optional and can be used as a UI layer. It is not required for the scanner to work.
