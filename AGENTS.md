# PortHound AGENTS

## Resumen del proyecto
- PortHound4 es un escaner de red en Python con orquestacion `master/agent`.
- `manage.py` es el lanzador principal (wizard + flags + env vars).
- `app.py` expone API HTTP + WebSocket y coordina rutas, cluster y UI.
- `server.py` contiene el motor de escaneo (TCP/UDP/ICMP/SCTP), banners y DB SQLite.
- `frontend/` (Vue 3) es opcional y no bloquea el backend.

## Rutas y archivos clave
- `manage.py` -> entrypoint recomendado para todos los modos.
- `app.py` -> API/WS, cluster, endpoints de dashboard/catalogo/ataques.
- `master.py` -> runtime de `master`/`standalone`.
- `agent.py` -> runtime de `agent` (poll de tareas y submit de resultados).
- `server.py` -> DB + workers de escaneo + persistencia.
- `Database.db`, `Master.db`, `Agent.db` -> DBs SQLite locales (segun rol y configuracion).
- `ws_demo.py` -> componentes demo reutilizados por `app.py` y servidor standalone de demostracion.

## Como ejecutar
- Flujo recomendado local (master):
  - `python manage.py`
  - escucha por defecto en `0.0.0.0:45678`
- Modo explicito:
  - `python manage.py --role master --host 0.0.0.0 --port 45678 --db-path Master.db`
  - `python manage.py --role agent --master http://<MASTER_HOST>:45678 --agent-id <id> --agent-token <token>`
- Flujo docker rapido:
  - ver `FAST_DOCKER.md`

## API principal (`app.py`)
- Core:
  - `GET /`, `GET /protocols/`, `GET /targets/`
  - `POST|PUT|DELETE /target/`
  - `POST /target/action/`, `POST /target/action/bulk/`
  - `GET /ports/`, `GET|DELETE /ports/tcp|udp|icmp|sctp/`
  - `GET /tags/`, `GET /tags/tcp|udp|icmp|sctp/`
  - `GET|DELETE /banners/`, `GET|DELETE /favicons/`
- Dashboard/catalogo/intel:
  - `GET /api/dashboard/`, `GET /api/endpoints/`
  - `GET|POST|PUT|DELETE /api/catalog/*`
  - `GET /api/ip/domains/`, `GET /api/ip/ttl-path/`, `GET /api/ip/intel/`
- WebSocket/chat:
  - `GET /api/ws/clients`, `POST /api/ws/broadcast|ping|close`
  - `GET /api/chat/messages`, `POST /api/chat/clear`
- Cluster master/agent:
  - `GET /cluster/agents/`
  - `GET|POST|DELETE /api/cluster/agent/credentials`
  - `POST /api/cluster/agent/register|heartbeat|task/pull|task/submit`

Notas:
- `POST/PUT/DELETE` y endpoints de control/cluster usan politica de admin (`PORTHOUND_API_TOKEN` o loopback).
- TLS/CA de cluster esta deshabilitado por politica; autenticacion activa es `agent_id + token` sobre HTTP interno.

## Modelo de datos (SQLite)
Tablas principales creadas por `DB.create_tables()`:
- `targets`: red objetivo, protocolo, estado, progreso y timestamps.
- `ports`: resultados de puertos/hosts (`tcp`, `udp`, `icmp`, `sctp`).
- `tags`: metadatos por endpoint (ej: `time_ms`, `socket_type`).
- `banners`: respuesta cruda y texto decodificado.
- `favicons`: favicon capturado + hash para fingerprint.
- `cluster_agent_credentials`: credenciales de agentes para el cluster.

## Flujo de escaneo
- `master` orquesta tareas sobre `targets` activos.
- `agent` hace pull de tareas y reporta progreso/resultados al master.
- En `standalone`, el nodo corre scanner local y API en el mismo proceso.
- El motor usa `threading` y locks en DB para evitar corrupcion SQLite.

## Notas para cambios
- Las rutas API nuevas deben declararse en `app.py`.
- Mantener el patron de `self.lock` en `server.DB` para operaciones SQLite.
- Evitar editar DBs (`*.db`) y `frontend/dist/` salvo solicitud explicita.

## Uso responsable
Este proyecto es para auditorias autorizadas. Mantener el aviso legal en `README.md`.
