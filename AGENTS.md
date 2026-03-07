# PortHound AGENTS

## Resumen del proyecto
- PortHound es un escaner de red en Python con un API HTTP muy simple y almacenamiento en SQLite.
- `server.py` es el servicio principal: expone el API, ejecuta escaneo TCP/UDP y captura banners.
- `ws_demo.py` es un servidor HTTP + WebSocket independiente (demo) con un mini ORM y UI embebida.
- `frontend/` es un proyecto Vue 3 de plantilla, no esta conectado al backend por defecto.

## Rutas y archivos clave
- `server.py` -> API HTTP, DB SQLite, hilos de escaneo TCP/UDP y banners.
- `Database.db` -> base SQLite persistente usada por `server.py`.
- `ws_demo.py` -> servidor HTTP/WS standalone con ORM simple y chat demo.
- `frontend/` -> Vue 3 (CLI) con `npm run serve|build|lint`.
- `CODE Nov 14 01:00` -> copia antigua del servidor WS (no usada en runtime).

## Como ejecutar
- Backend escaner/API: `python server.py`
  - Escucha en `127.0.0.1:45678` (ver `API(host, port)`).
  - Arranca hilos `TCP`, `UDP`, `BannerTCP`, `BannerUDP`.
- Servidor WS/HTTP demo: `python ws_demo.py`
  - Usa `HOST=0.0.0.0`, `PORT=8765`.
- Frontend:
  - `cd frontend`
  - `npm install`
  - `npm run serve` (dev), `npm run build` (prod), `npm run lint`

## API principal (`server.py`)
- `GET /` -> resumen de conteos (`count_ports`, `count_banners`, `count_targets`)
- `GET /count/targets/`
- `GET /count/ports/`
- `GET /count/ports/udp/`
- `GET /count/ports/tcp/`
- `GET /count/banners/`
- `GET /targets/` -> lista de objetivos
- `POST /target/` -> crear objetivo (body JSON)
- `PUT /target/` -> actualizar objetivo (body JSON)
- `DELETE /target/` -> borrar objetivo (body JSON)
- `GET /ports/` -> todos los puertos
- `GET /ports/udp/` | `DELETE /ports/udp/`
- `GET /ports/tcp/` | `DELETE /ports/tcp/`
- `GET /tags/` | `GET /tags/tcp/` | `GET /tags/udp/`
- `GET /banners/` | `DELETE /banners/`

Notas:
- `POST /target/` valida que `network` sea CIDR IPv4.
- Algunas rutas responden `OPTIONS` para CORS (ver `process_request`).

## Modelo de datos (SQLite)
Tablas creadas en `DB.create_tables()`:
- `targets`: `id`, `network`, `type`, `proto`, `timesleep`, `progress`, timestamps.
  - `type`: `common` (1-1023), `not_common` (1024-65534), `full` (1-65534).
- `ports`: `id`, `ip`, `port`, `proto`, `state`, `progress`, timestamps.
  - `state`: `open` o `filtered` segun el escaneo.
- `tags`: `id`, `ip`, `port`, `proto`, `key`, `value`, timestamps.
  - Se usa para `time_ms` de los escaneos.
- `banners`: `id`, `ip`, `port`, `proto`, `response` (BLOB), `response_plain`.

## Flujo de escaneo
- `TCP` y `UDP` leen `targets` y lanzan un hilo por objetivo.
- Se guarda progreso (%) en `targets.progress` para reanudar.
- `BannerTCP` y `BannerUDP` iteran una lista grande de payloads y guardan banners.
- La concurrencia es con `threading` y se protege SQLite con locks.

## Notas para cambios
- El API no usa frameworks; cualquier ruta nueva debe ir en `API.process_request`.
- Mantener el patron de `self.lock` en `DB` para evitar corrupcion.
- `DB.config()` existe pero no se llama en `server.py`; si se activa, revisar efectos.
- Evitar editar `Database.db` y `frontend/dist/` salvo que se solicite.

## Uso responsable
Este proyecto es para auditorias autorizadas. Mantener el aviso legal en `README.md`.
