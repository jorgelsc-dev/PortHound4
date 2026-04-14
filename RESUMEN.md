# RESUMEN DEL PROYECTO PortHound4

## Estado actual

PortHound4 es un escaner de red Python con arquitectura `master/agent/standalone`, API HTTP + WebSocket y persistencia SQLite.

Entrypoint recomendado:
- `manage.py`

Roles:
- `master`: orquesta cluster y expone UI/API.
- `agent`: consume tareas del master y reporta resultados.
- `standalone`: ejecuta API + scanner local en el mismo nodo.

## Componentes principales

- `manage.py`: bootstrap de configuracion (flags, env, wizard interactivo).
- `app.py`: rutas HTTP/WS, dashboard, cluster, catalogos e integraciones.
- `master.py`: runtime del rol master/standalone.
- `agent.py`: runtime del agente (register, pull, heartbeat, submit).
- `server.py`: motor de escaneo (TCP/UDP/ICMP/SCTP), banners y DB.
- `settings.py`: lectura de variables de entorno.
- `frontend/`: UI Vue 3 opcional.

## Puertos y protocolos

- API/WS por defecto: `0.0.0.0:45678`
- Master-Agent: HTTP interno con `agent_id + token`
- TLS/CA de cluster: deshabilitado por politica (endpoints CA/enroll devuelven `410`)

## Persistencia

Base SQLite configurable con `PORTHOUND_DB_PATH`.

Defaults por rol:
- `master` -> `Master.db`
- `agent` -> `Agent.db`
- `standalone` -> `Standalone.db`

Tablas principales:
- `targets`
- `ports`
- `tags`
- `banners`
- `favicons`
- `cluster_agent_credentials`

## Flujo operativo recomendado

1. Iniciar master (`python manage.py` o flags explicitos).
2. Crear credencial de agente desde `/cluster/agents/` o API.
3. Iniciar agentes con `--master`, `--agent-id`, `--agent-token`.
4. Crear targets por UI/API.
5. Monitorear progreso y resultados (`ports`, `tags`, `banners`, `favicons`).

## Documentacion canonica

- `README.md` -> guia principal y flujo completo.
- `FAST.md` -> arranque local rapido.
- `API.md` -> referencia de endpoints actual.
- `ARCHITECTURE.md` -> descripcion de componentes.
- `DEPLOYMENT.md` -> despliegue local, APT/ZIP y systemd.
- `INSTALL.md` + `GETTING_STARTED.md` -> instalacion y primer uso.
- `docs/` -> notas tecnicas por modulo.

## Nota

Este archivo reemplaza un resumen historico largo que ya no representaba la base de codigo actual.
