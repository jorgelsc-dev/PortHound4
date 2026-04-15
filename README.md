# 🛡️ PortHound4

[![CI](https://github.com/jorgelsc-dev/PortHound4/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jorgelsc-dev/PortHound4/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

PortHound4 es un scanner de red distribuido en Python para auditorias autorizadas. Soporta modos `master`/`agent`/`standalone`, escaneo TCP/UDP/ICMP/SCTP, banner grabbing, persistencia en SQLite y control por API HTTP + WebSocket.

PortHound4 is a distributed Python network scanner for authorized security audits. It supports `master`/`agent`/`standalone` modes, TCP/UDP/ICMP/SCTP scanning, banner grabbing, SQLite persistence, and HTTP + WebSocket APIs.

Keywords: `python`, `network-scanner`, `port-scanner`, `cybersecurity`, `banner-grabbing`, `sqlite`, `websocket`, `master-agent`.

---

## 📘 Documentacion

- `README.md` -> guia principal del proyecto.
- `FAST.md` -> guia corta, directa y simple para arrancar rapido.
- `docs/` -> notas tecnicas adicionales.
- `docs/screenshots/` -> capturas recomendadas para presentar el proyecto en GitHub.
- `docs/repository_visibility.md` -> checklist de visibilidad/indexacion para GitHub.

---

## ✨ Caracteristicas

- Escaneo TCP/UDP concurrente.
- Captura de banners con payloads extensos.
- Progreso reanudable por target.
- SQLite local, sin dependencias externas.
- API HTTP y WebSocket en un solo servidor.
- Frontend opcional en Vue 3.

---

## 🚀 Inicio rapido (flujo que funciona local)

> Flujo recomendado: levantar `master` en HTTP interno y conectar agentes con `agent_id + token`.

Si quieres la version corta, abre `FAST.md`.

### 0) Prerequisitos

- Python 3.11+.
- Puertos abiertos entre nodos (por defecto `45678/tcp`).

### 1) Crear entorno virtual `env` (una sola vez)

```bash
python3 -m venv env
env/bin/python -m pip install --upgrade pip
```

Opcional (si prefieres activar el entorno):

```bash
source env/bin/activate
```

### 2) Paso a paso: Master (nodo principal)

1. Arranque master (interactivo):

```bash
env/bin/python manage.py
```

Entrada directa equivalente (solo runtime, sin web de estado):

```bash
env/bin/python master.py
```

Al ejecutar `python manage.py`, se asume `master` con:
- `IP`: `127.0.0.1`
- `Port`: `45678`
- (TLS queda desactivado por politica)

2. Arranque por argumentos (equivalente):

```bash
env/bin/python manage.py \
  --role master \
  --db-path Master.db
```

3. Arranque rapido sin argumentos:

```bash
env/bin/python manage.py
```

`manage.py` funciona en modo no interactivo: toma valores de flags/env/base64 y usa la DB del rol (`Master.db`) como defaults.

4. Verifica que el master responda:
- UI/API: `http://localhost:45678` o `http://127.0.0.1:45678`
- No uses `http://0.0.0.0:45678` en el navegador.
- Vista de agentes: `http://localhost:45678/cluster/agents/`

5. Si ya guardaste valores incorrectos en DB:
- Vuelve a ejecutar con argumentos explicitos (sobrescribe y guarda de nuevo).

### 3) Paso a paso: Agente (repetir por cada agente)

1. En el master abre la web: `http://localhost:45678/cluster/agents/`
- Pulsa `Agregar agente`.
- Copia `agent_id` + `token` del bloque generado.
- Copia el `ENROLL BASE64` (contiene JSON con todo lo necesario).
- Copia `COMANDO RAPIDO (copiar/pegar en el agente)`.
- Ese bloque trae todo lo necesario para ejecutar el agente sin wizard.

2. Comandos soportados (modo simple):

- Master (sin base64):

```bash
env/bin/python manage.py
```

- Agente (con base64 generado por el master):

```bash
env/bin/python manage.py '<BASE64_DEL_MASTER>'
```

Notas:
- Sin base64 siempre es `master` (`127.0.0.1:45678`).
- Con base64 siempre es `agent` (`127.0.0.1:45677`).
- Si pasas `--host` o `--port`, el launcher los ignora por politica fija.

Web del agente (estado simple):
- `http://127.0.0.1:45677/`
- API: `GET /api/agent/status`

### 4) Verificacion final (master + agentes)

- Abre `http://127.0.0.1:45678/cluster/agents/` y confirma `online`.
- Consulta API de agentes:

```bash
curl http://127.0.0.1:45678/api/cluster/agents
```

### Ejecucion legacy (sin cluster)

```bash
env/bin/python server.py   # API de escaneo
env/bin/python ws_demo.py  # Demo HTTP/WS
```

### Resumen ultra corto

1. Inicia el master con `env/bin/python master.py` o `env/bin/python manage.py`.
2. Abre `http://localhost:45678/cluster/agents/`.
3. Crea una credencial de agente y copia `agent_id` + `token`.
4. En el agente ejecuta `env/bin/python agent.py` o `env/bin/python manage.py '<BASE64>'`.
5. Verifica en la vista de agentes que el estado aparezca como `online`.

### Problemas comunes de conectividad

- `Only http:// URLs are supported`:
  - El agente se configuro con `https://`.
  - Solucion: usa `http://<master>:45678`.

- `Invalid agent_id or token`:
  - `agent_id` o `token` no coincide con la credencial activa en el master.
  - Solucion: regenera la credencial desde `/cluster/agents/` y vuelve a cargarla en el agente.

- `El agente parece bloqueado al ejecutar una task`:
  - Un escaneo `full` (1-65534) puede tardar mucho tiempo segun `timesleep` y timeouts de red.
  - El agente ahora imprime progreso periodico en consola: `[agent] task progress ...`.
  - Puedes ajustar deteccion de estancamiento con `PORTHOUND_AGENT_TASK_STALL_SECONDS` (minimo 90, por defecto 300).

### 5) Empaquetado (APT + ZIP)

Paquete Debian (`.deb`) instalable con `apt`:

```bash
./packaging/deb/build.sh
sudo apt install ./dist/deb/porthound4_<version>-1_all.deb
```

Paquete portable (`.zip`):

```bash
./packaging/zip/build.sh
unzip dist/zip/porthound4_<version>-1.zip
cd porthound4_<version>-1
python3 manage.py
```

Comandos utiles (APT):

```bash
porthound4 --help
porthound4
# stop with Ctrl+C
```

Master explicito:

```bash
porthound4 --role master --host 0.0.0.0 --port 45678 --db-path ./Master.db
```

Agent explicito:

```bash
porthound4 --role agent --master http://127.0.0.1:45678 --agent-id <id> --agent-token <token>
```

Si vienes de una version anterior con servicio activo:

```bash
sudo systemctl disable --now porthound4.service
```

Release automatica en `main`:
- publica `porthound4_<version>-<rev>_all.deb`
- publica `porthound4_<version>-<rev>.zip`

---

## 🧩 Estructura del proyecto

- `app.py` -> app principal con rutas `plain/api/ws`.
- `master.py` -> arranque dedicado del rol master/standalone.
- `agent.py` -> runtime dedicado del rol agent y loop de ejecucion remota.
- `framework.py` -> micro framework interno (router, request/response, WS).
- `server.py` -> motor de escaneo TCP/UDP + banners + SQLite.
- `ws_demo.py` -> servidor HTTP/WS con ORM ligero y UI demo.
- `settings.py` -> configuracion del servidor.
- `frontend/` -> frontend Vue 3.
- `scripts/generate_certs.py` -> utilitario legacy de certificados (no requerido en el flujo actual).

---

## 🔌 API principal (resumen)

- `GET /` -> conteos (o HTML si `Accept: text/html`)
- `GET /targets/`
- `POST /target/` | `PUT /target/` | `DELETE /target/`
- `GET /ports/` | `GET /ports/tcp/` | `GET /ports/udp/`
- `GET /banners/`
- `GET /tags/` | `GET /tags/tcp/` | `GET /tags/udp/`
- `GET /count/targets/` | `GET /count/ports/` | `GET /count/banners/`

API WS demo:
- `GET /api/ws/clients`
- `POST /api/ws/broadcast`
- `POST /api/ws/ping`
- `POST /api/ws/close`
- `GET /api/chat/messages`
- `POST /api/chat/clear`

WebSocket:
- `ws://HOST:PORT/ws/`

Cluster master/agent:
- `GET /api/cluster/agents`
- `GET /api/cluster/agent/credentials`
- `POST /api/cluster/agent/credentials`
- `DELETE /api/cluster/agent/credentials`
- `POST /api/cluster/agent/register`
- `POST /api/cluster/agent/task/pull`
- `POST /api/cluster/agent/task/submit`

---

## 🎛️ Frontend

```bash
cd frontend
npm install
npm run serve
```

El frontend es opcional. El backend master funciona sin compilar `frontend/`.

---

## ⚠️ Uso Responsable / Responsible Use

### Español

**Advertencia:** Esta herramienta debe ser utilizada unicamente con fines educativos, profesionales o de auditoria de seguridad en sistemas que sean de tu propiedad o con autorizacion explicita por escrito del propietario.

El uso de PortHound para realizar actividades maliciosas o no autorizadas va en contra de la etica profesional y puede violar leyes locales, nacionales o internacionales.

**El autor no se hace responsable** del mal uso, danos o consecuencias derivadas del uso indebido de esta herramienta. Todo usuario es responsable de cumplir con la legislacion vigente y actuar con integridad profesional.

### English

**Warning:** This tool is intended solely for educational, professional, or authorized security auditing purposes on systems that you own or have explicit written permission to test.

Using PortHound for malicious or unauthorized activities goes against professional ethics and may violate local, national, or international laws.

**The author is not responsible** for any misuse, damage, or consequences resulting from the inappropriate use of this tool. Each user is responsible for complying with applicable laws and maintaining professional integrity.

---

## 🔐 Security

Please report vulnerabilities privately. See `SECURITY.md`.

---

## 🤝 Community

- Contribution guide: `CONTRIBUTING.md`
- Code of conduct: `CODE_OF_CONDUCT.md`
- Security policy: `SECURITY.md`

---

## 💛 Support / Donations

If PortHound helps your work and you want to support maintenance, you can donate in BTC:

`bc1q3lhxpr9yantvefmvhpd2h4lu0ykf3t45zvuve2`

---

## 📄 Licencia / License

Este proyecto esta licenciado bajo la Licencia MIT. Consulta el archivo `LICENSE` para mas detalles.

This project is licensed under the MIT License. See `LICENSE` for details.
