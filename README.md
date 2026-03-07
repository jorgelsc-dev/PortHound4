# 🛡️ PortHound4

PortHound4 es una herramienta profesional de ciberseguridad para escaneo de red, deteccion de servicios y banner grabbing. Combina escaneo TCP/UDP, almacenamiento en SQLite y un API/WS ligero para integracion y control.

PortHound4 is a professional cybersecurity tool for network scanning, service detection, and banner grabbing. It combines TCP/UDP scanning, SQLite storage, and a lightweight API/WS layer for orchestration.

---

## ✨ Caracteristicas

- Escaneo TCP/UDP concurrente.
- Captura de banners con payloads extensos.
- Progreso reanudable por target.
- SQLite local, sin dependencias externas.
- API HTTP y WebSocket en un solo servidor.
- Frontend opcional en Vue 3.

---

## 🚀 Inicio rapido (Cluster Seguro)

> Flujo recomendado: 1 master + N agentes, todos con TLS/mTLS y CA propia.

### 0) Prerequisitos

- Python 3.11+.
- `cryptography` (se instala en el paso de `env`).
- Puertos abiertos entre nodos (por defecto `45678/tcp`).

### 1) Crear entorno virtual `env` (una sola vez)

```bash
python3 -m venv env
env/bin/python -m pip install --upgrade pip
env/bin/python -m pip install cryptography
```

Opcional (si prefieres activar el entorno):

```bash
source env/bin/activate
```

### 2) Generar PKI local (CA + certs)

```bash
export MASTER_IP=127.0.0.1
env/bin/python scripts/generate_certs.py \
  --out-dir certs \
  --master-host localhost \
  --master-ip "${MASTER_IP}" \
  --overwrite
```

Genera:
- `certs/ca/ca.cert.pem`
- `certs/master/master.cert.pem` + `certs/master/master.key.pem`
- `certs/admin/admin.cert.pem` + `certs/admin/admin.key.pem`
- `certs/agent/agent.cert.pem` + `certs/agent/agent.key.pem`
- `certs/master.env`, `certs/agent.env`, `certs/admin.env`
- Variable lista para terminal: `PORTHOUND_CA_ONELINE='-----BEGIN...\\n...\\n-----END...'`

### 3) Paso a paso: Master (nodo principal)

1. Inicia el master (modo explicito por argumentos):

```bash
env/bin/python manage.py \
  --role master \
  --host 0.0.0.0 \
  --port 45678 \
  --ca certs/ca/ca.cert.pem \
  --tls-cert-file certs/master/master.cert.pem \
  --tls-key-file certs/master/master.key.pem
```

2. Alternativa rapida (sin argumentos): `manage.py` carga `certs/master.env` automaticamente.

```bash
env/bin/python manage.py
```

3. Verifica que el master responda:
- UI/API TLS: `https://<MASTER_HOST>:45678`
- Vista de agentes: `https://<MASTER_HOST>:45678/cluster/agents/`

### 4) Paso a paso: Agente (repetir por cada agente)

1. En cada agente, asegurate de tener estos archivos:
- `certs/ca/ca.cert.pem`
- `certs/agent/agent.cert.pem`
- `certs/agent/agent.key.pem`
- opcional: `certs/agent.env`

2. Inicia un agente por argumentos (recomendado para remoto):

```bash
env/bin/python manage.py \
  --role agent \
  --master https://<MASTER_HOST>:45678 \
  --ca certs/ca/ca.cert.pem \
  --agent-cert certs/agent/agent.cert.pem \
  --agent-key certs/agent/agent.key.pem \
  --ip <IP_DE_SALIDA_DEL_AGENTE>
```

3. Alternativa rapida por env (sin argumentos): `manage.py` carga `certs/agent.env` automaticamente.

```bash
source certs/agent.env
export PORTHOUND_MASTER=https://<MASTER_HOST>:45678
export PORTHOUND_IP=<IP_DE_SALIDA_DEL_AGENTE>
env/bin/python manage.py
```

4. Opcion remota sin archivo CA (inline):

```bash
export PORTHOUND_ROLE=agent
export PORTHOUND_MASTER=https://<MASTER_HOST>:45678
export PORTHOUND_CA_ONELINE='-----BEGIN CERTIFICATE-----\n...'
export PORTHOUND_AGENT_CERT=/ruta/agent.cert.pem
export PORTHOUND_AGENT_KEY=/ruta/agent.key.pem
export PORTHOUND_IP=<IP_DE_SALIDA_DEL_AGENTE>
env/bin/python manage.py
```

Obtener CA one-line desde el master:

```bash
curl -k \
  --cert certs/admin/admin.cert.pem \
  --key certs/admin/admin.key.pem \
  https://<MASTER_HOST>:45678/api/cluster/ca/oneline
```

### 5) Verificacion final (master + agentes)

- Abre `https://<MASTER_HOST>:45678/cluster/agents/` y confirma `online`.
- Consulta API de agentes:

```bash
curl -k \
  --cert certs/admin/admin.cert.pem \
  --key certs/admin/admin.key.pem \
  https://<MASTER_HOST>:45678/api/cluster/agents
```

### Ejecucion legacy (sin cluster)

```bash
env/bin/python server.py   # API de escaneo
env/bin/python ws_demo.py  # Demo HTTP/WS
```

---

## 🧩 Estructura del proyecto

- `app.py` -> app principal con rutas `plain/api/ws`.
- `framework.py` -> micro framework interno (router, request/response, WS).
- `server.py` -> motor de escaneo TCP/UDP + banners + SQLite.
- `ws_demo.py` -> servidor HTTP/WS con ORM ligero y UI demo.
- `settings.py` -> configuracion del servidor.
- `frontend/` -> frontend Vue 3.
- `scripts/generate_certs.py` -> PKI local (CA + certs mTLS).

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
- `wss://HOST:PORT/ws/`

Cluster master/agent:
- `GET /api/cluster/agents`
- `GET /api/cluster/ca`
- `GET /api/cluster/ca/raw`
- `GET /api/cluster/ca/oneline`
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

## 📄 Licencia / License

Este proyecto esta licenciado bajo la Licencia MIT. Consulta el archivo `LICENSE` para mas detalles.

This project is licensed under the MIT License. See `LICENSE` for details.
