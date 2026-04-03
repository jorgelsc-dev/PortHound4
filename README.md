# 🛡️ PortHound4

PortHound4 es una herramienta profesional de ciberseguridad para escaneo de red, deteccion de servicios y banner grabbing. Combina escaneo TCP/UDP, almacenamiento en SQLite y un API/WS ligero para integracion y control.

PortHound4 is a professional cybersecurity tool for network scanning, service detection, and banner grabbing. It combines TCP/UDP scanning, SQLite storage, and a lightweight API/WS layer for orchestration.

---

## 📘 Documentacion

- `README.md` -> guia principal del proyecto.
- `FAST.md` -> guia corta, directa y simple para arrancar rapido.
- `docs/` -> notas tecnicas adicionales.

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

Entrada directa equivalente:

```bash
env/bin/python master.py
```

Al ejecutar `python manage.py`, se asume `master` y te pedira:
- `IP`: `0.0.0.0`
- `Port`: `45678`
- (TLS queda desactivado por politica)

2. Arranque por argumentos (equivalente):

```bash
env/bin/python manage.py \
  --role master \
  --host 0.0.0.0 \
  --port 45678 \
  --db-path Master.db
```

3. Arranque rapido sin argumentos:

```bash
env/bin/python manage.py
```

`manage.py` abre wizard en terminal (uno por uno) y usa la DB del rol (`Master.db`) como valores por defecto.

4. Verifica que el master responda:
- UI/API: `http://localhost:45678` o `http://127.0.0.1:45678`
- No uses `http://0.0.0.0:45678` en el navegador.
- Vista de agentes: `http://localhost:45678/cluster/agents/`

5. Si ya guardaste valores incorrectos en DB:
- Vuelve a ejecutar con argumentos explicitos (sobrescribe y guarda de nuevo).
- O ejecuta `env/bin/python manage.py --interactive` y corrige los campos.

### 3) Paso a paso: Agente (repetir por cada agente)

1. En el master abre la web: `http://localhost:45678/cluster/agents/`
- Pulsa `Agregar agente`.
- Copia `agent_id` + `token` del bloque generado.
- Copia el `ENROLL BASE64` (contiene JSON con todo lo necesario).
- Copia `COMANDO RAPIDO (copiar/pegar en el agente)`.
- Ese bloque ya trae exactamente lo que debes responder en el wizard del agente.

2. En el agente:

```bash
env/bin/python manage.py agent
```

Entrada directa equivalente:

```bash
env/bin/python agent.py
```

Al ejecutar `python manage.py agent`, te pedira:
- `Enroll base64 (opcional)`: pega el base64 del master para autocompletar todo.
- `agent_id`: `<agent_id generado en la web>`
- `token`: `<token generado en la web>`
- `master_ip`: `<IP del master>`
- `master_host`: `<host del master>`

3. Enroll directo (recomendado si ya tienes base64):

```bash
env/bin/python manage.py agent --enroll '<BASE64_DEL_MASTER>'
```

4. Inicia un agente por argumentos (opcional para remoto):

```bash
env/bin/python manage.py \
  --role agent \
  --master http://<MASTER_HOST>:45678 \
  --agent-id <agent_id_generado_en_web> \
  --agent-token <token_generado_en_web> \
  --ip <IP_DE_SALIDA_DEL_AGENTE>
```

5. Alternativa rapida por env (sin argumentos):

```bash
export PORTHOUND_ROLE=agent
export PORTHOUND_MASTER=http://<MASTER_HOST>:45678
export PORTHOUND_AGENT_ID=<agent_id_generado_en_web>
export PORTHOUND_AGENT_TOKEN=<token_generado_en_web>
export PORTHOUND_IP=<IP_DE_SALIDA_DEL_AGENTE>
env/bin/python manage.py
```

### 4) Verificacion final (master + agentes)

- Abre `http://<MASTER_HOST>:45678/cluster/agents/` y confirma `online`.
- Consulta API de agentes:

```bash
curl http://<MASTER_HOST>:45678/api/cluster/agents
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
4. En el agente ejecuta `env/bin/python agent.py` o `env/bin/python manage.py agent`.
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

## 📄 Licencia / License

Este proyecto esta licenciado bajo la Licencia MIT. Consulta el archivo `LICENSE` para mas detalles.

This project is licensed under the MIT License. See `LICENSE` for details.
