# FAST.md

Guia muy simple para usar PortHound4 sin leer todo el `README.md`.

## 1) Crear entorno

```bash
python3 -m venv env
env/bin/python -m pip install --upgrade pip
```

## 2) Iniciar el master

La forma mas simple:

```bash
env/bin/python master.py
```

Alternativa:

```bash
env/bin/python manage.py
```

Luego abre en el navegador:

```text
http://localhost:45678/cluster/agents/
```

## 3) Crear un agente desde la web

En la vista `/cluster/agents/`:

1. Pulsa `Agregar agente`.
2. Copia el `agent_id`.
3. Copia el `token`.
4. Copia el `ENROLL BASE64`.

## 4) Iniciar el agente

Forma simple con asistente:

```bash
env/bin/python manage.py agent
```

Forma directa:

```bash
env/bin/python agent.py
```

Si usas `manage.py agent`, responde:

- `Enroll base64 (opcional)`: pega el base64 del master para autocompletar todo.
- `agent_id`: el que te dio el master.
- `token`: el que te dio el master.
- `master_ip`: la IP del master.
- `master_host`: el host del master.

Enroll directo (recomendado):

```bash
env/bin/python manage.py agent --enroll '<BASE64_DEL_MASTER>'
```

## 5) Confirmar que funciona

Vuelve a abrir:

```text
http://localhost:45678/cluster/agents/
```

Si todo va bien, el agente debe verse como `online`.

## 6) Flujo basico de uso

1. Levanta el `master`.
2. Registra uno o mas agentes.
3. Desde la interfaz del master crea targets o tareas.
4. El agente toma la tarea, ejecuta el escaneo y reporta resultados.

## 7) Si algo falla

- Si ves `Only http:// URLs are supported`, usa `http://` y no `https://`.
- Si ves `Invalid agent_id or token`, crea una credencial nueva y vuelve a copiarla.
- Si el agente tarda mucho, revisa la consola del agente; ahi imprime el progreso.

## 8) Modo legacy

Si no quieres usar master/agent:

```bash
env/bin/python server.py
env/bin/python ws_demo.py
```
