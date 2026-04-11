# FAST_DOCKER.md

Guia rapida para levantar `master + 1 agent` con imagen de GHCR.

## 1) Variables

```bash
export IMAGE=ghcr.io/jorgelsc-dev/porthound4:production
export ADMIN_TOKEN='admin-porthound'
export AGENT_ID='agent-01'
export AGENT_TOKEN='token-agent-01'
```

## 2) Descargar imagen

```bash
docker pull "$IMAGE"
```

## 3) Crear red y volumenes

```bash
docker network create porthound_net || true
docker volume create porthound_master_data
docker volume create porthound_agent_data
```

## 4) Limpiar contenedores previos

```bash
docker rm -f porthound-master porthound-agent-01 >/dev/null 2>&1 || true
```

## 5) Iniciar master

```bash
docker run -d \
  --name porthound-master \
  --network porthound_net \
  -p 45678:45678 \
  -e PORTHOUND_API_TOKEN="$ADMIN_TOKEN" \
  -v porthound_master_data:/data \
  "$IMAGE"
```

## 6) Crear credencial del agent en el master

```bash
sleep 3
curl -sS -X POST http://127.0.0.1:45678/api/cluster/agent/credentials \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"agent_id\":\"$AGENT_ID\",\"token\":\"$AGENT_TOKEN\"}"
```

## 7) Iniciar agent enlazado al master

```bash
docker run -d \
  --name porthound-agent-01 \
  --network porthound_net \
  -e PORTHOUND_ROLE=agent \
  -e PORTHOUND_MASTER=http://porthound-master:45678 \
  -e PORTHOUND_AGENT_ID="$AGENT_ID" \
  -e PORTHOUND_AGENT_TOKEN="$AGENT_TOKEN" \
  -e PORTHOUND_DB_PATH=/data/Agent.db \
  -v porthound_agent_data:/data \
  "$IMAGE"
```

## 8) Verificar estado del cluster

```bash
curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://127.0.0.1:45678/api/cluster/agents
```

## 9) Logs

```bash
docker logs --tail 100 porthound-master
docker logs --tail 100 porthound-agent-01
```
