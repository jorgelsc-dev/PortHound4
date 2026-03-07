# WebSocket

## Endpoint
- wss://HOST:PORT/ws/

## Behavior
- Text messages are echoed back.
- Binary messages are echoed with a BIN ECHO prefix.
- Messages formatted as [alias] text are stored in SQLite (chat demo).

## Control API
See API.md for broadcast, ping, close, and chat endpoints.
