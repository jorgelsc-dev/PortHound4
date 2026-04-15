# enhanced_server.py (versión basada en clases Threading + ORM SQLite)
# Servidor HTTP + WebSocket + REST con funcionalidades WebSocket ampliadas:
# - text / binary
# - fragmentation (continuation frames)
# - control frames: ping/pong/close (parseo de close code + reason)
# - negociación de subprotocolos (Sec-WebSocket-Protocol)
# - API REST para listar clientes, broadcast, ping, cerrar
# - ORM SQLite con concurrencia y transacciones anidadas
# UNICAS librerías externas: socket, threading, uuid, time, json, sqlite3

import socket
import threading
import uuid
import time
import json
import sqlite3

HOST = '0.0.0.0'
PORT = 8765

MAGIC_WS = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# ============================================================
#  SHA1 (implementación pura en Python para no importar hashlib)
# ============================================================

def _left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

def sha1(data_bytes):
    message = bytearray(data_bytes)
    orig_len_bits = (8 * len(message)) & 0xffffffffffffffff
    message.append(0x80)
    while (len(message) * 8) % 512 != 448:
        message.append(0)
    message += orig_len_bits.to_bytes(8, 'big')

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    for i in range(0, len(message), 64):
        w = [0] * 80
        chunk = message[i:i+64]
        for j in range(16):
            w[j] = int.from_bytes(chunk[j*4:(j+1)*4], 'big')
        for j in range(16, 80):
            w[j] = _left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)

        a, b, c, d, e = h0, h1, h2, h3, h4
        for t in range(80):
            if 0 <= t <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= t <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= t <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            tmp = (_left_rotate(a, 5) + f + e + k + w[t]) & 0xffffffff
            e = d
            d = c
            c = _left_rotate(b, 30)
            b = a
            a = tmp

        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    digest = b''.join(x.to_bytes(4, 'big') for x in [h0, h1, h2, h3, h4])
    return digest

# ============================================================
#  Base64 (implementación mínima para bytes -> base64 str)
# ============================================================

B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def base64_encode(data_bytes):
    res = []
    i = 0
    n = len(data_bytes)
    while i < n:
        b = data_bytes[i:i+3]
        i += 3
        pad = 3 - len(b)
        val = 0
        for x in b:
            val = (val << 8) + x
        val <<= (pad * 8)
        for j in range(18, -1, -6):
            idx = (val >> j) & 0x3F
            res.append(B64_ALPHABET[idx])
        if pad:
            res[-pad:] = '=' * pad
    return ''.join(res)

# ============================================================
#  Utilidades WebSocket frames
# ============================================================

def recv_exact(conn, n):
    data = b''
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return data

def read_ws_frame_raw(conn):
    """
    Lee un único frame y devuelve (fin, opcode, payload_bytes, masked_flag, mask_bytes).
    No realiza ensamblado de fragmentation (eso lo hace el loop).
    """
    hdr = recv_exact(conn, 2)
    b1, b2 = hdr[0], hdr[1]
    fin = (b1 >> 7) & 1
    opcode = b1 & 0x0f
    masked = (b2 >> 7) & 1
    payload_len = b2 & 0x7f

    if payload_len == 126:
        ext = recv_exact(conn, 2)
        payload_len = int.from_bytes(ext, 'big')
    elif payload_len == 127:
        ext = recv_exact(conn, 8)
        payload_len = int.from_bytes(ext, 'big')

    mask = None
    if masked:
        mask = recv_exact(conn, 4)

    payload = b''
    if payload_len:
        payload = recv_exact(conn, payload_len)
        if masked and mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return fin, opcode, payload, bool(masked), mask

def make_ws_frame_bytes(opcode, payload=b''):
    """
    Construye un frame desde el servidor hacia el cliente (no enmascarado).
    opcode: int (1=text,2=binary,8=close,9=ping,10=pong,0=continuation)
    payload: bytes
    """
    fin = 0x80  # siempre FIN=1 salvo que se quiera fragmentar por el servidor
    b1 = fin | (opcode & 0x0f)
    payload_len = len(payload)
    header = bytes([b1])

    if payload_len <= 125:
        header += bytes([payload_len])
    elif payload_len <= 65535:
        header += bytes([126]) + payload_len.to_bytes(2, 'big')
    else:
        header += bytes([127]) + payload_len.to_bytes(8, 'big')

    return header + payload

def parse_close_payload(payload):
    """
    Si payload >=2, los primeros 2 bytes son close-code, resto utf-8 reason.
    Devuelve (code:int or None, reason:str or None)
    """
    if not payload:
        return None, None
    if len(payload) >= 2:
        code = int.from_bytes(payload[:2], 'big')
        reason = ''
        if len(payload) > 2:
            try:
                reason = payload[2:].decode('utf-8', errors='ignore')
            except Exception:
                reason = ''
        return code, reason
    return None, None

# ============================================================
#  HTTP helpers
# ============================================================

def parse_http_request(conn):
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = conn.recv(1024)
        if not chunk:
            break
        data += chunk
        if len(data) > 65536:
            break
    header_text, _, remainder = data.partition(b'\r\n\r\n')
    lines = header_text.decode('utf-8', errors='ignore').split('\r\n')
    if not lines:
        return None
    request_line = lines[0]
    parts = request_line.split()
    if len(parts) != 3:
        return None
    method, path, version = parts
    if not version.startswith('HTTP/'):
        return None
    headers = {}
    for line in lines[1:]:
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip().lower()] = v.strip()
    return {
        'method': method,
        'path': path,
        'version': version,
        'headers': headers,
        'remainder': remainder
    }

def send_http_response(conn, status_code=200, reason='OK', headers=None, body=b''):
    if headers is None:
        headers = {}
    status_line = f"HTTP/1.1 {status_code} {reason}\r\n"
    hdrs = ''
    lowermap = {k.lower(): v for k, v in headers.items()}
    if 'content-length' not in lowermap:
        headers['Content-Length'] = str(len(body))
    if 'connection' not in lowermap:
        headers['Connection'] = 'close'
    if 'server' not in lowermap:
        headers['Server'] = 'MinimalWS/1.0'
    for k, v in headers.items():
        hdrs += f"{k}: {v}\r\n"
    resp = status_line + hdrs + "\r\n"
    try:
        conn.sendall(resp.encode('utf-8') + body)
    except Exception as e:
        print(f"[HTTP] Error enviando respuesta {status_code}: {e}")

def parse_query_string(qs):
    """
    Parser sencillo de query-string (sin decode de %).
    Ej: "limit=50&foo=bar" -> {"limit": "50", "foo": "bar"}
    """
    params = {}
    if not qs:
        return params
    parts = qs.split('&')
    for part in parts:
        if not part:
            continue
        if '=' in part:
            k, v = part.split('=', 1)
        else:
            k, v = part, ''
        params[k] = v
    return params

# ============================================================
#  HTML page (servida en /)
# ============================================================

INDEX_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Servidor WS avanzado</title>
  <style>
    body{font-family: Arial, sans-serif; max-width:900px; margin:20px;}
    button, input, select { margin:4px; }
    pre { background:#f0f0f0; padding:8px; overflow:auto; }
    fieldset{margin-bottom:10px;}
    legend{font-weight:bold;}
    #messages{max-height:250px; overflow-y:auto; border:1px solid #ccc; padding:4px;}
    #chat_text{width:70%;}
  </style>
</head>
<body>
  <h1>Servidor HTTP + WebSocket (avanzado)</h1>
  <p>Pruebas WebSocket + ORM SQLite (mensajes de chat persistidos).</p>
  <p>
    Support PortHound (optional): BTC
    <code id="btc_address">bc1q3lhxpr9yantvefmvhpd2h4lu0ykf3t45zvuve2</code>
    <button id="copy_btc" type="button">Copiar BTC</button>
  </p>

  <fieldset>
    <legend>Conexión WebSocket</legend>
    <div>
      <label>Plantillas de subprotocolos:
        <select id="subprotos_preset">
          <option value="">-- seleccionar plantilla --</option>
          <option value="chat">chat</option>
          <option value="chat,json">chat,json</option>
          <option value="chat,json,superchat">chat,json,superchat</option>
        </select>
      </label>
    </div>
    <div>
      <label>Subprotocolos deseados (comma-separated):
        <input id="subprotos" value="chat"/>
      </label>
    </div>

    <button id="connect">Conectar WS</button>
    <button id="disconnect">Desconectar</button>
    <div id="wsstatus">Estado: cerrado</div>
    <div>ID de este cliente (asignado por servidor): <code id="this_client_id">desconocido</code></div>
  </fieldset>

  <fieldset>
    <legend>Enviar (cliente)</legend>
    <input id="textmsg" placeholder="Texto..." size="60"/>
    <button id="sendtext">Enviar texto</button>
    <button id="sendbinary">Enviar binario (ejemplo 0..9)</button>
    <button id="sendfragmented">Enviar fragmentado (texto largo dividido)</button>
  </fieldset>

  <fieldset>
    <legend>Peticiones REST al servidor (control desde página)</legend>
    <button id="listclients">Listar clientes (API) + rellenar select</button>
    <button id="server_broadcast">Pedir broadcast de texto por servidor</button>
    <button id="server_ping">Pedir ping desde servidor a todos</button>
    <button id="server_chat_list">Listar mensajes de chat (API)</button>
    <button id="server_chat_clear">Borrar mensajes de chat (API)</button>
  </fieldset>

  <fieldset>
    <legend>Cerrar conexión desde servidor</legend>
    <div>
      <label>Seleccionar cliente:
        <select id="close_client_select">
          <option value="">-- sin selección (usar campo manual) --</option>
        </select>
      </label>
    </div>
    <div>
      <input id="close_client_id" placeholder="client id (manual / opcional)" size="40"/>
    </div>
    <div>
      <input id="close_code" placeholder="Código (1000)" size="8"/>
      <input id="close_reason" placeholder="Razón" size="20"/>
      <button id="server_close">Pedir cerrar</button>
    </div>
  </fieldset>

  <h3>Mensajes / Log</h3>
  <ul id="messages"></ul>

  <hr/>

  <fieldset>
    <legend>Chat sencillo (sobre este servidor, persistido en SQLite)</legend>
    <div>
      <label>Alias:
        <input id="chat_alias" placeholder="tu nombre o nick" size="20"/>
      </label>
      <button id="chat_save_alias">Guardar alias</button>
    </div>
    <div>
      <label>Modo de envío:
        <select id="chat_mode">
          <option value="local">Solo a este WebSocket (echo servidor)</option>
          <option value="broadcast">Broadcast a todos (API /api/ws/broadcast)</option>
          <option value="ping">Ping (API /api/ws/ping)</option>
        </select>
      </label>
    </div>
    <div>
      <input id="chat_text" placeholder="Escribe un mensaje de chat..." />
      <button id="chat_send">Enviar</button>
      <button id="chat_clear">Limpiar log</button>
    </div>
    <p style="font-size:12px;color:#666;">
      Los mensajes que parezcan "[alias] texto" se guardan en SQLite en la tabla "chat_messages".
      Puedes verlos con <code>GET /api/chat/messages?limit=20</code>.
    </p>
  </fieldset>

<script>
let ws = null;

function addMsg(s){
  const ul = document.getElementById('messages');
  const li = document.createElement('li');
  const ts = new Date().toISOString();
  li.textContent = '[' + ts + '] ' + s;
  ul.appendChild(li);
  ul.scrollTop = ul.scrollHeight;
}

document.getElementById('copy_btc').onclick = function(){
  const el = document.getElementById('btc_address');
  const value = el ? String(el.textContent || '').trim() : '';
  if(!value){
    return;
  }
  if(navigator && navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(value)
      .then(() => addMsg('[BTC] Dirección copiada al portapapeles.'))
      .catch(() => addMsg('[BTC] No se pudo copiar automáticamente.'));
    return;
  }
  addMsg('[BTC] Copia manual: ' + value);
};

function refreshClientsSelect(list){
  const sel = document.getElementById('close_client_select');
  if(!sel) return;
  sel.innerHTML = '';
  const opt0 = document.createElement('option');
  opt0.value = '';
  opt0.textContent = '-- sin selección (usar campo manual) --';
  sel.appendChild(opt0);

  if(!Array.isArray(list)) return;
  list.forEach(c => {
    const opt = document.createElement('option');
    opt.value = c.id;
    const proto = c.subprotocol ? (', proto=' + c.subprotocol) : '';
    opt.textContent = c.id + ' [' + c.addr + proto + ']';
    sel.appendChild(opt);
  });
}

function getChatAlias(){
  const el = document.getElementById('chat_alias');
  let alias = el ? el.value.trim() : '';
  if(!alias) alias = 'anon';
  return alias;
}

(function initAlias(){
  try{
    const stored = localStorage.getItem('ws_chat_alias');
    if(stored){
      const el = document.getElementById('chat_alias');
      if(el) el.value = stored;
    }
  }catch(e){}
})();

document.getElementById('subprotos_preset').onchange = function(){
  const val = this.value;
  if(val){
    document.getElementById('subprotos').value = val;
  }
};

document.getElementById('connect').onclick = function(){
  if(ws && ws.readyState === WebSocket.OPEN) return;
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = location.host;
  const sublist = document.getElementById('subprotos').value.trim();
  const subprotos = sublist ? sublist.split(',').map(s=>s.trim()).filter(Boolean) : undefined;
  const wsurl = protocol + '//' + host + '/ws/';
  try {
    ws = subprotos && subprotos.length ? new WebSocket(wsurl, subprotos) : new WebSocket(wsurl);
  } catch(e) {
    addMsg('Error creando WebSocket: '+e);
    return;
  }
  ws.binaryType = 'arraybuffer';
  ws.onopen = () => {
    document.getElementById('wsstatus').innerText = 'Estado: abierto';
    addMsg('Conectado (protocol='+ws.protocol+')');
  };
  ws.onmessage = (ev) => {
    if(ev.data instanceof ArrayBuffer){
      const a = new Uint8Array(ev.data);
      addMsg('Recibido BINARIO len='+a.length+' bytes: '+Array.from(a).slice(0,20).join(','));
    } else {
      let prefix = 'Recibido: ';
      let txt = ev.data;
      try{
        const jd = JSON.parse(txt);
        if(jd && jd.type === 'welcome' && jd.client_id){
          document.getElementById('this_client_id').textContent = jd.client_id;
          prefix = 'Recibido (welcome JSON): ';
        }
      }catch(e){}
      addMsg(prefix + txt);
    }
  };
  ws.onclose = (e) => {
    document.getElementById('wsstatus').innerText = 'Estado: cerrado';
    addMsg('Cerrado code='+e.code+' reason='+e.reason);
  };
  ws.onerror = (e) => { addMsg('Error WS: ' + e); };
};

document.getElementById('disconnect').onclick = function(){
  if(ws) ws.close();
};

document.getElementById('sendtext').onclick = function(){
  if(!ws || ws.readyState !== WebSocket.OPEN){
    addMsg('WS no conectado');
    return;
  }
  const m = document.getElementById('textmsg').value || ('Hola desde cliente @ '+new Date().toISOString());
  ws.send(m);
  addMsg('Enviado texto: '+m);
};

document.getElementById('sendbinary').onclick = function(){
  if(!ws || ws.readyState !== WebSocket.OPEN){
    addMsg('WS no conectado');
    return;
  }
  const arr = new Uint8Array(10);
  for(let i=0;i<10;i++) arr[i]=i;
  ws.send(arr.buffer);
  addMsg('Enviado binario 10 bytes');
};

document.getElementById('sendfragmented').onclick = function(){
  if(!ws || ws.readyState !== WebSocket.OPEN){
    addMsg('WS no conectado');
    return;
  }
  const parts = ['parte1-','parte2-','parte3-','(fin)'];
  for(let p of parts){
    ws.send(p);
  }
  addMsg('Enviado (simulado) fragmentado como múltiples mensajes consecutivos');
};

async function callApi(path, method='GET', body=null, onOk){
  const opts = { method, headers: {} };
  if(body){
    opts.body = JSON.stringify(body);
    opts.headers['Content-Type']='application/json';
  }
  const r = await fetch(path, opts);
  const t = await r.text();
  let parsed = null;
  try{ parsed = JSON.parse(t); }catch(e){}
  if(r.ok && typeof onOk === 'function'){
    try{ onOk(parsed, t, r); }catch(e){}
  }
  addMsg('/api -> ' + r.status + ' ' + r.statusText + ' : ' + t);
  return t;
}

document.getElementById('listclients').onclick = () =>
  callApi('/api/ws/clients', 'GET', null, (jsonList) => {
    refreshClientsSelect(jsonList);
  });

document.getElementById('server_broadcast').onclick = () => {
  const text = prompt('Texto para broadcast por servidor:', 'Broadcast desde servidor @ '+new Date().toISOString());
  if(text) callApi('/api/ws/broadcast', 'POST', {type:'text', message:text});
};

document.getElementById('server_ping').onclick = () =>
  callApi('/api/ws/ping', 'POST', {});

document.getElementById('server_close').onclick = () => {
  const sel = document.getElementById('close_client_select');
  let id = sel && sel.value ? sel.value : null;
  if(!id){
    const manual = document.getElementById('close_client_id').value.trim();
    if(manual) id = manual;
  }
  const code = parseInt(document.getElementById('close_code').value) || 1000;
  const reason = document.getElementById('close_reason').value || '';
  callApi('/api/ws/close', 'POST', {client_id: id, code: code, reason: reason});
};

document.getElementById('server_chat_list').onclick = () =>
  callApi('/api/chat/messages?limit=20', 'GET', null);

document.getElementById('server_chat_clear').onclick = () =>
  callApi('/api/chat/clear', 'POST', {});

// ----- Chat UI -----
document.getElementById('chat_save_alias').onclick = function(){
  const alias = getChatAlias();
  try{
    localStorage.setItem('ws_chat_alias', alias);
  }catch(e){}
  addMsg('[CHAT] Alias establecido: ' + alias);
};

document.getElementById('chat_clear').onclick = function(){
  const ul = document.getElementById('messages');
  ul.innerHTML = '';
};

document.getElementById('chat_send').onclick = function(){
  const txtEl = document.getElementById('chat_text');
  const raw = (txtEl.value || '').trim();
  if(!raw){
    addMsg('[CHAT] Mensaje vacío, no se envía.');
    return;
  }
  const alias = getChatAlias();
  const modeSel = document.getElementById('chat_mode');
  const mode = modeSel ? modeSel.value : 'local';
  const full = '[' + alias + '] ' + raw;

  if(mode === 'local'){
    if(!ws || ws.readyState !== WebSocket.OPEN){
      addMsg('[CHAT] WS no conectado (modo local).');
      return;
    }
    ws.send(full);
    addMsg('[CHAT->WS] ' + full);
  } else if(mode === 'broadcast'){
    callApi('/api/ws/broadcast', 'POST', {type:'text', message: full});
    addMsg('[CHAT->API broadcast] ' + full);
  } else if(mode === 'ping'){
    callApi('/api/ws/ping', 'POST', {payload: full});
    addMsg('[CHAT->API ping] ' + full);
  }

  txtEl.value = '';
  txtEl.focus();
};

document.getElementById('chat_text').addEventListener('keydown', function(ev){
  if(ev.key === 'Enter'){
    ev.preventDefault();
    document.getElementById('chat_send').click();
  }
});
</script>
</body>
</html>
""".encode('utf-8')

# ============================================================
#  ORM SQLite (solo sqlite3 + threading)
# ============================================================

class Field:
    def __init__(self, column_type, primary_key=False, unique=False,
                 null=True, default=None, index=False):
        self.column_type = column_type
        self.primary_key = primary_key
        self.unique = unique
        self.null = null
        self.default = default
        self.index = index
        self.name = None  # se rellena en el metaclass

    def _sql_literal(self, value):
        if value is None:
            return "NULL"
        if isinstance(value, bool):
            return "1" if value else "0"
        if isinstance(value, (int, float)):
            return str(value)
        s = str(value).replace("'", "''")
        return "'" + s + "'"

    def ddl_fragment(self):
        parts = [self.name, self.column_type]
        if self.primary_key:
            parts.append("PRIMARY KEY")
        if self.unique:
            parts.append("UNIQUE")
        if not self.null and not self.primary_key:
            parts.append("NOT NULL")
        if self.default is not None and not self.primary_key:
            parts.append("DEFAULT")
            parts.append(self._sql_literal(self.default))
        return " ".join(parts)

class IntegerField(Field):
    def __init__(self, primary_key=False, unique=False, null=True,
                 default=None, index=False, auto_increment=False):
        super().__init__("INTEGER", primary_key=primary_key, unique=unique,
                         null=null, default=default, index=index)
        self.auto_increment = auto_increment

    def ddl_fragment(self):
        parts = [self.name, self.column_type]
        if self.primary_key:
            parts.append("PRIMARY KEY")
        if self.auto_increment and self.primary_key:
            parts.append("AUTOINCREMENT")
        if self.unique and not self.primary_key:
            parts.append("UNIQUE")
        if not self.null and not self.primary_key:
            parts.append("NOT NULL")
        if self.default is not None and not self.primary_key:
            parts.append("DEFAULT")
            parts.append(self._sql_literal(self.default))
        return " ".join(parts)

class TextField(Field):
    def __init__(self, primary_key=False, unique=False, null=True,
                 default=None, index=False):
        super().__init__("TEXT", primary_key=primary_key, unique=unique,
                         null=null, default=default, index=index)

class RealField(Field):
    def __init__(self, primary_key=False, unique=False, null=True,
                 default=None, index=False):
        super().__init__("REAL", primary_key=primary_key, unique=unique,
                         null=null, default=default, index=index)

class BlobField(Field):
    def __init__(self, primary_key=False, unique=False, null=True,
                 default=None, index=False):
        super().__init__("BLOB", primary_key=primary_key, unique=unique,
                         null=null, default=default, index=index)

class BooleanField(IntegerField):
    def __init__(self, primary_key=False, unique=False, null=True,
                 default=None, index=False):
        super().__init__(primary_key=primary_key, unique=unique,
                         null=null, default=default, index=index)

class ModelMeta(type):
    def __new__(mcls, name, bases, attrs):
        if name == "Model":
            return super().__new__(mcls, name, bases, attrs)

        fields = {}
        for key, value in list(attrs.items()):
            if isinstance(value, Field):
                value.name = key
                fields[key] = value

        tablename = attrs.get("__tablename__") or name.lower()
        pk_name = None
        for fname, field in fields.items():
            if field.primary_key:
                pk_name = fname
                break

        attrs["_meta"] = {
            "table": tablename,
            "fields": fields,
            "pk_name": pk_name,
        }

        return super().__new__(mcls, name, bases, attrs)

class Database:
    def __init__(self, path=":memory:", shared_cache=False,
                 timeout=10.0, pragmas=None):
        """
        path=":memory:"        -> BD en memoria privada
        shared_cache=True      -> usa "file::memory:?cache=shared" (uri=True)
        timeout=10.0           -> busy timeout
        pragmas=dict()         -> PRAGMAs extra
        """
        self._lock = threading.RLock()
        self._tx_depth = threading.local()

        if shared_cache:
            if path == ":memory:":
                dsn = "file::memory:?cache=shared"
            else:
                dsn = path
            self._conn = sqlite3.connect(
                dsn,
                check_same_thread=False,
                timeout=timeout,
                uri=True,
            )
        else:
            self._conn = sqlite3.connect(
                path,
                check_same_thread=False,
                timeout=timeout,
            )

        self._conn.row_factory = sqlite3.Row

        base_pragmas = {
            "journal_mode": "WAL",
            "synchronous": "NORMAL",
            "foreign_keys": 1,
            "busy_timeout": int(timeout * 1000),
        }
        if pragmas:
            base_pragmas.update(pragmas)

        for k, v in base_pragmas.items():
            self.set_pragma(k, v)

    def set_pragma(self, name, value):
        sql = "PRAGMA %s=%s" % (name, value)
        with self._lock:
            print("[DB]", sql)
            self._conn.execute(sql)

    def get_pragma(self, name):
        sql = "PRAGMA %s" % name
        with self._lock:
            print("[DB]", sql)
            cur = self._conn.execute(sql)
            row = cur.fetchone()
        if row is None:
            return None
        return row[0]

    def _get_tx_depth(self):
        return getattr(self._tx_depth, "value", 0)

    def _set_tx_depth(self, v):
        self._tx_depth.value = v

    def in_transaction(self):
        return self._get_tx_depth() > 0

    def execute(self, sql, params=None):
        if params is None:
            params = ()
        sql_trim = sql.strip()
        first = sql_trim.split()[0].upper() if sql_trim else ""
        is_write = first in (
            "INSERT", "UPDATE", "DELETE", "REPLACE",
            "CREATE", "DROP", "ALTER",
        )
        with self._lock:
            print("[DB] SQL:", sql_trim, "params=", params)
            cur = self._conn.execute(sql, params)
            if is_write and not self.in_transaction():
                self._conn.commit()
        return cur

    def executemany(self, sql, seq_of_params):
        sql_trim = sql.strip()
        first = sql_trim.split()[0].upper() if sql_trim else ""
        is_write = first in ("INSERT", "UPDATE", "DELETE", "REPLACE")
        with self._lock:
            count = 0
            for p in seq_of_params:
                print("[DB] SQL many:", sql_trim, "params=", p)
                self._conn.execute(sql, p)
                count += 1
            if is_write and not self.in_transaction():
                self._conn.commit()
        return count

    def transaction(self):
        return Transaction(self)

class Transaction:
    def __init__(self, db):
        self.db = db
        self._sp_name = None
        self._entered = False

    def __enter__(self):
        depth = self.db._get_tx_depth()
        if depth == 0:
            with self.db._lock:
                print("[DB] BEGIN")
                self.db._conn.execute("BEGIN")
            self.db._set_tx_depth(1)
        else:
            self._sp_name = "sp_%d" % depth
            with self.db._lock:
                print("[DB] SAVEPOINT", self._sp_name)
                self.db._conn.execute("SAVEPOINT %s" % self._sp_name)
            self.db._set_tx_depth(depth + 1)
        self._entered = True
        return self

    def __exit__(self, exc_type, exc, tb):
        if not self._entered:
            return False

        depth = self.db._get_tx_depth()
        try:
            if exc_type is not None:
                if self._sp_name is None:
                    with self.db._lock:
                        print("[DB] ROLLBACK")
                        self.db._conn.rollback()
                    self.db._set_tx_depth(0)
                else:
                    with self.db._lock:
                        print("[DB] ROLLBACK TO SAVEPOINT", self._sp_name)
                        self.db._conn.execute("ROLLBACK TO SAVEPOINT %s" % self._sp_name)
                        print("[DB] RELEASE SAVEPOINT", self._sp_name)
                        self.db._conn.execute("RELEASE SAVEPOINT %s" % self._sp_name)
                    self.db._set_tx_depth(depth - 1)
            else:
                if self._sp_name is None:
                    with self.db._lock:
                        print("[DB] COMMIT")
                        self.db._conn.commit()
                    self.db._set_tx_depth(0)
                else:
                    with self.db._lock:
                        print("[DB] RELEASE SAVEPOINT", self._sp_name)
                        self.db._conn.execute("RELEASE SAVEPOINT %s" % self._sp_name)
                    self.db._set_tx_depth(depth - 1)
        finally:
            self._entered = False
        return False

class QuerySet:
    def __init__(self, db, model, where=None, params=None,
                 order_by=None, limit=None, offset=None):
        self.db = db
        self.model = model
        self.where = where
        self.params = params or []
        self.order_by_clause = order_by
        self.limit_val = limit
        self.offset_val = offset

    def _clone(self, **overrides):
        kwargs = dict(
            db=self.db,
            model=self.model,
            where=self.where,
            params=list(self.params),
            order_by=self.order_by_clause,
            limit=self.limit_val,
            offset=self.offset_val,
        )
        for k, v in overrides.items():
            kwargs[k] = v
        return QuerySet(**kwargs)

    def where_raw(self, clause, *params):
        if self.where:
            new_where = "(" + self.where + ") AND (" + clause + ")"
            new_params = list(self.params) + list(params)
        else:
            new_where = clause
            new_params = list(params)
        return self._clone(where=new_where, params=new_params)

    def filter(self, **kwargs):
        clauses = []
        params = []
        for key, value in kwargs.items():
            if "__" in key:
                field_name, op = key.split("__", 1)
            else:
                field_name, op = key, "eq"

            column = field_name
            if op == "eq":
                clauses.append(column + " = ?")
                params.append(value)
            elif op == "gt":
                clauses.append(column + " > ?")
                params.append(value)
            elif op == "lt":
                clauses.append(column + " < ?")
                params.append(value)
            elif op == "gte":
                clauses.append(column + " >= ?")
                params.append(value)
            elif op == "lte":
                clauses.append(column + " <= ?")
                params.append(value)
            elif op == "ne":
                clauses.append(column + " != ?")
                params.append(value)
            elif op == "like":
                clauses.append(column + " LIKE ?")
                params.append(value)
            elif op == "in":
                if not value:
                    clauses.append("1=0")
                else:
                    placeholders = ",".join("?" for _ in value)
                    clauses.append(column + " IN (" + placeholders + ")")
                    for v in value:
                        params.append(v)
            else:
                raise ValueError("Operador no soportado: " + op)

        if clauses:
            clause = " AND ".join(clauses)
            return self.where_raw(clause, *params)
        else:
            return self

    def order_by(self, clause):
        return self._clone(order_by=clause)

    def limit(self, n, offset=None):
        return self._clone(limit=n, offset=offset if offset is not None else self.offset_val)

    def _build_select(self):
        fields = list(self.model._meta["fields"].keys())
        columns_sql = ", ".join(fields)
        table = self.model._meta["table"]
        sql = "SELECT " + columns_sql + " FROM " + table
        params = list(self.params)
        if self.where:
            sql += " WHERE " + self.where
        if self.order_by_clause:
            sql += " ORDER BY " + self.order_by_clause
        if self.limit_val is not None:
            sql += " LIMIT ?"
            params.append(self.limit_val)
        if self.offset_val is not None:
            sql += " OFFSET ?"
            params.append(self.offset_val)
        return sql, params

    def all(self):
        sql, params = self._build_select()
        cur = self.db.execute(sql, params)
        rows = cur.fetchall()
        objs = []
        for row in rows:
            objs.append(self.model.from_row(row))
        return objs

    def first(self):
        qs = self.limit(1)
        sql, params = qs._build_select()
        cur = self.db.execute(sql, params)
        row = cur.fetchone()
        if not row:
            return None
        return self.model.from_row(row)

    def get(self, **kwargs):
        qs = self.filter(**kwargs).limit(2)
        sql, params = qs._build_select()
        cur = self.db.execute(sql, params)
        rows = cur.fetchall()
        if not rows:
            raise LookupError("No se encontró ningún registro")
        if len(rows) > 1:
            raise LookupError("Se encontraron múltiples registros para .get()")
        return self.model.from_row(rows[0])

    def count(self):
        table = self.model._meta["table"]
        sql = "SELECT COUNT(*) AS c FROM " + table
        params = list(self.params)
        if self.where:
            sql += " WHERE " + self.where
        cur = self.db.execute(sql, params)
        row = cur.fetchone()
        return row["c"]

    def delete(self):
        table = self.model._meta["table"]
        sql = "DELETE FROM " + table
        params = list(self.params)
        if self.where:
            sql += " WHERE " + self.where
        cur = self.db.execute(sql, params)
        return cur.rowcount

    def update(self, **kwargs):
        if not kwargs:
            return 0
        table = self.model._meta["table"]
        set_clauses = []
        params = []
        for k, v in kwargs.items():
            set_clauses.append(k + " = ?")
            params.append(v)
        sql = "UPDATE " + table + " SET " + ", ".join(set_clauses)
        if self.where:
            sql += " WHERE " + self.where
            params.extend(self.params)
        cur = self.db.execute(sql, params)
        return cur.rowcount

    def create(self, **kwargs):
        obj = self.model(**kwargs)
        obj.save(self.db)
        return obj

class Model(metaclass=ModelMeta):
    __tablename__ = None

    def __init__(self, **kwargs):
        fields = self._meta["fields"]
        for name, field in fields.items():
            if name in kwargs:
                value = kwargs[name]
            else:
                if callable(field.default):
                    value = field.default()
                else:
                    value = field.default
            setattr(self, name, value)

    @classmethod
    def create_table(cls, db, if_not_exists=True):
        fields = cls._meta["fields"]
        table = cls._meta["table"]
        if not fields:
            raise RuntimeError("Modelo sin campos: " + cls.__name__)

        column_ddls = []
        index_ddls = []
        for name, field in fields.items():
            field.name = name
            column_ddls.append(field.ddl_fragment())
            if field.index and not field.primary_key:
                idx_name = "idx_%s_%s" % (table, name)
                unique = "UNIQUE " if field.unique else ""
                idx_sql = "CREATE " + unique + "INDEX IF NOT EXISTS " + idx_name
                idx_sql += " ON " + table + " (" + name + ");"
                index_ddls.append(idx_sql)

        ine = "IF NOT EXISTS " if if_not_exists else ""
        sql = "CREATE TABLE " + ine + table + " (\n  "
        sql += ",\n  ".join(column_ddls) + "\n);"
        db.execute(sql)
        for idx_sql in index_ddls:
            db.execute(idx_sql)

    @classmethod
    def drop_table(cls, db, if_exists=True):
        table = cls._meta["table"]
        ie = "IF EXISTS " if if_exists else ""
        sql = "DROP TABLE " + ie + table + ";"
        db.execute(sql)

    @classmethod
    def objects(cls, db):
        return QuerySet(db, cls)

    @classmethod
    def from_row(cls, row):
        if row is None:
            return None
        data = {}
        for name in cls._meta["fields"].keys():
            data[name] = row[name]
        return cls(**data)

    @classmethod
    def raw(cls, db, sql, params=None):
        if params is None:
            params = ()
        cur = db.execute(sql, params)
        rows = cur.fetchall()
        objs = []
        for row in rows:
            data = {}
            for name in cls._meta["fields"].keys():
                if name in row.keys():
                    data[name] = row[name]
                else:
                    data[name] = None
            objs.append(cls(**data))
        return objs

    def pk_value(self):
        pk_name = self._meta["pk_name"]
        if pk_name is None:
            return None
        return getattr(self, pk_name, None)

    def save(self, db):
        fields = self._meta["fields"]
        table = self._meta["table"]
        pk_name = self._meta["pk_name"]
        pk_val = None
        if pk_name:
            pk_val = getattr(self, pk_name, None)

        if pk_name and pk_val is not None:
            cols = []
            params = []
            for name, field in fields.items():
                if name == pk_name:
                    continue
                cols.append(name + "=?")
                params.append(getattr(self, name))
            params.append(pk_val)
            sql = "UPDATE " + table + " SET " + ", ".join(cols)
            sql += " WHERE " + pk_name + "=?"
            cur = db.execute(sql, params)
            return cur.rowcount
        else:
            cols = []
            placeholders = []
            params = []
            for name, field in fields.items():
                if field.primary_key and isinstance(field, IntegerField):
                    continue
                cols.append(name)
                placeholders.append("?")
                params.append(getattr(self, name))
            sql = "INSERT INTO " + table + " (" + ", ".join(cols) + ")"
            sql += " VALUES (" + ", ".join(placeholders) + ")"
            cur = db.execute(sql, params)
            if pk_name and isinstance(fields[pk_name], IntegerField):
                new_id = cur.lastrowid
                setattr(self, pk_name, new_id)
            return 1

    def delete(self, db):
        table = self._meta["table"]
        pk_name = self._meta["pk_name"]
        if not pk_name:
            raise RuntimeError("Modelo sin clave primaria, delete() no soportado")
        pk_val = getattr(self, pk_name, None)
        if pk_val is None:
            return 0
        sql = "DELETE FROM " + table + " WHERE " + pk_name + "=?"
        cur = db.execute(sql, (pk_val,))
        return cur.rowcount

    def to_dict(self):
        data = {}
        for name in self._meta["fields"].keys():
            data[name] = getattr(self, name)
        return data

# ============================================================
#  Modelo ChatMessage (ejemplo de uso del ORM)
# ============================================================

class ChatMessage(Model):
    __tablename__ = "chat_messages"
    id = IntegerField(primary_key=True, auto_increment=True)
    client_id = TextField(index=True, null=False)
    alias = TextField(null=False)
    message = TextField(null=False)
    created_at = IntegerField(null=False, index=True)

def parse_chat_line(text):
    """
    Intenta parsear "[alias] mensaje" y devuelve (alias, mensaje).
    Si no coincide el patrón, alias=None y mensaje=text.
    """
    if text.startswith('['):
        idx = text.find(']')
        if idx > 1:
            alias = text[1:idx].strip()
            msg = text[idx+1:].lstrip()
            return alias or 'anon', msg
    return None, text

# ============================================================
#  ClientRegistry (gestiona clientes WS de forma thread-safe)
# ============================================================

class ClientRegistry:
    def __init__(self):
        self._clients = {}  # client_id -> dict {sock, addr, thread, subprotocol, created}
        self._lock = threading.Lock()

    def register_client(self, client_id, sock, addr, thread, subprotocol):
        with self._lock:
            self._clients[client_id] = {
                'sock': sock,
                'addr': addr,
                'thread': thread,
                'subprotocol': subprotocol or '',
                'created': time.time()
            }
        try:
            print(f"[WS] Registrado cliente {client_id} desde {addr} (subprotocol={subprotocol or ''})")
        except Exception:
            pass

    def unregister_client(self, client_id):
        with self._lock:
            info = self._clients.pop(client_id, None)
        if info:
            try:
                info['sock'].close()
            except Exception:
                pass
            try:
                print(f"[WS] Cliente {client_id} desconectado")
            except Exception:
                pass

    def list_clients_info(self):
        with self._lock:
            out = []
            for cid, info in self._clients.items():
                out.append({
                    'id': cid,
                    'addr': f"{info['addr'][0]}:{info['addr'][1]}",
                    'subprotocol': info.get('subprotocol',''),
                    'created': info.get('created',0)
                })
        print(f"[WS] list_clients_info -> {len(out)} clientes")
        return out

    def send_to_client(self, client_id, opcode, payload=b''):
        with self._lock:
            info = self._clients.get(client_id)
            if not info:
                print(f"[WS] send_to_client: cliente {client_id} no encontrado")
                return False, "no such client"
            sock = info['sock']
        try:
            sock.sendall(make_ws_frame_bytes(opcode, payload))
            print(f"[WS] send_to_client: cid={client_id} opcode={opcode} len={len(payload)}")
            return True, "sent"
        except Exception as e:
            print(f"[WS] Error en send_to_client {client_id}: {e}")
            return False, str(e)

    def broadcast(self, opcode, payload=b''):
        failed = []
        with self._lock:
            items = list(self._clients.items())
        print(f"[WS] broadcast: opcode={opcode} len={len(payload)} a {len(items)} clientes")
        for cid, info in items:
            try:
                info['sock'].sendall(make_ws_frame_bytes(opcode, payload))
                print(f"[WS]  broadcast -> cid={cid} OK")
            except Exception as e:
                print(f"[WS]  broadcast -> cid={cid} ERROR: {e}")
                failed.append((cid, str(e)))
        return failed

# ============================================================
#  ConnectionThread (maneja una conexión TCP)
# ============================================================

class ConnectionThread(threading.Thread):
    def __init__(self, conn, addr, registry, db):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.registry = registry
        self.db = db

    def run(self):
        print(f"[HTTP] Nueva conexión desde {self.addr}")
        try:
            req = parse_http_request(self.conn)
            if not req:
                print(f"[HTTP] Petición vacía/incorrecta desde {self.addr}, cerrando.")
                self.conn.close()
                return

            raw_path = req['path']
            method = req['method'].upper()
            headers = req['headers']
            print(f"[HTTP] {self.addr} {method} {raw_path}")
            path, _, query = raw_path.partition('?')
            req['path'] = path
            req['query'] = query

            if path == '/ws/' and headers.get('upgrade','').lower() == 'websocket':
                client_id = str(uuid.uuid4())
                print(f"[HTTP->WS] Upgrade solicitado por {self.addr}, client_id={client_id}")
                self.handle_ws_connection(req, client_id)
                return

            if path.startswith('/api/'):
                self.handle_api(req)
                self.conn.close()
                return

            if path == '/' and method == 'GET':
                print(f"[HTTP] Sirviendo INDEX_HTML a {self.addr}")
                send_http_response(self.conn, 200, 'OK',
                                   {'Content-Type':'text/html; charset=utf-8'},
                                   INDEX_HTML)
                self.conn.close()
                return

            print(f"[HTTP] 404 Not Found {path} desde {self.addr}")
            send_http_response(self.conn, 404, 'Not Found',
                               {'Content-Type':'text/plain; charset=utf-8'},
                               b'Not Found')
            self.conn.close()
        except Exception as e:
            print(f"[HTTP] Excepción manejando conexión desde {self.addr}: {e}")
            try:
                self.conn.close()
            except Exception:
                pass

    # ----------------------------
    # API handler (por conexión, usa ClientRegistry + ORM)
    # ----------------------------
    def handle_api(self, req):
        method = req['method']
        path = req['path']
        headers = req['headers']
        body = req['remainder']
        query = req.get('query','') or ''

        print(f"[API] {method} {path}?{query}")

        if 'content-length' in headers:
            try:
                cl = int(headers['content-length'])
            except Exception:
                cl = 0
            if cl < 0:
                cl = 0
            if len(body) < cl:
                need = cl - len(body)
                if need > 0:
                    body += recv_exact(self.conn, need)

        if path == '/api/hello':
            if method.upper() == 'GET':
                print("[API] /api/hello GET")
                payload = '{"message":"Hello from server"}'.encode('utf-8')
                send_http_response(self.conn, 200, 'OK',
                                   {'Content-Type':'application/json; charset=utf-8'},
                                   payload)
                return True
            else:
                print("[API] /api/hello método no permitido")
                send_http_response(self.conn, 405, 'Method Not Allowed', {'Allow':'GET'}, b'')
                return True

        if path == '/api/echo':
            if method.upper() == 'POST':
                try:
                    body_text = body.decode('utf-8', errors='ignore')
                except Exception:
                    body_text = ''
                print(f"[API] /api/echo cuerpo={body_text[:200]!r}")
                esc = body_text.replace('\\','\\\\').replace('"','\\"')
                payload = ('{"received":"%s"}' % esc).encode('utf-8')
                send_http_response(self.conn, 200, 'OK',
                                   {'Content-Type':'application/json; charset=utf-8'},
                                   payload)
                return True
            else:
                send_http_response(self.conn, 405, 'Method Not Allowed', {'Allow':'POST'}, b'')
                return True

        if path == '/api/ws/clients':
            print("[API] /api/ws/clients listado")
            info = self.registry.list_clients_info()
            payload = json.dumps(info, default=str).encode('utf-8')
            send_http_response(self.conn, 200, 'OK',
                               {'Content-Type':'application/json; charset=utf-8'},
                               payload)
            return True

        if path == '/api/ws/broadcast':
            if method.upper() != 'POST':
                send_http_response(self.conn, 405, 'Method Not Allowed', {'Allow':'POST'}, b'')
                return True
            try:
                jd = json.loads(body.decode('utf-8') or '{}')
            except Exception:
                jd = {}
            t = jd.get('type','text')
            message = jd.get('message','')
            print(f"[API] /api/ws/broadcast type={t} message={message[:100]!r}")
            if t == 'text':
                payload = message.encode('utf-8')
                failed = self.registry.broadcast(1, payload)
            else:
                b = jd.get('binary')
                if isinstance(b, list):
                    payload = bytes(b)
                else:
                    payload = (jd.get('message','')).encode('utf-8')
                failed = self.registry.broadcast(2, payload)
            if failed:
                print(f"[API] broadcast parcial, fallos={failed}")
                payload = json.dumps({'status':'partial','failed': failed}).encode('utf-8')
                send_http_response(self.conn, 500, 'Partial',
                                   {'Content-Type':'application/json; charset=utf-8'},
                                   payload)
            else:
                send_http_response(self.conn, 200, 'OK',
                                   {'Content-Type':'application/json; charset=utf-8'},
                                   json.dumps({'status':'ok'}).encode('utf-8'))
            return True

        if path == '/api/ws/ping':
            if method.upper() != 'POST':
                send_http_response(self.conn, 405, 'Method Not Allowed', {'Allow':'POST'}, b'')
                return True
            try:
                jd = json.loads(body.decode('utf-8') or '{}')
            except Exception:
                jd = {}
            payload = jd.get('payload','').encode('utf-8')
            print(f"[API] /api/ws/ping payload={payload[:80]!r}")
            failed = self.registry.broadcast(9, payload)
            if failed:
                payload = json.dumps({'status':'partial','failed': failed}).encode('utf-8')
                send_http_response(self.conn, 500, 'Partial',
                                   {'Content-Type':'application/json; charset=utf-8'},
                                   payload)
            else:
                payload = json.dumps({'status':'ok'}).encode('utf-8')
                send_http_response(self.conn, 200, 'OK',
                                   {'Content-Type':'application/json; charset=utf-8'},
                                   payload)
            return True

        if path == '/api/ws/close':
            if method.upper() != 'POST':
                send_http_response(self.conn, 405, 'Method Not Allowed', {'Allow':'POST'}, b'')
                return True
            try:
                jd = json.loads(body.decode('utf-8') or '{}')
            except Exception:
                jd = {}
            client_id = jd.get('client_id')
            code = int(jd.get('code', 1000))
            reason = jd.get('reason', '')
            if code < 0:
                code = 1000
            payload = code.to_bytes(2, 'big') + (reason.encode('utf-8') if reason else b'')
            print(f"[API] /api/ws/close client_id={client_id} code={code} reason={reason!r}")
            if client_id:
                ok, msg = self.registry.send_to_client(client_id, 8, payload)
                if ok:
                    send_http_response(self.conn, 200, 'OK',
                                       {'Content-Type':'application/json; charset=utf-8'},
                                       b'{"status":"ok"}')
                else:
                    send_http_response(self.conn, 500, 'Error',
                                       {'Content-Type':'application/json; charset=utf-8'},
                                       json.dumps({'status':'error','msg':msg}).encode('utf-8'))
            else:
                failed = self.registry.broadcast(8, payload)
                if failed:
                    send_http_response(self.conn, 500, 'Partial',
                                       {'Content-Type':'application/json; charset=utf-8'},
                                       json.dumps({'status':'partial','failed':failed}).encode('utf-8'))
                else:
                    send_http_response(self.conn, 200, 'OK',
                                       {'Content-Type':'application/json; charset=utf-8'},
                                       b'{"status":"ok"}')
            return True

        # ----- API ORM: ChatMessage -----
        if path == '/api/chat/messages' and method.upper() == 'GET':
            params = parse_query_string(query)
            try:
                limit = int(params.get('limit', '50'))
            except Exception:
                limit = 50
            if limit <= 0:
                limit = 50
            if limit > 500:
                limit = 500
            msgs = ChatMessage.objects(self.db).order_by("id DESC").limit(limit).all()
            data = [m.to_dict() for m in msgs]
            payload = json.dumps(data).encode('utf-8')
            send_http_response(self.conn, 200, 'OK',
                               {'Content-Type':'application/json; charset=utf-8'},
                               payload)
            return True

        if path == '/api/chat/clear' and method.upper() == 'POST':
            print("[API] /api/chat/clear -> borrando mensajes")
            with self.db.transaction():
                borrados = ChatMessage.objects(self.db).delete()
            payload = json.dumps({'status': 'ok', 'deleted': borrados}).encode('utf-8')
            send_http_response(self.conn, 200, 'OK',
                               {'Content-Type':'application/json; charset=utf-8'},
                               payload)
            return True

        if path == '/' and method.upper() == 'GET':
            print("[API] GET / (INDEX_HTML) desde handle_api")
            send_http_response(self.conn, 200, 'OK',
                               {'Content-Type':'text/html; charset=utf-8'},
                               INDEX_HTML)
            return True

        print(f"[API] 404 Not Found: {path}")
        send_http_response(self.conn, 404, 'Not Found',
                           {'Content-Type':'text/plain; charset=utf-8'},
                           b'Not Found')
        return True

    # ----------------------------
    # WebSocket per-connection handler
    # ----------------------------
    def handle_ws_connection(self, initial_req, client_id):
        headers = initial_req['headers']

        subprotocol = ''
        saw_proto = headers.get('sec-websocket-protocol','')
        if saw_proto:
            offered = [p.strip() for p in saw_proto.split(',') if p.strip()]
            if offered:
                subprotocol = offered[0]

        key = headers.get('sec-websocket-key', '')
        if not key:
            print(f"[WS] Handshake inválido desde {self.addr}, falta Sec-WebSocket-Key")
            send_http_response(self.conn, 400, 'Bad Request',
                               {'Content-Type':'text/plain; charset=utf-8'},
                               b'Missing Sec-WebSocket-Key')
            try:
                self.conn.close()
            except Exception:
                pass
            return

        print(f"[WS] Handshake desde {self.addr} client_id={client_id} subprotocols_ofrecidos={saw_proto!r}")

        accept_src = (key + MAGIC_WS).encode('utf-8')
        digest = sha1(accept_src)
        accept = base64_encode(digest)
        resp_headers = {
            'Upgrade': 'websocket',
            'Connection': 'Upgrade',
            'Sec-WebSocket-Accept': accept
        }
        if subprotocol:
            resp_headers['Sec-WebSocket-Protocol'] = subprotocol

        send_http_response(self.conn, 101, 'Switching Protocols', resp_headers, b'')

        self.registry.register_client(client_id, self.conn, self.addr, threading.current_thread(), subprotocol)

        try:
            welcome = json.dumps({
                "type": "welcome",
                "client_id": client_id,
                "subprotocol": subprotocol
            }).encode('utf-8')
            self.conn.sendall(make_ws_frame_bytes(1, welcome))
            print(f"[WS] Enviado mensaje welcome a {client_id}")
        except Exception as e:
            print(f"[WS] Error enviando welcome a {client_id}: {e}")

        fragmented_msg_opcode = None
        fragmented_parts = []
        try:
            while True:
                fin, opcode, payload, masked, mask = read_ws_frame_raw(self.conn)
                plen = len(payload)
                print(f"[WS RECV] cid={client_id} opcode={opcode} fin={fin} masked={masked} len={plen}")

                if opcode == 0x8:
                    code, reason = parse_close_payload(payload)
                    print(f"[WS CLOSE] cid={client_id} code={code} reason={reason!r}")
                    try:
                        close_payload = payload if payload else b''
                        self.conn.sendall(make_ws_frame_bytes(0x8, close_payload))
                    except Exception as e:
                        print(f"[WS] Error respondiendo CLOSE a {client_id}: {e}")
                    break
                elif opcode == 0x9:
                    print(f"[WS PING] cid={client_id} len={plen}")
                    try:
                        self.conn.sendall(make_ws_frame_bytes(0xA, payload))
                        print(f"[WS PONG] enviado a cid={client_id}")
                    except Exception as e:
                        print(f"[WS] Error enviando PONG a {client_id}: {e}")
                    continue
                elif opcode == 0xA:
                    print(f"[WS PONG RECV] cid={client_id} len={plen}")
                    continue

                if opcode == 0x0:
                    if fragmented_msg_opcode is None:
                        print(f"[WS] CONTINUATION sin inicio previo en cid={client_id}, descartando fragmentos")
                        fragmented_parts = []
                        fragmented_msg_opcode = None
                        continue
                    fragmented_parts.append(payload)
                    if fin:
                        full = b''.join(fragmented_parts)
                        if fragmented_msg_opcode == 1:
                            try:
                                text = full.decode('utf-8', errors='ignore')
                            except Exception:
                                text = ''
                            print(f"[WS TEXT FRAG COMPLETO] cid={client_id} text={text[:120]!r}")
                            self._handle_text_message(client_id, text, fragmented=True)
                        elif fragmented_msg_opcode == 2:
                            print(f"[WS BIN FRAG COMPLETO] cid={client_id} len={len(full)}")
                            prefix = b"BIN ECHO:"
                            self.conn.sendall(make_ws_frame_bytes(2, prefix + full))
                        fragmented_parts = []
                        fragmented_msg_opcode = None
                    else:
                        print(f"[WS] CONTINUATION (parte intermedia) cid={client_id} len_parte={plen}")
                elif opcode == 0x1 or opcode == 0x2:
                    if fin:
                        if opcode == 0x1:
                            text = payload.decode('utf-8', errors='ignore')
                            print(f"[WS TEXT] cid={client_id} text={text[:200]!r}")
                            self._handle_text_message(client_id, text, fragmented=False)
                        else:
                            print(f"[WS BIN] cid={client_id} len={plen}")
                            prefix = b"BIN ECHO:"
                            self.conn.sendall(make_ws_frame_bytes(2, prefix + payload))
                    else:
                        fragmented_msg_opcode = opcode
                        fragmented_parts = [payload]
                        print(f"[WS] Inicio de mensaje fragmentado cid={client_id} opcode={opcode} len={plen}")
                else:
                    print(f"[WS] Opcode reservado/no soportado {opcode} en cid={client_id}, ignorando.")
                    continue
        except ConnectionError:
            print(f"[WS] ConnectionError en cid={client_id}")
        except Exception as e:
            print(f"[WS] Excepción en loop de cid={client_id}: {e}")
        finally:
            self.registry.unregister_client(client_id)
            try:
                self.conn.close()
            except Exception:
                pass

    def _handle_text_message(self, client_id, text, fragmented=False):
        alias, msg = parse_chat_line(text)
        ts = int(time.time())
        if msg.strip():
            try:
                ChatMessage.objects(self.db).create(
                    client_id=client_id,
                    alias=alias or 'anon',
                    message=msg,
                    created_at=ts
                )
                print(f"[CHAT/ORM] Guardado mensaje chat cid={client_id} alias={alias or 'anon'} len={len(msg)}")
            except Exception as e:
                print(f"[CHAT/ORM] Error guardando mensaje: {e}")
        if fragmented:
            reply = "Server echo (frag): " + text
        else:
            reply = "Server echo: " + text
        try:
            self.conn.sendall(make_ws_frame_bytes(1, reply.encode('utf-8')))
        except Exception as e:
            print(f"[WS] Error enviando echo a cid={client_id}: {e}")

# ============================================================
#  Servidor principal
# ============================================================

class WebSocketHTTPServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.registry = ClientRegistry()
        self._sock = None

        # BD en memoria compartida: file::memory:?cache=shared
        self.db = Database(
            path=":memory:",
            shared_cache=True,
            timeout=10.0,
            pragmas={
                "journal_mode": "WAL",
                "synchronous": "NORMAL",
                "foreign_keys": 1,
            },
        )
        # Crear tabla de ejemplo para el chat
        ChatMessage.create_table(self.db)

    def serve_forever(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(128)
        self._sock = s
        print("Servidor escuchando en http://%s:%d/ ..." % (self.host, self.port))
        try:
            while True:
                conn, addr = s.accept()
                print(f"[ACCEPT] Conexión aceptada desde {addr}")
                t = ConnectionThread(conn, addr, self.registry, self.db)
                t.start()
        except KeyboardInterrupt:
            print("\n[shutdown] interrupted by user (Ctrl+C). stopping server...")
        finally:
            s.close()
            print("[shutdown] server socket closed.")

def run_server(host, port):
    srv = WebSocketHTTPServer(host, port)
    srv.serve_forever()

if __name__ == '__main__':
    run_server(HOST, PORT)

# ============================================================
#  EJEMPLOS DE USO (HTTP / API / WS)
# ============================================================
# HTTP:
#   - Abrir en navegador:  http://0.0.0.0:8765/
#
# API (ejemplos con curl):
#   - Listar clientes WS:
#       curl http://0.0.0.0:8765/api/ws/clients
#
#   - Broadcast de texto:
#       curl -X POST http://0.0.0.0:8765/api/ws/broadcast \
#            -H "Content-Type: application/json" \
#            -d '{"type":"text","message":"Hola a todos desde curl"}'
#
#   - Ping a todos:
#       curl -X POST http://0.0.0.0:8765/api/ws/ping \
#            -H "Content-Type: application/json" \
#            -d '{"payload":"ping-desde-api"}'
#
#   - Cerrar todos los clientes:
#       curl -X POST http://0.0.0.0:8765/api/ws/close \
#            -H "Content-Type: application/json" \
#            -d '{"code":1000,"reason":"bye"}'
#
#   - Listar mensajes de chat guardados en SQLite:
#       curl "http://0.0.0.0:8765/api/chat/messages?limit=20"
#
#   - Borrar todos los mensajes de chat:
#       curl -X POST http://0.0.0.0:8765/api/chat/clear
#
# WebSocket (WS):
#   - Desde el HTML:
#       * Conectar con "Conectar WS".
#       * En la parte de chat:
#            - Pon un alias.
#            - Escribe un mensaje y "Enviar".
#         Se manda algo tipo: "[alias] mensaje".
#         El servidor:
#           - lo guarda en la tabla "chat_messages" (ORM SQLite)
#           - responde con "Server echo: [alias] mensaje" al mismo WS.
#
#   - Desde herramientas WS (wscat, websocat, etc.):
#       wscat -c ws://0.0.0.0:8765/ws/
#       > [pepe] hola desde wscat
#       < Server echo: [pepe] hola desde wscat
#     Y el mensaje se almacena en "chat_messages".
