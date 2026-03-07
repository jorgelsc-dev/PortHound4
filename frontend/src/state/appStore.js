import { reactive } from "vue";

const state = reactive({
  apiBase: "",
  wsStatus: "offline",
});

const STORAGE_KEY_API = "porthound.apiBase";
const WS_RECONNECT_DELAY_MS = 1800;
const WS_REFRESH_THROTTLE_MS = 800;
const WS_REFRESH_EVENT_TYPES = new Set([
  "welcome",
  "scan_map_snapshot",
  "scan_map_update",
]);

const tableRefreshSubscribers = new Set();

let wsClient = null;
let wsReconnectTimer = null;
let wsRefreshTimer = null;
let wsPendingRefreshPayload = null;

function suggestApiBaseFromLocation(locationLike = null) {
  const locationRef =
    locationLike ||
    (typeof window !== "undefined" && window.location ? window.location : null);
  if (!locationRef) return "";

  const protocol = String(locationRef.protocol || "http:");
  const hostname = String(locationRef.hostname || "127.0.0.1");
  const port = String(locationRef.port || "");
  const isDevPort = port === "8080" || port === "5173" || port === "3000";
  if (isDevPort) {
    return `${protocol}//${hostname}:45678`;
  }
  return String(locationRef.origin || `${protocol}//${hostname}${port ? `:${port}` : ""}`);
}

function initApiBase() {
  if (typeof window === "undefined") {
    state.apiBase = "";
    return;
  }
  const envBase =
    typeof process !== "undefined" && process.env
      ? process.env.VUE_APP_API_BASE
      : "";
  const storedApiBase = window.localStorage
    ? window.localStorage.getItem(STORAGE_KEY_API)
    : "";
  const base = storedApiBase || envBase || suggestApiBaseFromLocation(window.location) || "";
  state.apiBase = String(base || "").replace(/\/+$/, "");
}

function setApiBase(value) {
  const cleaned = String(value || "").trim().replace(/\/+$/, "");
  state.apiBase = cleaned;
  if (typeof window !== "undefined" && window.localStorage) {
    window.localStorage.setItem(STORAGE_KEY_API, cleaned);
  }
  reconnectRealtime();
}

function apiUrl(path) {
  const base = state.apiBase ? state.apiBase.replace(/\/+$/, "") : "";
  const safePath = path && path.startsWith("/") ? path : `/${path || ""}`;
  return `${base}${safePath}`;
}

function parseJsonSafe(text) {
  try {
    return text ? JSON.parse(text) : null;
  } catch (err) {
    return null;
  }
}

function buildHttpError(res, text, data) {
  const trimmed = (text || "").trim();
  const looksLikeHtml =
    trimmed.startsWith("<!DOCTYPE") ||
    trimmed.startsWith("<html") ||
    trimmed.startsWith("<!doctype");
  const message =
    (data && data.status) ||
    (looksLikeHtml
      ? `HTTP ${res.status} ${res.statusText}`
      : trimmed || `HTTP ${res.status} ${res.statusText}`);
  return new Error(message);
}

function fetchJsonPromise(path, options = {}) {
  const opts = { ...options };
  opts.headers = opts.headers || {};
  if (opts.body && !opts.headers["Content-Type"]) {
    opts.headers["Content-Type"] = "application/json";
  }
  return fetch(apiUrl(path), opts)
    .then((res) =>
      res.text().then((text) => {
        const data = parseJsonSafe(text);
        if (!res.ok) {
          throw buildHttpError(res, text, data);
        }
        return data;
      })
    );
}

function fetchJson(path, options = {}) {
  return fetchJsonPromise(path, options);
}

function extractArray(payload) {
  if (Array.isArray(payload)) return payload;
  if (payload && Array.isArray(payload.datas)) return payload.datas;
  return [];
}

function notifyTableRefresh(payload) {
  if (!tableRefreshSubscribers.size) return;
  tableRefreshSubscribers.forEach((subscriber) => {
    try {
      subscriber(payload);
    } catch (err) {
      // ignore subscriber-level failures
    }
  });
}

function scheduleTableRefresh(payload) {
  wsPendingRefreshPayload = payload;
  if (wsRefreshTimer) return;
  wsRefreshTimer = setTimeout(() => {
    wsRefreshTimer = null;
    const pending = wsPendingRefreshPayload;
    wsPendingRefreshPayload = null;
    notifyTableRefresh(pending);
  }, WS_REFRESH_THROTTLE_MS);
}

function wsUrl() {
  let base = state.apiBase;
  if (!base && typeof window !== "undefined") {
    base = window.location.origin;
  }
  try {
    const parsed = new URL(base);
    const protocol = parsed.protocol === "https:" ? "wss:" : "ws:";
    return `${protocol}//${parsed.host}/ws/`;
  } catch (err) {
    if (typeof window !== "undefined") {
      const protocol = window.location.protocol === "https:" ? "wss" : "ws";
      return `${protocol}://${window.location.host}/ws/`;
    }
  }
  return "ws://127.0.0.1:45678/ws/";
}

function clearReconnectTimer() {
  if (!wsReconnectTimer) return;
  clearTimeout(wsReconnectTimer);
  wsReconnectTimer = null;
}

function scheduleReconnect() {
  if (typeof window === "undefined") return;
  if (wsReconnectTimer) return;
  clearReconnectTimer();
  state.wsStatus = "offline";
  wsReconnectTimer = setTimeout(() => {
    wsReconnectTimer = null;
    connectRealtime();
  }, WS_RECONNECT_DELAY_MS);
}

function destroyRealtime() {
  clearReconnectTimer();
  if (wsRefreshTimer) {
    clearTimeout(wsRefreshTimer);
    wsRefreshTimer = null;
  }
  wsPendingRefreshPayload = null;
  if (!wsClient) {
    state.wsStatus = "offline";
    return;
  }
  const socket = wsClient;
  wsClient = null;
  try {
    socket.close();
  } catch (err) {
    // ignore close failures
  } finally {
    state.wsStatus = "offline";
  }
}

function reconnectRealtime() {
  if (typeof window === "undefined") return;
  destroyRealtime();
  connectRealtime();
}

function connectRealtime() {
  if (typeof window === "undefined" || typeof window.WebSocket === "undefined") {
    state.wsStatus = "offline";
    return;
  }
  if (
    wsClient &&
    (wsClient.readyState === window.WebSocket.OPEN ||
      wsClient.readyState === window.WebSocket.CONNECTING)
  ) {
    return;
  }

  let socket = null;
  try {
    socket = new window.WebSocket(wsUrl());
  } catch (err) {
    state.wsStatus = "error";
    scheduleReconnect();
    return;
  }

  wsClient = socket;
  state.wsStatus = "connecting";

  socket.addEventListener("open", () => {
    if (wsClient !== socket) return;
    clearReconnectTimer();
    state.wsStatus = "online";
    try {
      socket.send(JSON.stringify({ action: "scan_map_snapshot", limit: 300 }));
    } catch (err) {
      state.wsStatus = "error";
    }
  });

  socket.addEventListener("message", (event) => {
    if (wsClient !== socket) return;
    const payload = parseJsonSafe(event.data);
    if (!payload || typeof payload !== "object") return;
    const type = String(payload.type || "").trim().toLowerCase();
    if (!WS_REFRESH_EVENT_TYPES.has(type)) return;
    scheduleTableRefresh({
      type,
      payload,
      receivedAt: Date.now(),
    });
  });

  socket.addEventListener("error", () => {
    if (wsClient !== socket) return;
    state.wsStatus = "error";
  });

  socket.addEventListener("close", () => {
    if (wsClient !== socket) return;
    wsClient = null;
    state.wsStatus = "offline";
    scheduleReconnect();
  });
}

function initRealtime() {
  connectRealtime();
}

function subscribeTableRefresh(handler) {
  if (typeof handler !== "function") {
    return () => {};
  }
  tableRefreshSubscribers.add(handler);
  return () => {
    tableRefreshSubscribers.delete(handler);
  };
}

export default {
  state,
  suggestApiBaseFromLocation,
  initApiBase,
  initRealtime,
  setApiBase,
  apiUrl,
  fetchJsonPromise,
  fetchJson,
  extractArray,
  reconnectRealtime,
  destroyRealtime,
  subscribeTableRefresh,
};
