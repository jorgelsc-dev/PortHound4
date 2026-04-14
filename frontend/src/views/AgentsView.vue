<template>
  <div>
    <ViewHeader
      overline="Cluster"
      title="Agents"
      description="Monitor status y controla agentes activos del cluster."
      :refresh-loading="loading"
      @refresh="load"
    />

    <v-row dense class="mb-4">
      <v-col v-for="metric in metricCards" :key="metric.key" cols="12" sm="6" lg="3">
        <v-card variant="tonal" class="pa-4 metric-card">
          <div class="d-flex align-center justify-space-between ga-3">
            <div>
              <div class="text-caption text-medium-emphasis">{{ metric.label }}</div>
              <div class="text-h5 font-weight-bold" :class="metric.colorClass">
                {{ metric.value }}
              </div>
            </div>
            <v-icon :icon="metric.icon" :class="metric.colorClass" />
          </div>
        </v-card>
      </v-col>
    </v-row>

    <v-card class="mb-4 pa-4 onboarding-card" variant="outlined">
      <div class="d-flex flex-wrap align-center justify-space-between ga-3 mb-3">
        <div>
          <div class="text-overline text-medium-emphasis">Agent Onboarding</div>
          <div class="text-subtitle-1 font-weight-bold">Agregar agente</div>
          <div class="text-body-2 text-medium-emphasis">
            Genera credenciales y copia solo los datos necesarios del agente.
          </div>
        </div>
        <div class="d-flex align-center ga-2">
          <v-btn
            color="primary"
            variant="flat"
            :loading="creatingCredential"
            @click="createAgentCredential"
          >
            Agregar agente
          </v-btn>
          <v-btn
            v-if="onboardingCommandBase64"
            color="secondary"
            variant="tonal"
            @click="copyText(onboardingCommandBase64)"
          >
            Copiar comando base64
          </v-btn>
        </div>
      </div>

      <v-row dense>
        <v-col cols="12" md="8">
          <v-text-field
            v-model.trim="newAgentId"
            label="agent_id (opcional)"
            placeholder="edge-agent-01"
            prepend-inner-icon="mdi-identifier"
            :disabled="creatingCredential"
            variant="outlined"
            density="comfortable"
            hide-details
          />
        </v-col>
        <v-col cols="12" md="4">
          <v-chip color="info" variant="tonal" size="small">
            Comunicacion: `agent_id + token` (HTTP)
          </v-chip>
        </v-col>
      </v-row>

      <v-alert
        v-if="credentialError"
        type="error"
        variant="tonal"
        density="comfortable"
        class="mt-3"
      >
        {{ credentialError }}
      </v-alert>

      <v-alert
        v-if="actionError"
        type="error"
        variant="tonal"
        density="comfortable"
        class="mt-3"
      >
        {{ actionError }}
      </v-alert>

      <v-alert
        v-if="onboardingRows.length"
        type="info"
        variant="tonal"
        density="comfortable"
        class="mt-3"
      >
        Guia rapida:
        1) Copia el `ENROLL BASE64`.
        2) En el agente ejecuta `env/bin/python manage.py &lt;base64&gt;`.
        3) Si prefieres, copia el comando completo con base64.
      </v-alert>

      <div
        v-if="onboardingRows.length"
        class="onboarding-copy-list mt-3"
      >
        <div
          v-for="row in onboardingRows"
          :key="row.key"
          class="onboarding-copy-row"
        >
          <div class="onboarding-copy-row__label">
            {{ row.label }}
          </div>
          <code class="onboarding-copy-row__value">{{ row.value }}</code>
          <v-btn
            icon
            size="small"
            variant="text"
            color="primary"
            :title="`Copiar ${row.label}`"
            @click="copyText(row.value)"
          >
            <v-icon icon="mdi-content-copy" />
          </v-btn>
        </div>
      </div>
    </v-card>

    <v-row dense class="mb-3">
      <v-col cols="12" md="8">
        <v-text-field
          v-model.trim="tableFilters.query"
          label="Search agents"
          placeholder="agent id, ip, network, task..."
          prepend-inner-icon="mdi-magnify"
          :loading="loading"
          clearable
          variant="outlined"
          density="comfortable"
        />
      </v-col>
      <v-col cols="12" md="4">
        <v-select
          v-model="tableFilters.status"
          :items="statusFilterOptions"
          label="Status"
          item-title="label"
          item-value="value"
          :loading="loading"
          clearable
          variant="outlined"
          density="comfortable"
        />
      </v-col>
    </v-row>

    <EntityTablePanel
      title="Cluster Agents"
      subtitle="Estado en vivo y acciones de control por agente."
      :rows="filteredRows"
      :columns="columns"
      :loading="loading"
      :error="error"
      :last-updated="lastUpdatedLabel"
      :live-refresh="true"
      empty-text="No agents registered"
      @refresh="load"
    >
      <template #cell-status="{ value }">
        <v-chip size="small" :color="statusColor(value)" variant="tonal">
          {{ normalizeStatus(value) }}
        </v-chip>
      </template>

      <template #cell-last_seen="{ item }">
        <div class="d-flex flex-column">
          <span>{{ item.last_seen_iso || "-" }}</span>
          <span class="text-caption text-medium-emphasis">
            {{ formatAge(item.seconds_since_seen) }}
          </span>
        </div>
      </template>

      <template #cell-client="{ value }">
        <span>{{ formatClient(value) }}</span>
      </template>

      <template #cell-actions="{ item }">
        <div class="d-flex align-center ga-1">
          <v-btn
            icon
            size="small"
            color="warning"
            variant="text"
            :title="`Detener ${item.agent_id}`"
            :loading="isAgentActionLoading(item.agent_id, 'stop')"
            @click="controlAgent(item, 'stop')"
          >
            <v-icon icon="mdi-stop-circle-outline" />
          </v-btn>
          <v-btn
            icon
            size="small"
            color="error"
            variant="text"
            :title="`Eliminar ${item.agent_id}`"
            :loading="isAgentActionLoading(item.agent_id, 'delete')"
            @click="controlAgent(item, 'delete')"
          >
            <v-icon icon="mdi-delete-outline" />
          </v-btn>
        </div>
      </template>

      <template #cell-active_tasks="{ value }">
        <div v-if="Array.isArray(value) && value.length" class="agent-task-list">
          <div
            v-for="task in value"
            :key="taskKey(task)"
            class="agent-task-item"
          >
            <v-chip size="x-small" variant="tonal" color="info">
              {{ String(task.proto || "?").toUpperCase() }}
            </v-chip>
            <span class="agent-task-item__text">
              {{ task.network || "unknown-network" }}
            </span>
            <span class="text-caption text-medium-emphasis">
              {{ Number(task.lease_seconds_left || 0) }}s
            </span>
          </div>
        </div>
        <span v-else class="text-medium-emphasis">-</span>
      </template>
    </EntityTablePanel>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";

const POLL_MS = 4000;

export default {
  name: "AgentsView",
  components: {
    ViewHeader,
    EntityTablePanel,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      generatedAt: "",
      summary: {
        total_agents: 0,
        online: 0,
        stale: 0,
        offline: 0,
        active_tasks: 0,
      },
      rows: [],
      columns: [
        { key: "agent_id", label: "Agent ID" },
        { key: "status", label: "Status" },
        { key: "last_seen", label: "Last Seen" },
        { key: "client", label: "Client" },
        { key: "auth_mode", label: "Auth" },
        { key: "active_task_count", label: "Tasks" },
        { key: "active_tasks", label: "Active Task Detail" },
        { key: "actions", label: "Actions" },
      ],
      tableFilters: {
        query: "",
        status: "",
      },
      creatingCredential: false,
      credentialError: "",
      actionError: "",
      newAgentId: "",
      onboardingData: null,
      agentActionLoading: {},
      pollTimer: null,
    };
  },
  computed: {
    apiBase() {
      return this.store.state.apiBase;
    },
    metricCards() {
      return [
        {
          key: "total",
          label: "Total Agents",
          value: Number(this.summary.total_agents || 0),
          icon: "mdi-server-network",
          colorClass: "text-primary",
        },
        {
          key: "online",
          label: "Online",
          value: Number(this.summary.online || 0),
          icon: "mdi-lan-connect",
          colorClass: "text-success",
        },
        {
          key: "stale",
          label: "Stale",
          value: Number(this.summary.stale || 0),
          icon: "mdi-lan-pending",
          colorClass: "text-warning",
        },
        {
          key: "offline",
          label: "Offline",
          value: Number(this.summary.offline || 0),
          icon: "mdi-lan-disconnect",
          colorClass: "text-error",
        },
        {
          key: "tasks",
          label: "Active Tasks",
          value: Number(this.summary.active_tasks || 0),
          icon: "mdi-timer-sand",
          colorClass: "text-info",
        },
      ];
    },
    lastUpdatedLabel() {
      if (this.generatedAt) {
        return `${this.lastUpdated} | snapshot ${this.generatedAt}`;
      }
      return this.lastUpdated;
    },
    statusFilterOptions() {
      const statuses = [...new Set(
        this.rows.map((item) => this.normalizeStatus(item && item.status))
      )]
        .filter(Boolean)
        .sort();
      return [
        { label: "All", value: "" },
        ...statuses.map((status) => ({ label: status, value: status })),
      ];
    },
    filteredRows() {
      const query = String(this.tableFilters.query || "").trim().toLowerCase();
      const status = this.normalizeStatus(this.tableFilters.status);
      return this.rows.filter((item) => {
        if (status && this.normalizeStatus(item.status) !== status) {
          return false;
        }
        if (!query) {
          return true;
        }
        const taskTokens = Array.isArray(item.active_tasks)
          ? item.active_tasks
            .map((task) => [
              task.task_id,
              task.network,
              task.proto,
              task.master_target_id,
              task.lease_seconds_left,
            ].join(" "))
            .join(" ")
          : "";

        const haystack = [
          item.agent_id,
          item.status,
          item.last_seen_iso,
          item.seconds_since_seen,
          item.auth_mode,
          item.active_task_count,
          this.formatClient(item.client),
          taskTokens,
        ]
          .map((value) => String(value == null ? "" : value).toLowerCase())
          .join(" ");
        return haystack.includes(query);
      });
    },
    onboardingRows() {
      const data = this.onboardingData || {};
      const rows = [
        { key: "agent_id", label: "agent_id", value: String(data.agent_id || "").trim() },
        { key: "token", label: "token", value: String(data.token || "").trim() },
        { key: "enroll_base64", label: "enroll_base64", value: String(data.enroll_base64 || "").trim() },
        { key: "enroll_command", label: "comando_base64", value: String(data.enroll_command || "").trim() },
        { key: "master_ip", label: "master_ip", value: String(data.master_ip || "").trim() },
        { key: "master_host", label: "master_host", value: String(data.master_host || "").trim() },
      ];
      return rows.filter((row) => row.value);
    },
    onboardingCommandBase64() {
      const data = this.onboardingData || {};
      return String(data.enroll_command || "").trim();
    },
  },
  watch: {
    apiBase() {
      this.load();
    },
  },
  mounted() {
    this.load();
    this.startPolling();
  },
  beforeUnmount() {
    this.stopPolling();
  },
  methods: {
    async copyText(value) {
      const text = String(value || "").trim();
      if (!text) return;
      if (typeof navigator === "undefined" || !navigator.clipboard) return;
      try {
        await navigator.clipboard.writeText(text);
      } catch (err) {
        // ignore clipboard errors
      }
    },
    buildAgentOnboardingData(credential) {
      const data = credential && typeof credential === "object" ? credential : {};
      const agentId = String(data.agent_id || "").trim();
      const token = String(data.token || data.agent_key || "").trim();
      const masterBase = this.buildSuggestedMasterBase();
      const master = this.buildSuggestedMasterAddress(masterBase);
      const payload = this.buildAgentEnrollPayload({
        agent_id: agentId,
        token,
        master: masterBase,
        master_host: master.host,
        master_ip: master.ip,
      });
      const enrollBase64 = this.encodeBase64Unicode(JSON.stringify(payload));
      const enrollCommand = enrollBase64
        ? `env/bin/python manage.py '${enrollBase64}'`
        : "";
      return {
        agent_id: agentId,
        token,
        master_ip: master.ip,
        master_host: master.host,
        master: masterBase,
        enroll_base64: enrollBase64,
        enroll_command: enrollCommand,
      };
    },
    buildSuggestedMasterAddress(masterBase) {
      let hostFromBase = "";
      if (masterBase) {
        try {
          hostFromBase = String(new URL(masterBase).hostname || "").trim().toLowerCase();
        } catch (err) {
          hostFromBase = "";
        }
      }
      const rawHost = typeof window !== "undefined"
        ? String(hostFromBase || window.location.hostname || "").trim().toLowerCase()
        : "";
      let safeHost = rawHost;
      if (!safeHost || safeHost === "0.0.0.0" || safeHost === "::") {
        safeHost = "127.0.0.1";
      }
      return {
        host: safeHost,
        ip: this.isIPv4(safeHost) ? safeHost : "",
      };
    },
    buildSuggestedMasterBase() {
      const rawHost = typeof window !== "undefined"
        ? String(window.location.hostname || "").trim().toLowerCase()
        : "";
      let safeHost = rawHost;
      if (!safeHost || safeHost === "0.0.0.0" || safeHost === "::") {
        safeHost = "127.0.0.1";
      }
      const port = typeof window !== "undefined"
        ? String(window.location.port || "").trim()
        : "";
      const hostPort = port ? `${safeHost}:${port}` : safeHost;
      return `http://${hostPort}`;
    },
    isIPv4(value) {
      return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(String(value || "").trim());
    },
    encodeBase64Unicode(text) {
      if (typeof TextEncoder === "undefined" || typeof btoa === "undefined") {
        return "";
      }
      const encoder = new TextEncoder();
      const bytes = encoder.encode(String(text || ""));
      let binary = "";
      bytes.forEach((b) => {
        binary += String.fromCharCode(b);
      });
      return btoa(binary);
    },
    buildAgentEnrollPayload(payload) {
      const data = payload && typeof payload === "object" ? payload : {};
      return {
        version: 1,
        master: String(data.master || "").trim(),
        master_host: String(data.master_host || "").trim(),
        master_ip: String(data.master_ip || "").trim(),
        agent_id: String(data.agent_id || "").trim(),
        agent_token: String(data.token || "").trim(),
        agent_poll_seconds: 8,
        agent_http_timeout: 20,
        agent_tls_check_hostname: 0,
      };
    },
    createAgentCredential() {
      this.creatingCredential = true;
      this.credentialError = "";
      this.actionError = "";
      const agentId = String(this.newAgentId || "").trim();
      const body = agentId ? { agent_id: agentId } : {};
      return this.store
        .fetchJsonPromise("/api/cluster/agent/credentials", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        })
        .then((payload) => {
          const credential = payload && payload.credential ? payload.credential : {};
          this.onboardingData = this.buildAgentOnboardingData(credential);
          return this.load();
        })
        .catch((err) => {
          this.credentialError =
            err && err.message ? err.message : "Failed creating agent credential";
        })
        .finally(() => {
          this.creatingCredential = false;
        });
    },
    isAgentActionLoading(agentId, action) {
      const key = `${String(agentId || "").trim()}:${String(action || "").trim().toLowerCase()}`;
      return Boolean(this.agentActionLoading[key]);
    },
    setAgentActionLoading(agentId, action, value) {
      const key = `${String(agentId || "").trim()}:${String(action || "").trim().toLowerCase()}`;
      this.agentActionLoading = {
        ...this.agentActionLoading,
        [key]: Boolean(value),
      };
    },
    controlAgent(item, action) {
      const agentId = String((item && item.agent_id) || "").trim();
      const normalizedAction = String(action || "").trim().toLowerCase();
      if (!agentId || !["stop", "delete"].includes(normalizedAction)) return Promise.resolve();

      const message = normalizedAction === "stop"
        ? `Detener agente ${agentId}? Esto revoca el token activo.`
        : `Eliminar agente ${agentId}? Esto revoca token, libera tareas y lo quita de la vista.`;
      if (typeof window !== "undefined" && typeof window.confirm === "function") {
        if (!window.confirm(message)) {
          return Promise.resolve();
        }
      }

      this.actionError = "";
      this.setAgentActionLoading(agentId, normalizedAction, true);
      return this.store
        .fetchJsonPromise("/api/cluster/agent/control", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            agent_id: agentId,
            action: normalizedAction,
          }),
        })
        .then(() => this.load())
        .catch((err) => {
          this.actionError = err && err.message
            ? err.message
            : `No se pudo ${normalizedAction === "stop" ? "detener" : "eliminar"} el agente`;
        })
        .finally(() => {
          this.setAgentActionLoading(agentId, normalizedAction, false);
        });
    },
    normalizeStatus(value) {
      const raw = String(value || "").trim().toLowerCase();
      if (raw === "online" || raw === "stale" || raw === "offline") {
        return raw;
      }
      return "";
    },
    statusColor(value) {
      const status = this.normalizeStatus(value);
      if (status === "online") return "success";
      if (status === "stale") return "warning";
      if (status === "offline") return "error";
      return "secondary";
    },
    formatClient(value) {
      if (Array.isArray(value)) {
        return value.filter((item) => item !== null && item !== undefined).join(":") || "-";
      }
      if (value && typeof value === "object") {
        try {
          return JSON.stringify(value);
        } catch (err) {
          return "-";
        }
      }
      const text = String(value || "").trim();
      return text || "-";
    },
    formatAge(value) {
      const seconds = Number(value);
      if (!Number.isFinite(seconds) || seconds < 0) {
        return "-";
      }
      return `${Math.round(seconds)}s ago`;
    },
    taskKey(task) {
      const tid = String((task && task.task_id) || "").trim();
      const targetId = String((task && task.master_target_id) || "").trim();
      const proto = String((task && task.proto) || "").trim();
      return `${tid}-${targetId}-${proto}`;
    },
    startPolling() {
      if (this.pollTimer) return;
      this.pollTimer = setInterval(() => {
        if (!this.loading) {
          this.load();
        }
      }, POLL_MS);
    },
    stopPolling() {
      if (!this.pollTimer) return;
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    },
    load() {
      this.loading = true;
      this.error = "";
      return this.store
        .fetchJsonPromise("/api/cluster/agents")
        .then((payload) => {
          this.summary = payload && payload.summary ? payload.summary : {
            total_agents: 0,
            online: 0,
            stale: 0,
            offline: 0,
            active_tasks: 0,
          };
          this.rows = this.store.extractArray(payload);
          this.generatedAt = String((payload && payload.generated_at) || "").trim();
          this.lastUpdated = new Date().toLocaleTimeString();
        })
        .catch((err) => {
          this.error = err && err.message ? err.message : "Failed to load cluster agents";
          this.rows = [];
          this.summary = {
            total_agents: 0,
            online: 0,
            stale: 0,
            offline: 0,
            active_tasks: 0,
          };
          this.generatedAt = "";
          this.lastUpdated = "";
        })
        .finally(() => {
          this.loading = false;
        });
    },
  },
};
</script>

<style scoped>
.metric-card {
  border-radius: 14px;
}

.onboarding-copy-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.onboarding-copy-row {
  display: grid;
  grid-template-columns: minmax(110px, auto) 1fr auto;
  gap: 10px;
  align-items: center;
  border: 1px solid rgba(99, 173, 219, 0.2);
  border-radius: 10px;
  padding: 10px 12px;
}

.onboarding-copy-row__label {
  font-size: 0.82rem;
  color: rgba(180, 202, 223, 0.84);
  text-transform: lowercase;
}

.onboarding-copy-row__value {
  overflow-wrap: anywhere;
  white-space: pre-wrap;
}

.agent-task-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
  min-width: 220px;
}

.agent-task-item {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.agent-task-item__text {
  overflow-wrap: anywhere;
}
</style>
