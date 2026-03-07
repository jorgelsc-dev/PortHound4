<template>
  <div>
    <ViewHeader
      overline="Cluster"
      title="Agents"
      description="Monitor status, heartbeat, certificate CN, and active task leases."
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

    <v-row dense class="mb-3">
      <v-col cols="12" md="8">
        <v-text-field
          v-model.trim="tableFilters.query"
          label="Search agents"
          placeholder="agent id, cn, ip, network, task..."
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
      subtitle="Live visibility for connected agents and current leased tasks."
      :rows="filteredRows"
      :columns="columns"
      :loading="loading"
      :error="error"
      :last-updated="lastUpdatedLabel"
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
        { key: "certificate_cn", label: "Certificate CN" },
        { key: "active_task_count", label: "Tasks" },
        { key: "active_tasks", label: "Active Task Detail" },
      ],
      tableFilters: {
        query: "",
        status: "",
      },
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
          item.certificate_cn,
          item.active_task_count,
          this.formatClient(item.client),
          taskTokens,
        ]
          .map((value) => String(value == null ? "" : value).toLowerCase())
          .join(" ");
        return haystack.includes(query);
      });
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
