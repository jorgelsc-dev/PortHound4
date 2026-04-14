<template>
  <div>
    <ViewHeader
      overline="Targets"
      title="Target Control"
      description="Define CIDR ranges and control each target execution."
      :refresh-loading="loading"
      @refresh="load"
    />

    <DataPanel
      title="Create Target"
      subtitle="Add a network scope for any protocol enabled by the backend."
      :loading="creating"
      :error="createError"
      :show-refresh="false"
      class="mb-6"
    >
      <v-form @submit.prevent="createTarget">
        <v-row dense>
          <v-col cols="12" md="4">
            <v-text-field
              v-model="form.network"
              label="CIDR network"
              placeholder="10.0.0.0/24"
              :loading="creating"
              :disabled="creating || loading"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="2">
            <v-select
              v-model="form.proto"
              :items="protos"
              label="Proto"
              :loading="creating"
              :disabled="creating || loading"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="2">
            <v-select
              v-model="form.port_mode"
              :items="portModes"
              label="Port mode"
              item-title="label"
              item-value="value"
              :loading="creating"
              :disabled="creating || loading"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="2">
            <v-select
              v-model="form.type"
              :items="types"
              label="Preset type"
              :loading="creating"
              :disabled="creating || loading || form.port_mode !== 'preset'"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="2">
            <v-text-field
              v-model.number="form.timesleep"
              label="Timesleep"
              type="number"
              step="0.1"
              min="0"
              :loading="creating"
              :disabled="creating || loading"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
        </v-row>
        <v-row dense>
          <v-col v-if="form.port_mode === 'single'" cols="12" md="2">
            <v-text-field
              v-model.number="form.port_single"
              label="Port"
              type="number"
              min="1"
              max="65535"
              :loading="creating"
              :disabled="creating || loading"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col v-if="form.port_mode === 'range'" cols="12" md="2">
            <v-text-field
              v-model.number="form.port_start"
              label="Port start"
              type="number"
              min="1"
              max="65535"
              :loading="creating"
              :disabled="creating || loading"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col v-if="form.port_mode === 'range'" cols="12" md="2">
            <v-text-field
              v-model.number="form.port_end"
              label="Port end"
              type="number"
              min="1"
              max="65535"
              :loading="creating"
              :disabled="creating || loading"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="4">
            <v-select
              v-model="form.agent_route"
              :items="agentRouteOptions"
              label="Scan Agent"
              item-title="label"
              item-value="value"
              :loading="creating || loading"
              :disabled="creating || loading"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="2" class="d-flex align-center">
            <v-btn
              color="primary"
              variant="flat"
              type="submit"
              :loading="creating"
            >
              Add
            </v-btn>
          </v-col>
        </v-row>
      </v-form>
    </DataPanel>

    <v-row dense class="mb-4">
      <v-col cols="12" md="5">
        <v-text-field
          v-model.trim="tableFilters.query"
          label="Search targets"
          placeholder="IP, network, protocol, port..."
          prepend-inner-icon="mdi-magnify"
          :loading="loading"
          clearable
          variant="outlined"
          density="comfortable"
        />
      </v-col>
      <v-col cols="12" md="2">
        <v-select
          v-model="tableFilters.proto"
          :items="targetProtoFilterOptions"
          label="Proto"
          item-title="label"
          item-value="value"
          :loading="loading"
          clearable
          variant="outlined"
          density="comfortable"
        />
      </v-col>
      <v-col cols="12" md="2">
        <v-select
          v-model="tableFilters.status"
          :items="targetStatusFilterOptions"
          label="Status"
          item-title="label"
          item-value="value"
          :loading="loading"
          clearable
          variant="outlined"
          density="comfortable"
        />
      </v-col>
      <v-col cols="12" md="3">
        <v-select
          v-model="tableFilters.portMode"
          :items="targetPortModeFilterOptions"
          label="Port mode"
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
      title="Active Targets"
      subtitle="Manage each target with start/restart/stop/delete controls."
      :rows="filteredTargets"
      :columns="columns"
      :loading="loading"
      :error="error"
      :last-updated="lastUpdated"
      :live-refresh="true"
      empty-text="No targets registered"
      @refresh="load"
    >
      <template #cell-progress="{ value }">
        <ProgressCell :value="value" />
      </template>

      <template #cell-port_scope="{ item }">
        <span>{{ formatPortScope(item) }}</span>
      </template>

      <template #cell-status="{ value }">
        <v-chip size="small" :color="statusColor(value)" variant="tonal">
          {{ normalizeStatus(value) }}
        </v-chip>
      </template>

      <template #cell-agent_route="{ item }">
        <span>{{ formatTargetAgentRoute(item) }}</span>
      </template>

      <template #cell-actions="{ item }">
        <div class="target-actions">
          <v-btn
            size="x-small"
            color="success"
            variant="tonal"
            :loading="isActionLoading(item.id, 'start')"
            :disabled="loading || creating || normalizeStatus(item.status) === 'active'"
            @click="runTargetAction(item, 'start')"
          >
            Start
          </v-btn>
          <v-btn
            size="x-small"
            color="info"
            variant="tonal"
            :loading="isActionLoading(item.id, 'restart')"
            :disabled="loading || creating"
            @click="runTargetAction(item, 'restart')"
          >
            Restart
          </v-btn>
          <v-btn
            size="x-small"
            color="warning"
            variant="tonal"
            :loading="isActionLoading(item.id, 'stop')"
            :disabled="loading || creating || normalizeStatus(item.status) === 'stopped'"
            @click="runTargetAction(item, 'stop')"
          >
            Stop
          </v-btn>
          <v-btn
            size="x-small"
            color="error"
            variant="tonal"
            :loading="isActionLoading(item.id, 'delete')"
            :disabled="loading || creating"
            @click="runTargetAction(item, 'delete')"
          >
            Delete
          </v-btn>
        </div>
      </template>
    </EntityTablePanel>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import DataPanel from "../components/ui/DataPanel.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";
import ProgressCell from "../components/ui/ProgressCell.vue";

export default {
  name: "TargetsView",
  components: {
    ViewHeader,
    DataPanel,
    EntityTablePanel,
    ProgressCell,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      createError: "",
      creating: false,
      lastUpdated: "",
      targets: [],
      columns: [
        { key: "id", label: "ID" },
        { key: "network", label: "Network" },
        { key: "type", label: "Type" },
        { key: "proto", label: "Proto" },
        { key: "port_scope", label: "Port Scope" },
        { key: "agent_route", label: "Agent Route" },
        { key: "status", label: "Status" },
        { key: "progress", label: "Progress" },
        { key: "timesleep", label: "Timesleep" },
        { key: "actions", label: "Actions" },
      ],
      types: ["common", "not_common", "full"],
      portModes: [
        { label: "Preset", value: "preset" },
        { label: "Single", value: "single" },
        { label: "Range", value: "range" },
      ],
      protos: [],
      clusterAgentIds: [],
      form: {
        network: "",
        type: "common",
        proto: "tcp",
        port_mode: "preset",
        port_single: 80,
        port_start: 1,
        port_end: 1024,
        timesleep: 0.5,
        agent_route: "random",
      },
      actionLoading: {
        id: null,
        action: "",
      },
      tableFilters: {
        query: "",
        proto: "",
        status: "",
        portMode: "",
      },
      wsRefreshTimer: null,
      stopTableRefreshSubscription: null,
    };
  },
  computed: {
    apiBase() {
      return this.store.state.apiBase;
    },
    targetProtoFilterOptions() {
      const values = [...new Set(this.targets.map((item) => String(item.proto || "").trim().toLowerCase()))]
        .filter(Boolean)
        .sort();
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value.toUpperCase(), value }))];
    },
    targetStatusFilterOptions() {
      const values = [...new Set(this.targets.map((item) => this.normalizeStatus(item.status)))]
        .filter(Boolean)
        .sort();
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value, value }))];
    },
    targetPortModeFilterOptions() {
      const values = [...new Set(this.targets.map((item) => this.normalizePortMode(item.port_mode)))]
        .filter(Boolean)
        .sort();
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value, value }))];
    },
    agentRouteOptions() {
      const options = [
        { label: "Random", value: "random" },
        { label: "Local", value: "local" },
      ];
      const ids = [...new Set((this.clusterAgentIds || []).map((item) => String(item || "").trim()))]
        .filter((item) => item && item.toLowerCase() !== "local")
        .sort((a, b) => a.localeCompare(b));
      ids.forEach((agentId) => {
        options.push({
          label: `Agent: ${agentId}`,
          value: `agent:${agentId}`,
        });
      });
      const selected = String(this.form.agent_route || "").trim();
      if (selected.startsWith("agent:") && !options.some((item) => item.value === selected)) {
        const selectedId = selected.slice("agent:".length).trim();
        if (selectedId) {
          options.push({
            label: `Agent: ${selectedId} (manual)`,
            value: `agent:${selectedId}`,
          });
        }
      }
      return options;
    },
    filteredTargets() {
      const query = String(this.tableFilters.query || "").trim().toLowerCase();
      const proto = String(this.tableFilters.proto || "").trim().toLowerCase();
      const status = String(this.tableFilters.status || "").trim().toLowerCase();
      const portMode = String(this.tableFilters.portMode || "").trim().toLowerCase();
      return this.targets.filter((item) => {
        if (proto && String(item.proto || "").trim().toLowerCase() !== proto) return false;
        if (status && this.normalizeStatus(item.status) !== status) return false;
        if (portMode && this.normalizePortMode(item.port_mode) !== portMode) return false;
        if (!query) return true;
        const haystack = [
          item.id,
          item.network,
          item.type,
          item.proto,
          item.status,
          item.port_mode,
          item.agent_mode,
          item.agent_id,
          item.port_start,
          item.port_end,
          item.timesleep,
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
    this.stopTableRefreshSubscription = this.store.subscribeTableRefresh(
      this.handleWsRefresh
    );
  },
  beforeUnmount() {
    if (this.wsRefreshTimer) {
      clearTimeout(this.wsRefreshTimer);
      this.wsRefreshTimer = null;
    }
    if (typeof this.stopTableRefreshSubscription === "function") {
      this.stopTableRefreshSubscription();
      this.stopTableRefreshSubscription = null;
    }
  },
  methods: {
    normalizeStatus(value) {
      const raw = String(value || "active").trim().toLowerCase();
      if (raw === "restarting") return "restarting";
      if (raw === "stopped") return "stopped";
      return "active";
    },
    statusColor(value) {
      const status = this.normalizeStatus(value);
      if (status === "active") return "success";
      if (status === "restarting") return "info";
      return "warning";
    },
    normalizePortMode(value) {
      const mode = String(value || "preset").trim().toLowerCase();
      if (mode === "single") return "single";
      if (mode === "range") return "range";
      return "preset";
    },
    normalizeTargetAgentMode(value) {
      const mode = String(value || "").trim().toLowerCase();
      if (mode === "local") return "local";
      if (mode === "agent") return "agent";
      return "random";
    },
    formatTargetAgentRoute(item) {
      const row = item || {};
      const mode = this.normalizeTargetAgentMode(row.agent_mode);
      if (mode === "local") return "local";
      if (mode === "agent") {
        const agentId = String(row.agent_id || "").trim();
        return agentId ? `agent:${agentId}` : "agent:(missing)";
      }
      return "random";
    },
    formatPortScope(item) {
      const mode = this.normalizePortMode(item && item.port_mode);
      const start = Number(item && item.port_start);
      const end = Number(item && item.port_end);
      if (mode === "single" && Number.isFinite(start) && start > 0) {
        return `single:${start}`;
      }
      if (
        mode === "range" &&
        Number.isFinite(start) &&
        Number.isFinite(end) &&
        start > 0 &&
        end > 0
      ) {
        return `range:${start}-${end}`;
      }
      return String(item && item.type ? item.type : "preset");
    },
    parsePort(value, label) {
      const port = Number(value);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error(`${label} must be between 1 and 65535`);
      }
      return port;
    },
    buildCreatePayload() {
      const mode = this.normalizePortMode(this.form.port_mode);
      const payload = {
        network: this.form.network,
        type: this.form.type,
        proto: this.form.proto,
        timesleep: this.form.timesleep,
        port_mode: mode,
      };
      if (mode === "single") {
        const port = this.parsePort(this.form.port_single, "Port");
        payload.type = "full";
        payload.port_start = port;
        payload.port_end = port;
      } else if (mode === "range") {
        const start = this.parsePort(this.form.port_start, "Port start");
        const end = this.parsePort(this.form.port_end, "Port end");
        if (start > end) {
          throw new Error("Port start must be <= Port end");
        }
        payload.type = "full";
        payload.port_start = start;
        payload.port_end = end;
      }
      const route = String(this.form.agent_route || "random").trim();
      if (route === "local") {
        payload.agent_mode = "local";
        payload.agent_id = "local";
      } else if (route.startsWith("agent:")) {
        const agentId = route.slice("agent:".length).trim();
        if (!agentId) {
          throw new Error("Agent route is invalid");
        }
        payload.agent_mode = "agent";
        payload.agent_id = agentId;
      } else {
        payload.agent_mode = "random";
        payload.agent_id = "";
      }
      return payload;
    },
    isActionLoading(id, action) {
      return this.actionLoading.id === id && this.actionLoading.action === action;
    },
    handleWsRefresh() {
      if (this.creating || this.loading) return;
      if (this.wsRefreshTimer) return;
      this.wsRefreshTimer = setTimeout(() => {
        this.wsRefreshTimer = null;
        this.load();
      }, 350);
    },
    normalizeProtocols(raw) {
      const items = this.store.extractArray(raw);
      const unique = [...new Set(items.map((item) => String(item).trim().toLowerCase()))];
      return unique.filter(Boolean);
    },
    loadClusterAgentIds() {
      return Promise.allSettled([
        this.store.fetchJsonPromise("/api/cluster/agent/credentials"),
        this.store.fetchJsonPromise("/api/cluster/agents"),
      ]).then((results) => {
        const ids = new Set();
        results.forEach((entry) => {
          if (!entry || entry.status !== "fulfilled") return;
          const rows = this.store.extractArray(entry.value);
          rows.forEach((row) => {
            const agentId = String((row || {}).agent_id || "").trim();
            if (agentId) ids.add(agentId);
          });
        });
        return [...ids];
      });
    },
    load() {
      this.loading = true;
      this.error = "";
      return Promise.all([
        this.store.fetchJsonPromise("/targets/"),
        this.store.fetchJsonPromise("/protocols/"),
        this.loadClusterAgentIds(),
      ])
        .then(([targetsRes, protocolsRes, agentIds]) => {
          this.targets = this.store.extractArray(targetsRes);
          this.protos = this.normalizeProtocols(protocolsRes);
          this.clusterAgentIds = Array.isArray(agentIds) ? agentIds : [];
          if (!this.protos.length) {
            this.protos = ["tcp", "udp", "icmp", "sctp"];
          }
          if (!this.protos.includes(this.form.proto)) {
            this.form.proto = this.protos[0];
          }
          this.lastUpdated = new Date().toLocaleTimeString();
        })
        .catch((err) => {
          this.targets = [];
          this.protos = ["tcp", "udp", "icmp", "sctp"];
          this.clusterAgentIds = [];
          if (!this.protos.includes(this.form.proto)) {
            this.form.proto = this.protos[0];
          }
          this.lastUpdated = "";
          this.error = err.message || "Failed to load targets";
        })
        .finally(() => {
          this.loading = false;
        });
    },
    createTarget() {
      this.createError = "";
      this.creating = true;
      let payload;
      try {
        payload = this.buildCreatePayload();
      } catch (err) {
        this.creating = false;
        this.createError = err.message || "Invalid target payload";
        return Promise.resolve();
      }
      return this.store
        .fetchJsonPromise("/target/", {
          method: "POST",
          body: JSON.stringify(payload),
        })
        .then(() => this.load())
        .catch((err) => {
          this.createError = err.message || "Failed to create target";
        })
        .finally(() => {
          this.creating = false;
        });
    },
    runTargetAction(item, action) {
      const targetId = Number(item && item.id);
      if (!Number.isFinite(targetId) || targetId <= 0) {
        this.error = "Invalid target id";
        return Promise.resolve();
      }

      if (action === "delete") {
        const ok = typeof window !== "undefined"
          ? window.confirm(`Delete target #${targetId}?`)
          : true;
        if (!ok) return Promise.resolve();
      }

      if (action === "restart") {
        const ok = typeof window !== "undefined"
          ? window.confirm(`Restart target #${targetId} and clear previous results?`)
          : true;
        if (!ok) return Promise.resolve();
      }

      this.error = "";
      this.actionLoading.id = targetId;
      this.actionLoading.action = action;

      const payload = {
        id: targetId,
        action,
        clean_results: action === "restart" || action === "delete",
      };

      return this.store
        .fetchJsonPromise("/target/action/", {
          method: "POST",
          body: JSON.stringify(payload),
        })
        .then(() => this.load())
        .catch((err) => {
          this.error = err.message || `Failed to ${action} target`;
        })
        .finally(() => {
          this.actionLoading.id = null;
          this.actionLoading.action = "";
        });
    },
  },
};
</script>

<style scoped>
.target-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
</style>
