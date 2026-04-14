<template>
  <div>
    <ViewHeader
      overline="Ports"
      title="Port Intelligence"
      description="Review discovered ports by protocol."
      :refresh-loading="loading"
      @refresh="load"
    />

    <DataPanel
      title="Discovered Ports"
      subtitle="Switch protocol tabs and reload manually when needed."
      :loading="loading"
      :error="error"
      :last-updated="lastUpdated"
      :live-refresh="true"
      @refresh="load"
    >
      <template #skeleton>
        <v-skeleton-loader type="heading, table-thead, table-row@6" class="skeleton-block" />
      </template>

      <v-alert v-if="!protocols.length && !loading" type="info" variant="tonal" class="mt-4">
        No protocols available from backend.
      </v-alert>

      <template v-else>
        <v-row dense class="mt-2">
          <v-col cols="12" md="7">
            <v-text-field
              v-model.trim="tableFilters.query"
              label="Search ports"
              placeholder="IP, port, state..."
              prepend-inner-icon="mdi-magnify"
              :loading="loading"
              clearable
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="3">
            <v-select
              v-model="tableFilters.state"
              :items="stateFilterOptions"
              label="State"
              item-title="label"
              item-value="value"
              :loading="loading"
              clearable
              variant="outlined"
              density="comfortable"
            />
          </v-col>
        </v-row>
        <div class="protocol-toolbar mt-4">
          <div class="protocol-toolbar__meta">
            <v-chip size="small" color="primary" variant="tonal">
              {{ activeProtoLabel }}
            </v-chip>
            <v-chip size="small" color="success" variant="tonal">
              Active: {{ activeTargetCount }}
            </v-chip>
            <v-chip size="small" color="warning" variant="tonal">
              Stopped: {{ stoppedTargetCount }}
            </v-chip>
            <v-chip size="small" variant="outlined">
              Targets: {{ matchingTargetCount }}
            </v-chip>
          </div>
          <div class="protocol-toolbar__actions">
            <v-btn
              size="small"
              color="success"
              variant="tonal"
              :loading="isBulkActionLoading('start')"
              :disabled="loading || !stoppedTargetCount"
              @click="runBulkTargetAction('start')"
            >
              Start {{ activeProtoShortLabel }}
            </v-btn>
            <v-btn
              size="small"
              color="warning"
              variant="tonal"
              :loading="isBulkActionLoading('stop')"
              :disabled="loading || !activeTargetCount"
              @click="runBulkTargetAction('stop')"
            >
              Stop {{ activeProtoShortLabel }}
            </v-btn>
            <v-btn
              size="small"
              color="info"
              variant="tonal"
              :loading="isBulkActionLoading('restart')"
              :disabled="loading || !matchingTargetCount"
              @click="runBulkTargetAction('restart')"
            >
              Restart {{ activeProtoShortLabel }}
            </v-btn>
            <v-btn size="small" variant="outlined" to="/targets">
              View Targets
            </v-btn>
          </div>
        </div>
        <v-tabs v-model="tab" color="primary" class="mt-4">
          <v-tab v-for="proto in protocols" :key="proto" :value="proto" :disabled="loading">
            {{ proto.toUpperCase() }}
          </v-tab>
        </v-tabs>
        <v-window v-model="tab" class="mt-4">
          <v-window-item v-for="proto in protocols" :key="`win-${proto}`" :value="proto">
            <v-table density="compact">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>IP</th>
                  <th>Port</th>
                  <th>State</th>
                  <th>Scan Status</th>
                  <th>Banner Progress</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="item in pagedRowsByProto[proto] || []" :key="item.id">
                  <td>{{ item.id }}</td>
                  <td>{{ item.ip }}</td>
                  <td>{{ item.port }}</td>
                  <td :title="formatStateTooltip(item)">{{ formatStateLabel(item) }}</td>
                  <td>
                    <v-chip
                      size="x-small"
                      :color="scanStatusColor(item.scan_state)"
                      variant="tonal"
                    >
                      {{ scanStatusLabel(item.scan_state) }}
                    </v-chip>
                  </td>
                  <td>
                    <ProgressCell :value="item.progress" />
                  </td>
                  <td>
                    <div class="row-actions">
                      <v-btn
                        size="x-small"
                        color="success"
                        variant="tonal"
                        :loading="isPortActionLoading(item.id, 'start')"
                        :disabled="loading || normalizePortScanState(item.scan_state) === 'active'"
                        @click="runPortAction(item, 'start')"
                      >
                        Start
                      </v-btn>
                      <v-btn
                        size="x-small"
                        color="warning"
                        variant="tonal"
                        :loading="isPortActionLoading(item.id, 'stop')"
                        :disabled="loading || normalizePortScanState(item.scan_state) === 'stopped'"
                        @click="runPortAction(item, 'stop')"
                      >
                        Stop
                      </v-btn>
                      <v-btn
                        size="x-small"
                        color="info"
                        variant="tonal"
                        :loading="isPortActionLoading(item.id, 'restart')"
                        :disabled="loading"
                        @click="runPortAction(item, 'restart')"
                      >
                        Restart
                      </v-btn>
                    </div>
                  </td>
                </tr>
                <tr v-if="!(filteredRowsByProto[proto] || []).length">
                  <td colspan="7" class="text-medium-emphasis py-4 text-center">
                    No {{ proto.toUpperCase() }} records
                  </td>
                </tr>
              </tbody>
            </v-table>
            <div class="d-flex justify-center mt-3" v-if="(pageCountsByProto[proto] || 1) > 1">
              <v-pagination
                v-model="paginationByProto[proto]"
                :length="pageCountsByProto[proto]"
                density="comfortable"
                total-visible="7"
              />
            </div>
          </v-window-item>
        </v-window>
      </template>
    </DataPanel>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import DataPanel from "../components/ui/DataPanel.vue";
import ProgressCell from "../components/ui/ProgressCell.vue";

const FALLBACK_PROTOCOLS = ["tcp", "udp", "icmp", "sctp"];
const PAGE_SIZE = 80;

export default {
  name: "PortsView",
  components: {
    ViewHeader,
    DataPanel,
    ProgressCell,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      tab: "tcp",
      protocols: [],
      targets: [],
      portsByProto: {},
      tableFilters: {
        query: "",
        state: "",
      },
      actionLoading: "",
      portActionLoading: {
        id: null,
        action: "",
      },
      paginationByProto: {},
      wsRefreshTimer: null,
      stopTableRefreshSubscription: null,
      lastProtocolsSyncAt: 0,
    };
  },
  computed: {
    apiBase() {
      return this.store.state.apiBase;
    },
    stateFilterOptions() {
      const states = [...new Set(
        this.rowsFor(this.tab).map((item) => String(item.state || "").trim().toLowerCase())
      )]
        .filter(Boolean)
        .sort();
      return [{ label: "All", value: "" }, ...states.map((value) => ({ label: value, value }))];
    },
    activeProtoLabel() {
      const proto = String(this.tab || "").trim().toUpperCase();
      return proto ? `Control ${proto}` : "Control";
    },
    activeProtoShortLabel() {
      const proto = String(this.tab || "").trim().toUpperCase();
      return proto || "targets";
    },
    targetsForActiveProto() {
      const activeProto = String(this.tab || "").trim().toLowerCase();
      if (!activeProto) return [];
      return this.targets.filter((item) => this.normalizeTargetProto(item && item.proto) === activeProto);
    },
    matchingTargetCount() {
      return this.targetsForActiveProto.length;
    },
    activeTargetCount() {
      return this.targetsForActiveProto.filter((item) =>
        ["active", "restarting"].includes(this.normalizeTargetStatus(item && item.status))
      ).length;
    },
    stoppedTargetCount() {
      return this.targetsForActiveProto.filter(
        (item) => this.normalizeTargetStatus(item && item.status) === "stopped"
      ).length;
    },
    filteredRowsByProto() {
      const query = String(this.tableFilters.query || "").trim().toLowerCase();
      const state = String(this.tableFilters.state || "").trim().toLowerCase();
      const mapped = {};
      this.protocols.forEach((proto) => {
        mapped[proto] = this.rowsFor(proto).filter((item) => {
          if (state && String(item.state || "").trim().toLowerCase() !== state) {
            return false;
          }
          if (!query) return true;
          const haystack = [
            item.id,
            item.ip,
            item.port,
            item.state,
            item.progress,
          ]
            .map((value) => String(value == null ? "" : value).toLowerCase())
            .join(" ");
          return haystack.includes(query);
        });
      });
      return mapped;
    },
    pageCountsByProto() {
      const mapped = {};
      this.protocols.forEach((proto) => {
        const rows = this.filteredRowsByProto[proto] || [];
        mapped[proto] = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
      });
      return mapped;
    },
    pagedRowsByProto() {
      const mapped = {};
      this.protocols.forEach((proto) => {
        const rows = this.filteredRowsByProto[proto] || [];
        const maxPages = this.pageCountsByProto[proto] || 1;
        const currentRaw = Number(this.paginationByProto[proto] || 1);
        const page = Number.isInteger(currentRaw) && currentRaw > 0
          ? Math.min(currentRaw, maxPages)
          : 1;
        if (page !== currentRaw) {
          this.paginationByProto = { ...this.paginationByProto, [proto]: page };
        }
        const start = (page - 1) * PAGE_SIZE;
        mapped[proto] = rows.slice(start, start + PAGE_SIZE);
      });
      return mapped;
    },
  },
  watch: {
    apiBase() {
      this.load();
    },
    tab() {
      this.tableFilters.state = "";
      this.ensurePaginationForProto(this.tab);
    },
    tableFilters: {
      deep: true,
      handler() {
        this.resetPagination();
      },
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
    normalizeTargetProto(value) {
      const proto = String(value || "").trim().toLowerCase();
      if (proto === "stcp") return "sctp";
      return proto;
    },
    normalizeTargetStatus(value) {
      const raw = String(value || "active").trim().toLowerCase();
      if (raw === "restarting") return "restarting";
      if (raw === "stopped") return "stopped";
      return "active";
    },
    normalizePortScanState(value) {
      const raw = String(value || "active").trim().toLowerCase();
      if (raw === "restarting") return "restarting";
      if (raw === "stopped") return "stopped";
      return "active";
    },
    isBulkActionLoading(action) {
      return this.actionLoading === action;
    },
    isPortActionLoading(id, action) {
      return this.portActionLoading.id === id && this.portActionLoading.action === action;
    },
    scanStatusLabel(value) {
      const status = this.normalizePortScanState(value);
      if (status === "restarting") return "restarting";
      if (status === "stopped") return "stopped";
      return "active";
    },
    scanStatusColor(value) {
      const status = this.normalizePortScanState(value);
      if (status === "restarting") return "info";
      if (status === "stopped") return "warning";
      return "success";
    },
    formatStateLabel(row) {
      const proto = String(row?.proto || "").trim().toLowerCase();
      const state = String(row?.state || "").trim().toLowerCase();
      if (!state) return "-";
      if (proto === "icmp" && state === "filtered") return "no reply";
      return state;
    },
    formatStateTooltip(row) {
      const proto = String(row?.proto || "").trim().toLowerCase();
      const state = String(row?.state || "").trim().toLowerCase();
      if (!state) return "-";
      if (proto === "icmp" && state === "filtered") {
        return "ICMP echo reply was not received. The host may be down or a firewall may be dropping the probe.";
      }
      if (proto === "icmp" && state === "open") {
        return "ICMP echo reply received.";
      }
      return state;
    },
    handleWsRefresh() {
      if (this.loading) return;
      if (this.wsRefreshTimer) return;
      this.wsRefreshTimer = setTimeout(() => {
        this.wsRefreshTimer = null;
        this.refreshActiveProtocolRealtime();
      }, 700);
    },
    rowsFor(proto) {
      return this.portsByProto[proto] || [];
    },
    ensurePaginationForProto(proto) {
      const key = String(proto || "").trim().toLowerCase();
      if (!key) return;
      if (!this.paginationByProto[key]) {
        this.paginationByProto = { ...this.paginationByProto, [key]: 1 };
      }
    },
    resetPagination() {
      const next = {};
      this.protocols.forEach((proto) => {
        next[proto] = 1;
      });
      this.paginationByProto = next;
    },
    normalizeProtocols(raw) {
      const items = this.store.extractArray(raw);
      const unique = [...new Set(items.map((item) => String(item).trim().toLowerCase()))];
      return unique.filter(Boolean);
    },
    loadProtocols() {
      return this.store.fetchJsonPromise("/protocols/").then((protocolsRes) => {
        const protocols = this.normalizeProtocols(protocolsRes);
        return protocols.length ? protocols : FALLBACK_PROTOCOLS;
      });
    },
    loadTargets() {
      return this.store.fetchJsonPromise("/targets/").then((targetsRes) => {
        this.targets = this.store.extractArray(targetsRes);
        return this.targets;
      });
    },
    loadPortsForProtocols(protocols) {
      const list = Array.isArray(protocols) && protocols.length ? protocols : FALLBACK_PROTOCOLS;
      return Promise.allSettled(
        list.map((proto) => this.store.fetchJsonPromise(`/ports/${proto}/`))
      ).then((responses) => {
        const mapped = {};
        list.forEach((proto, index) => {
          const result = responses[index];
          mapped[proto] =
            result && result.status === "fulfilled"
              ? this.store.extractArray(result.value)
              : [];
        });
        this.portsByProto = mapped;
        this.protocols = list;
        list.forEach((proto) => this.ensurePaginationForProto(proto));
      });
    },
    refreshActiveProtocolRealtime() {
      const now = Date.now();
      const shouldSyncProtocols = now - this.lastProtocolsSyncAt >= 30000;
      if (shouldSyncProtocols) {
        return this.load().catch(() => {
          // keep stale table on transient refresh errors
        });
      }
      const activeProto = String(this.tab || "").trim().toLowerCase();
      if (!activeProto) return Promise.resolve();
      return this.store
        .fetchJsonPromise(`/ports/${activeProto}/`)
        .then((payload) => {
          this.portsByProto = {
            ...this.portsByProto,
            [activeProto]: this.store.extractArray(payload),
          };
          this.lastUpdated = new Date().toLocaleTimeString();
          this.ensurePaginationForProto(activeProto);
        })
        .catch(() => {
          // keep stale table on transient refresh errors
        });
    },
    load() {
      this.loading = true;
      this.error = "";
      return Promise.allSettled([this.loadProtocols(), this.loadTargets()])
        .then(([protocolsRes, targetsRes]) => {
          const protocols =
            protocolsRes.status === "fulfilled" ? protocolsRes.value : FALLBACK_PROTOCOLS;
          if (targetsRes.status !== "fulfilled") {
            this.targets = [];
          }
          if (!protocols.length) {
            this.protocols = [];
            this.portsByProto = {};
            this.paginationByProto = {};
            return [];
          }
          if (!protocols.includes(this.tab)) {
            this.tab = protocols[0];
          }
          return this.loadPortsForProtocols(protocols);
        })
        .then(() => {
          this.lastUpdated = new Date().toLocaleTimeString();
          this.lastProtocolsSyncAt = Date.now();
        })
        .catch((err) => {
          this.protocols = FALLBACK_PROTOCOLS;
          this.targets = [];
          this.portsByProto = {};
          this.resetPagination();
          this.lastUpdated = "";
          this.error = err.message || "Failed to load ports";
        })
        .finally(() => {
          this.loading = false;
        });
    },
    runBulkTargetAction(action) {
      const proto = String(this.tab || "").trim().toLowerCase();
      if (!proto) {
        this.error = "No active protocol selected";
        return Promise.resolve();
      }
      if (!this.matchingTargetCount) {
        this.error = `No targets found for ${proto.toUpperCase()}`;
        return Promise.resolve();
      }
      if (action === "stop") {
        const ok = typeof window !== "undefined"
          ? window.confirm(`Stop all ${proto.toUpperCase()} targets?`)
          : true;
        if (!ok) return Promise.resolve();
      }
      if (action === "restart") {
        const ok = typeof window !== "undefined"
          ? window.confirm(`Restart all ${proto.toUpperCase()} targets and clear previous results?`)
          : true;
        if (!ok) return Promise.resolve();
      }
      this.error = "";
      this.actionLoading = action;
      return this.store
        .fetchJsonPromise("/target/action/bulk/", {
          method: "POST",
          body: JSON.stringify({
            action,
            proto,
            clean_results: action === "restart",
          }),
        })
        .then(() => this.load())
        .catch((err) => {
          this.error = err.message || `Failed to ${action} ${proto} targets`;
        })
        .finally(() => {
          this.actionLoading = "";
        });
    },
    runPortAction(item, action) {
      const endpointId = Number(item && item.id);
      if (!Number.isFinite(endpointId) || endpointId <= 0) {
        this.error = "Invalid port endpoint id";
        return Promise.resolve();
      }
      const proto = String(item && item.proto || "").trim().toUpperCase() || "endpoint";
      const ip = String(item && item.ip || "").trim() || "n/a";
      const port = String(item && item.port != null ? item.port : "").trim() || "n/a";
      if (action === "stop") {
        const ok = typeof window !== "undefined"
          ? window.confirm(`Stop ${proto} endpoint ${ip}:${port}?`)
          : true;
        if (!ok) return Promise.resolve();
      }
      if (action === "restart") {
        const ok = typeof window !== "undefined"
          ? window.confirm(`Restart ${proto} endpoint ${ip}:${port} and clear collected banner artifacts?`)
          : true;
        if (!ok) return Promise.resolve();
      }
      this.error = "";
      this.portActionLoading = { id: endpointId, action };
      return this.store
        .fetchJsonPromise("/port/action/", {
          method: "POST",
          body: JSON.stringify({
            id: endpointId,
            action,
            clean_results: action === "restart",
          }),
        })
        .then(() => this.refreshActiveProtocolRealtime())
        .catch((err) => {
          this.error = err.message || `Failed to ${action} port endpoint`;
        })
        .finally(() => {
          this.portActionLoading = { id: null, action: "" };
        });
    },
  },
};
</script>

<style scoped>
.protocol-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.protocol-toolbar__meta,
.protocol-toolbar__actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.row-actions {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
</style>
