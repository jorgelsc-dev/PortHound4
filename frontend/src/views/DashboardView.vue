<template>
  <div>
    <ViewHeader
      overline="Operational snapshot"
      title="Dashboard"
      description="Live counts, targets, and banners from the scanner backend."
      :refresh-loading="loading"
      @refresh="load"
    />

    <v-row dense>
      <v-col
        v-for="metric in metricCards"
        :key="metric.key"
        cols="12"
        md="3"
      >
        <div v-if="loading" class="metric-skeleton">
          <div class="metric-skeleton__chrome">
            <div>
              <div class="metric-skeleton__line metric-skeleton__line--label"></div>
              <div class="metric-skeleton__line metric-skeleton__line--value"></div>
            </div>
            <div class="metric-skeleton__orb"></div>
          </div>
          <div class="metric-skeleton__line metric-skeleton__line--footer"></div>
        </div>
        <v-card v-else variant="tonal" class="pa-5 metric-card">
          <div class="d-flex align-center justify-space-between ga-3">
            <div>
              <div class="text-caption text-medium-emphasis">{{ metric.label }}</div>
              <div class="text-h5 font-weight-bold" :class="metric.colorClass">
                {{ metric.value }}
              </div>
            </div>
            <v-icon :icon="metric.icon" class="metric-icon" :class="metric.colorClass" />
          </div>
        </v-card>
      </v-col>
    </v-row>

    <v-alert v-if="error" type="error" variant="tonal" class="my-6">
      {{ error }}
    </v-alert>

    <v-row class="mt-4" dense>
      <v-col cols="12" lg="7">
        <MapPanel />
      </v-col>
      <v-col cols="12" lg="5">
        <DataPanel
          title="Quick Links"
          subtitle="Jump to the core sections."
          :loading="loading"
          :show-refresh="false"
          :last-updated="lastUpdated"
        >
          <div class="d-flex flex-wrap ga-2">
            <v-btn v-for="item in quickLinks" :key="item.to" :to="item.to" variant="outlined">
              {{ item.label }}
            </v-btn>
          </div>
          <v-divider class="my-4" />
          <div class="text-subtitle-2">Ports by protocol</div>
          <div class="d-flex flex-wrap ga-2 mt-2">
            <v-chip v-for="chip in protocolChips" :key="chip.proto" size="small" variant="tonal">
              {{ chip.proto.toUpperCase() }}: {{ chip.count }}
            </v-chip>
            <span v-if="!protocolChips.length" class="text-body-2 text-medium-emphasis">
              No protocol data yet
            </span>
          </div>
          <v-divider class="my-4" />
          <div class="text-subtitle-2">Last update</div>
          <div class="text-body-2 text-medium-emphasis">{{ lastUpdated }}</div>
        </DataPanel>
      </v-col>
    </v-row>

    <v-row class="mt-4" dense>
      <v-col cols="12" md="6">
        <v-row dense class="mb-2">
          <v-col cols="12" md="8">
            <v-text-field
              v-model.trim="targetFilters.query"
              label="Search targets"
              placeholder="network, proto, type..."
              prepend-inner-icon="mdi-magnify"
              :loading="loading"
              clearable
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="4">
            <v-select
              v-model="targetFilters.proto"
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
        </v-row>
        <EntityTablePanel
          title="Recent Targets"
          subtitle="Latest configured network scopes."
          :rows="filteredRecentTargets"
          :columns="targetColumns"
          :loading="loading"
          :error="error"
          :show-refresh="false"
          empty-text="No targets"
        >
          <template #cell-progress="{ value }">
            <ProgressCell :value="value" />
          </template>
          <template #cell-status="{ value }">
            <v-chip size="small" :color="statusColor(value)" variant="tonal">
              {{ normalizeStatus(value) }}
            </v-chip>
          </template>
          <template #cell-actions="{ item }">
            <div class="target-actions">
              <v-btn
                size="x-small"
                color="success"
                variant="tonal"
                :loading="isActionLoading(item.id, 'start')"
                :disabled="loading || normalizeStatus(item.status) === 'active'"
                @click="runTargetAction(item, 'start')"
              >
                Start
              </v-btn>
              <v-btn
                size="x-small"
                color="warning"
                variant="tonal"
                :loading="isActionLoading(item.id, 'stop')"
                :disabled="loading || normalizeStatus(item.status) === 'stopped'"
                @click="runTargetAction(item, 'stop')"
              >
                Stop
              </v-btn>
            </div>
          </template>
        </EntityTablePanel>
      </v-col>
      <v-col cols="12" md="6">
        <v-row dense class="mb-2">
          <v-col cols="12" md="8">
            <v-text-field
              v-model.trim="bannerFilters.query"
              label="Search banners"
              placeholder="ip, banner, port..."
              prepend-inner-icon="mdi-magnify"
              :loading="loading"
              clearable
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="4">
            <v-select
              v-model="bannerFilters.proto"
              :items="bannerProtoFilterOptions"
              label="Proto"
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
          title="Latest Banners"
          subtitle="Recent banner responses from scanned services."
          :rows="filteredRecentBanners"
          :columns="bannerColumns"
          :loading="loading"
          :error="error"
          :show-refresh="false"
          empty-text="No banners"
        >
          <template #cell-response_plain="{ value }">
            <span class="banner-cell">{{ value }}</span>
          </template>
        </EntityTablePanel>
      </v-col>
    </v-row>
  </div>
</template>

<script>
import store from "../state/appStore";
import MapPanel from "../components/MapPanel.vue";
import ViewHeader from "../components/ui/ViewHeader.vue";
import DataPanel from "../components/ui/DataPanel.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";
import ProgressCell from "../components/ui/ProgressCell.vue";

export default {
  name: "DashboardView",
  components: {
    MapPanel,
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
      lastUpdated: "n/a",
      counts: {
        count_targets: 0,
        count_ports: 0,
        count_banners: 0,
      },
      targets: [],
      banners: [],
      portsByProto: {},
      wsClients: [],
      targetColumns: [
        { key: "network", label: "Network" },
        { key: "type", label: "Type" },
        { key: "proto", label: "Proto" },
        { key: "status", label: "Status" },
        { key: "progress", label: "Progress" },
        { key: "actions", label: "Actions" },
      ],
      bannerColumns: [
        { key: "ip", label: "IP" },
        { key: "port", label: "Port" },
        { key: "response_plain", label: "Banner" },
      ],
      quickLinks: [
        { label: "Map", to: "/map" },
        { label: "Agents", to: "/agents" },
        { label: "Targets", to: "/targets" },
        { label: "Explorer", to: "/explorer" },
        { label: "Ports", to: "/ports" },
        { label: "Banners", to: "/banners" },
        { label: "Tags", to: "/tags" },
        { label: "API", to: "/api" },
      ],
      targetFilters: {
        query: "",
        proto: "",
      },
      bannerFilters: {
        query: "",
        proto: "",
      },
      actionLoading: {
        id: null,
        action: "",
      },
      wsRefreshTimer: null,
      stopTableRefreshSubscription: null,
    };
  },
  computed: {
    apiBase() {
      return this.store.state.apiBase;
    },
    metricCards() {
      return [
        {
          key: "targets",
          label: "Targets",
          value: this.counts.count_targets,
          icon: "mdi-target",
          colorClass: "text-primary",
        },
        {
          key: "ports",
          label: "Ports",
          value: this.counts.count_ports,
          icon: "mdi-ethernet",
          colorClass: "text-success",
        },
        {
          key: "banners",
          label: "Banners",
          value: this.counts.count_banners,
          icon: "mdi-card-text",
          colorClass: "text-secondary",
        },
        {
          key: "ws",
          label: "WS Clients",
          value: this.wsClients.length,
          icon: "mdi-access-point",
          colorClass: "text-warning",
        },
      ];
    },
    protocolChips() {
      const entries = Object.entries(this.portsByProto || {});
      return entries
        .map(([proto, rows]) => ({ proto, count: Array.isArray(rows) ? rows.length : 0 }))
        .sort((a, b) => a.proto.localeCompare(b.proto));
    },
    targetProtoFilterOptions() {
      const values = [...new Set(this.targets.map((item) => String(item.proto || "").trim().toLowerCase()))]
        .filter(Boolean)
        .sort();
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value.toUpperCase(), value }))];
    },
    bannerProtoFilterOptions() {
      const values = [...new Set(this.banners.map((item) => String(item.proto || "").trim().toLowerCase()))]
        .filter(Boolean)
        .sort();
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value.toUpperCase(), value }))];
    },
    filteredRecentTargets() {
      const query = String(this.targetFilters.query || "").trim().toLowerCase();
      const proto = String(this.targetFilters.proto || "").trim().toLowerCase();
      return this.targets
        .filter((item) => {
          if (proto && String(item.proto || "").trim().toLowerCase() !== proto) return false;
          if (!query) return true;
          const haystack = [
            item.network,
            item.type,
            item.proto,
            item.status,
            item.progress,
            item.port_mode,
            item.port_start,
            item.port_end,
          ]
            .map((value) => String(value == null ? "" : value).toLowerCase())
            .join(" ");
          return haystack.includes(query);
        })
        .slice(0, 6);
    },
    filteredRecentBanners() {
      const query = String(this.bannerFilters.query || "").trim().toLowerCase();
      const proto = String(this.bannerFilters.proto || "").trim().toLowerCase();
      return this.banners
        .filter((item) => {
          if (proto && String(item.proto || "").trim().toLowerCase() !== proto) return false;
          if (!query) return true;
          const haystack = [
            item.ip,
            item.port,
            item.proto,
            item.response_plain,
          ]
            .map((value) => String(value == null ? "" : value).toLowerCase())
            .join(" ");
          return haystack.includes(query);
        })
        .slice(0, 6);
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
    isActionLoading(id, action) {
      return this.actionLoading.id === id && this.actionLoading.action === action;
    },
    handleWsRefresh() {
      if (this.loading) return;
      if (this.wsRefreshTimer) return;
      this.wsRefreshTimer = setTimeout(() => {
        this.wsRefreshTimer = null;
        this.load();
      }, 350);
    },
    extractPortsMap(rawPorts) {
      if (Array.isArray(rawPorts)) {
        return rawPorts.reduce((acc, row) => {
          const proto = String((row && row.proto) || "").trim().toLowerCase();
          if (!proto) return acc;
          if (!acc[proto]) acc[proto] = [];
          acc[proto].push(row);
          return acc;
        }, {});
      }
      if (!rawPorts || typeof rawPorts !== "object") return {};
      const mapped = {};
      Object.keys(rawPorts).forEach((proto) => {
        mapped[proto] = Array.isArray(rawPorts[proto]) ? rawPorts[proto] : [];
      });
      return mapped;
    },
    normalizeProtocols(raw) {
      const items = this.store.extractArray(raw);
      const unique = [...new Set(items.map((item) => String(item).trim().toLowerCase()))];
      return unique.filter(Boolean);
    },
    runTargetAction(item, action) {
      const targetId = Number(item && item.id);
      if (!Number.isFinite(targetId) || targetId <= 0) {
        this.error = "Invalid target id";
        return Promise.resolve();
      }
      this.error = "";
      this.actionLoading.id = targetId;
      this.actionLoading.action = action;
      return this.store
        .fetchJsonPromise("/target/action/", {
          method: "POST",
          body: JSON.stringify({
            id: targetId,
            action,
            clean_results: false,
          }),
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
    load() {
      this.loading = true;
      this.error = "";
      return this.store
        .fetchJsonPromise("/api/dashboard/")
        .then((dashboard) => {
          const counts = dashboard.counts || {};
          this.counts = {
            count_targets: counts.count_targets || 0,
            count_ports: counts.count_ports || 0,
            count_banners: counts.count_banners || 0,
          };
          this.targets = this.store.extractArray(dashboard.targets);
          this.banners = this.store.extractArray(dashboard.banners);
          this.wsClients = this.store.extractArray(dashboard.ws_clients);
          this.portsByProto = this.extractPortsMap(dashboard.ports);
          this.lastUpdated = new Date().toLocaleTimeString();
        })
        .catch(() =>
          Promise.all([
            this.store.fetchJsonPromise("/"),
            this.store.fetchJsonPromise("/targets/"),
            this.store.fetchJsonPromise("/banners/"),
            this.store.fetchJsonPromise("/api/ws/clients"),
            this.store.fetchJsonPromise("/protocols/"),
          ])
            .then(([counts, targets, banners, ws, protocolsRes]) => {
              const protocols = this.normalizeProtocols(protocolsRes);
              return Promise.all(
                protocols.map((proto) => this.store.fetchJsonPromise(`/ports/${proto}/`))
              ).then((portsResponses) => {
                const portsByProto = {};
                protocols.forEach((proto, index) => {
                  portsByProto[proto] = this.store.extractArray(portsResponses[index]);
                });
                this.counts = {
                  count_targets: counts.count_targets || 0,
                  count_ports: counts.count_ports || 0,
                  count_banners: counts.count_banners || 0,
                };
                this.targets = this.store.extractArray(targets);
                this.banners = this.store.extractArray(banners);
                this.wsClients = this.store.extractArray(ws);
                this.portsByProto = portsByProto;
              });
            })
            .then(() => {
              this.error = "";
              this.lastUpdated = new Date().toLocaleTimeString();
            })
            .catch((fallbackErr) => {
              this.error = fallbackErr.message || "Failed to load dashboard";
            })
        )
        .finally(() => {
          this.loading = false;
        });
    },
  },
};
</script>

<style scoped>
.metric-card,
.metric-skeleton {
  border-radius: 16px;
}

.target-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.metric-skeleton {
  border: 1px solid rgba(106, 179, 221, 0.2);
  padding: 20px;
  background: linear-gradient(160deg, rgba(12, 20, 31, 0.92), rgba(9, 16, 26, 0.82));
  position: relative;
  overflow: hidden;
  box-shadow: inset 0 1px 0 rgba(131, 204, 239, 0.06);
}

.metric-skeleton::before {
  content: "";
  position: absolute;
  inset: 0;
  background-image: linear-gradient(rgba(129, 181, 220, 0.05) 1px, transparent 1px),
    linear-gradient(90deg, rgba(129, 181, 220, 0.04) 1px, transparent 1px);
  background-size: 24px 24px;
  opacity: 0.24;
}

.metric-skeleton::after {
  content: "";
  position: absolute;
  inset: 0;
  background: linear-gradient(
    110deg,
    rgba(24, 40, 58, 0) 0%,
    rgba(84, 164, 210, 0.08) 35%,
    rgba(131, 233, 255, 0.2) 50%,
    rgba(24, 40, 58, 0) 82%
  );
  animation: metric-skeleton-sweep 1.5s linear infinite;
}

.metric-skeleton__chrome {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  position: relative;
  z-index: 1;
}

.metric-skeleton__orb {
  width: 42px;
  height: 42px;
  border-radius: 14px;
  background: radial-gradient(circle at 35% 35%, rgba(129, 242, 255, 0.82), rgba(54, 152, 219, 0.38));
  box-shadow: inset 0 0 0 1px rgba(133, 206, 243, 0.18), 0 0 24px rgba(60, 168, 224, 0.14);
}

.metric-skeleton__line {
  height: 12px;
  border-radius: 999px;
  background: linear-gradient(
    90deg,
    rgba(57, 106, 151, 0.36),
    rgba(112, 188, 229, 0.36),
    rgba(57, 106, 151, 0.36)
  );
  background-size: 220% 100%;
  animation: metric-skeleton-slide 1.2s ease-in-out infinite;
}

.metric-skeleton__line--label {
  width: 44%;
}

.metric-skeleton__line--value {
  width: 60%;
  margin-top: 14px;
  height: 18px;
}

.metric-skeleton__line--footer {
  width: 74%;
  margin-top: 18px;
  position: relative;
  z-index: 1;
}

.metric-icon {
  opacity: 0.92;
}

.banner-cell {
  display: inline-block;
  max-width: 320px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

@keyframes metric-skeleton-slide {
  0% {
    background-position: 120% 0;
  }
  100% {
    background-position: -120% 0;
  }
}

@keyframes metric-skeleton-sweep {
  from {
    transform: translateX(-100%);
  }
  to {
    transform: translateX(100%);
  }
}
</style>
