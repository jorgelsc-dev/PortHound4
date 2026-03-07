<template>
  <div>
    <ViewHeader
      overline="API"
      title="Endpoint Catalog"
      description="Reference endpoints exposed by the backend."
      :refresh-loading="loading"
      @refresh="load"
    />

    <DataPanel
      title="Backend Endpoints"
      subtitle="Catalog fetched from /api/endpoints/."
      :loading="loading"
      :error="error"
      :last-updated="lastUpdated"
      @refresh="load"
    >
      <template #skeleton>
        <v-skeleton-loader type="heading, table-thead, table-row@8" class="skeleton-block" />
      </template>

      <div class="text-subtitle-1 font-weight-medium">Base URL</div>
      <div class="text-body-2 text-medium-emphasis">{{ apiBase }}</div>
      <v-divider class="my-4" />
      <v-row dense>
        <v-col cols="12" md="8">
          <v-text-field
            v-model.trim="tableFilters.query"
            label="Search endpoint"
            placeholder="path or description..."
            prepend-inner-icon="mdi-magnify"
            :loading="loading"
            clearable
            variant="outlined"
            density="comfortable"
          />
        </v-col>
        <v-col cols="12" md="4">
          <v-select
            v-model="tableFilters.method"
            :items="methodFilterOptions"
            label="Method"
            item-title="label"
            item-value="value"
            :loading="loading"
            clearable
            variant="outlined"
            density="comfortable"
          />
        </v-col>
      </v-row>
      <v-table density="compact" class="mt-3">
        <thead>
          <tr>
            <th>Method</th>
            <th>Path</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in filteredEndpoints" :key="item.method + item.path">
            <td>{{ item.method }}</td>
            <td>{{ item.path }}</td>
            <td>{{ item.desc }}</td>
          </tr>
          <tr v-if="!filteredEndpoints.length">
            <td colspan="3" class="text-medium-emphasis py-4 text-center">
              No endpoints found
            </td>
          </tr>
        </tbody>
      </v-table>
    </DataPanel>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import DataPanel from "../components/ui/DataPanel.vue";

const FALLBACK_ENDPOINTS = [
  { method: "GET", path: "/api/dashboard/", desc: "Frontend dashboard snapshot." },
  { method: "GET", path: "/api/endpoints/", desc: "Endpoint catalog." },
  { method: "GET", path: "/api/map/scan", desc: "Geolocated scan map snapshot." },
  { method: "GET", path: "/protocols/", desc: "Supported scanner protocols." },
  { method: "GET", path: "/targets/", desc: "List targets." },
  { method: "POST", path: "/target/", desc: "Create target." },
  { method: "POST", path: "/target/action/", desc: "Start/restart/stop/delete target." },
  { method: "POST", path: "/target/action/bulk/", desc: "Bulk start/restart/stop targets by protocol." },
  { method: "POST", path: "/port/action/", desc: "Start/restart/stop a specific endpoint scan." },
  { method: "POST", path: "/banner/action/", desc: "Start/restart/stop banner collection for a specific endpoint." },
  { method: "GET", path: "/ports/tcp/", desc: "List TCP ports." },
  { method: "GET", path: "/ports/udp/", desc: "List UDP ports." },
  { method: "GET", path: "/ports/icmp/", desc: "List ICMP hosts." },
  { method: "GET", path: "/ports/sctp/", desc: "List SCTP ports (if supported)." },
  { method: "GET", path: "/banners/", desc: "List banners." },
  { method: "GET", path: "/favicons/", desc: "List captured favicons." },
  { method: "GET", path: "/favicons/raw/?id=<id>", desc: "Raw favicon by id." },
  { method: "GET", path: "/api/ip/domains/?ip=<ipv4>", desc: "Discover domains associated with an IP." },
  { method: "GET", path: "/api/ip/ttl-path/?ip=<ipv4>", desc: "Estimate hop count and intermediate devices with TTL." },
  { method: "GET", path: "/api/ip/intel/?ip=<ipv4>", desc: "Combined IP intel (domains + TTL path + host profile with HTTP/TLS metrics)." },
  { method: "POST", path: "/api/ws/broadcast", desc: "Broadcast WS message." },
  { method: "POST", path: "/api/chat/clear", desc: "Clear chat log." },
];

export default {
  name: "ApiView",
  components: {
    ViewHeader,
    DataPanel,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      endpoints: FALLBACK_ENDPOINTS,
      tableFilters: {
        query: "",
        method: "",
      },
      wsRefreshTimer: null,
      stopTableRefreshSubscription: null,
    };
  },
  computed: {
    apiBase() {
      return this.store.state.apiBase || window.location.origin;
    },
    methodFilterOptions() {
      const methods = [...new Set(this.endpoints.map((item) => String(item.method || "").trim().toUpperCase()))]
        .filter(Boolean)
        .sort();
      return [{ label: "All", value: "" }, ...methods.map((value) => ({ label: value, value }))];
    },
    filteredEndpoints() {
      const query = String(this.tableFilters.query || "").trim().toLowerCase();
      const method = String(this.tableFilters.method || "").trim().toUpperCase();
      return this.endpoints.filter((item) => {
        if (method && String(item.method || "").trim().toUpperCase() !== method) {
          return false;
        }
        if (!query) return true;
        const haystack = [
          item.method,
          item.path,
          item.desc,
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
    handleWsRefresh() {
      if (this.loading) return;
      if (this.wsRefreshTimer) return;
      this.wsRefreshTimer = setTimeout(() => {
        this.wsRefreshTimer = null;
        this.load();
      }, 500);
    },
    load() {
      this.loading = true;
      this.error = "";
      return this.store
        .fetchJsonPromise("/api/endpoints/")
        .then((res) => {
          const parsed = this.store.extractArray(res);
          if (parsed.length) this.endpoints = parsed;
          this.lastUpdated = new Date().toLocaleTimeString();
        })
        .catch((err) => {
          this.error = err.message || "Failed to load endpoints";
          this.lastUpdated = "";
          this.endpoints = FALLBACK_ENDPOINTS;
        })
        .finally(() => {
          this.loading = false;
        });
    },
  },
};
</script>
