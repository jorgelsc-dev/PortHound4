<template>
  <div>
    <ViewHeader
      overline="Tags"
      title="Metadata Tags"
      description="Timing and metadata captured alongside scan results."
      :refresh-loading="loading"
      @refresh="load"
    />

    <v-row dense class="mb-4">
      <v-col cols="12" md="6">
        <v-text-field
          v-model.trim="tableFilters.query"
          label="Search tags"
          placeholder="IP, value, key..."
          prepend-inner-icon="mdi-magnify"
          :loading="loading"
          clearable
          variant="outlined"
          density="comfortable"
        />
      </v-col>
      <v-col cols="12" md="3">
        <v-select
          v-model="tableFilters.proto"
          :items="protoFilterOptions"
          label="Proto"
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
          v-model="tableFilters.key"
          :items="keyFilterOptions"
          label="Key"
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
      title="Tag Registry"
      subtitle="Scan metadata entries and timing indicators."
      :rows="filteredTags"
      :columns="columns"
      :loading="loading"
      :error="error"
      :last-updated="lastUpdated"
      :live-refresh="true"
      empty-text="No tags available"
      @refresh="load"
    />
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";

export default {
  name: "TagsView",
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
      tags: [],
      columns: [
        { key: "id", label: "ID" },
        { key: "ip", label: "IP" },
        { key: "port", label: "Port" },
        { key: "proto", label: "Proto" },
        { key: "key", label: "Key" },
        { key: "value", label: "Value" },
      ],
      tableFilters: {
        query: "",
        proto: "",
        key: "",
      },
      wsRefreshTimer: null,
      stopTableRefreshSubscription: null,
    };
  },
  computed: {
    apiBase() {
      return this.store.state.apiBase;
    },
    protoFilterOptions() {
      const values = [...new Set(this.tags.map((item) => String(item.proto || "").trim().toLowerCase()))]
        .filter(Boolean)
        .sort();
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value.toUpperCase(), value }))];
    },
    keyFilterOptions() {
      const values = [...new Set(this.tags.map((item) => String(item.key || "").trim().toLowerCase()))]
        .filter(Boolean)
        .sort();
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value, value }))];
    },
    filteredTags() {
      const query = String(this.tableFilters.query || "").trim().toLowerCase();
      const proto = String(this.tableFilters.proto || "").trim().toLowerCase();
      const key = String(this.tableFilters.key || "").trim().toLowerCase();
      return this.tags.filter((item) => {
        if (proto && String(item.proto || "").trim().toLowerCase() !== proto) return false;
        if (key && String(item.key || "").trim().toLowerCase() !== key) return false;
        if (!query) return true;
        const haystack = [
          item.id,
          item.ip,
          item.port,
          item.proto,
          item.key,
          item.value,
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
      }, 350);
    },
    load() {
      this.loading = true;
      this.error = "";
      return this.store
        .fetchJsonPromise("/tags/")
        .then((res) => {
          this.tags = this.store.extractArray(res);
          this.lastUpdated = new Date().toLocaleTimeString();
        })
        .catch((err) => {
          this.tags = [];
          this.lastUpdated = "";
          this.error = err.message || "Failed to load tags";
        })
        .finally(() => {
          this.loading = false;
        });
    },
  },
};
</script>
