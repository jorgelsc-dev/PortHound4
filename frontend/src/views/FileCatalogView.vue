<template>
  <div>
    <ViewHeader
      overline="Seed Files"
      title="File-backed Catalog"
      description="Manage immutable catalog data stored in JSON files (seeded at startup)."
      :refresh-loading="loadingAny"
      @refresh="loadAll"
    />

    <v-tabs v-model="tab" color="primary" class="mb-4">
      <v-tab value="rules">Regex Rules File</v-tab>
      <v-tab value="requests">Banner Requests File</v-tab>
      <v-tab value="ips">IP Presets File</v-tab>
    </v-tabs>

    <DataPanel
      v-if="tab === 'rules'"
      title="Banner Regex Rules (File)"
      subtitle="Entries here are loaded from JSON files and remain immutable in the DB."
      :loading="loadingRules"
      :error="rulesError"
      :last-updated="lastUpdatedRules"
      @refresh="loadRules"
      class="mb-6"
    >
      <v-form @submit.prevent="submitRule">
        <v-row dense>
          <v-col cols="12" md="3">
            <v-text-field
              v-model.trim="ruleForm.rule_id"
              label="Rule ID"
              placeholder="custom_http_header"
              :disabled="loadingRules || savingRule"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="3">
            <v-text-field
              v-model.trim="ruleForm.label"
              label="Label"
              placeholder="Custom Header Detector"
              :disabled="loadingRules || savingRule"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="2">
            <v-text-field
              v-model.number="ruleForm.flags"
              label="Flags"
              type="number"
              min="0"
              :disabled="loadingRules || savingRule"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="2">
            <v-switch
              v-model="ruleForm.active"
              inset
              color="success"
              label="Active"
              :disabled="loadingRules || savingRule"
            />
          </v-col>
          <v-col cols="12" md="2" class="d-flex align-center">
            <v-btn
              color="primary"
              type="submit"
              :loading="savingRule"
              :disabled="loadingRules"
            >
              Add to File
            </v-btn>
          </v-col>
        </v-row>
        <v-row dense>
          <v-col cols="12" md="3">
            <v-text-field
              v-model.trim="ruleForm.category"
              label="Category"
              :disabled="loadingRules || savingRule"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="3">
            <v-text-field
              v-model.trim="ruleForm.service"
              label="Service"
              :disabled="loadingRules || savingRule"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="3">
            <v-text-field
              v-model.trim="ruleForm.protocol"
              label="Protocol"
              :disabled="loadingRules || savingRule"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="3">
            <v-text-field
              v-model.trim="ruleForm.product"
              label="Product"
              :disabled="loadingRules || savingRule"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
        </v-row>
        <v-textarea
          v-model="ruleForm.pattern"
          label="Regex Pattern"
          placeholder="^Server:\\s*MyServer(?:/(?P<version>[0-9.]+))?"
          rows="3"
          auto-grow
          :disabled="loadingRules || savingRule"
          variant="outlined"
          density="comfortable"
        />
      </v-form>
    </DataPanel>

    <EntityTablePanel
      v-if="tab === 'rules'"
      title="Rules in File"
      subtitle="File entries are immutable in the DB."
      :rows="filteredRules"
      :columns="ruleColumns"
      :loading="loadingRules"
      :error="rulesError"
      :last-updated="lastUpdatedRules"
      :live-refresh="true"
      empty-text="No regex rules found"
      @refresh="loadRules"
    >
      <template #cell-pattern="{ value }">
        <span class="mono-clamp">{{ value }}</span>
      </template>
    </EntityTablePanel>

    <DataPanel
      v-if="tab === 'requests'"
      title="Banner Probe Requests (File)"
      subtitle="Add new probe requests to the seed JSON file."
      :loading="loadingRequests"
      :error="requestsError"
      :last-updated="lastUpdatedRequests"
      @refresh="loadRequests"
      class="mb-6"
    >
      <v-form @submit.prevent="submitRequest">
        <v-row dense>
          <v-col cols="12" md="2">
            <v-select
              v-model="requestForm.proto"
              :items="requestProtoItems"
              label="Proto"
              :disabled="loadingRequests || savingRequest"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="3">
            <v-select
              v-model="requestForm.scope"
              :items="requestScopeItems"
              label="Scope"
              item-title="label"
              item-value="value"
              :disabled="loadingRequests || savingRequest"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="2">
            <v-text-field
              v-model.number="requestForm.port"
              label="Port"
              type="number"
              min="0"
              :disabled="loadingRequests || savingRequest || requestForm.scope !== 'port_override'"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="3">
            <v-text-field
              v-model.trim="requestForm.name"
              label="Name"
              placeholder="Custom TCP Probe"
              :disabled="loadingRequests || savingRequest"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="2">
            <v-switch
              v-model="requestForm.active"
              inset
              color="success"
              label="Active"
              :disabled="loadingRequests || savingRequest"
            />
          </v-col>
        </v-row>
        <v-row dense>
          <v-col cols="12" md="3">
            <v-select
              v-model="requestForm.payload_format"
              :items="payloadFormatItems"
              label="Payload format"
              :disabled="loadingRequests || savingRequest"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="9">
            <v-text-field
              v-model.trim="requestForm.description"
              label="Description"
              :disabled="loadingRequests || savingRequest"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
        </v-row>
        <v-textarea
          v-model="requestForm.payload_encoded"
          label="Payload"
          placeholder="Raw text, hex, or base64 depending on payload format"
          rows="3"
          auto-grow
          :disabled="loadingRequests || savingRequest"
          variant="outlined"
          density="comfortable"
        />
        <div class="row-actions mt-2">
          <v-btn color="primary" type="submit" :loading="savingRequest" :disabled="loadingRequests">
            Add to File
          </v-btn>
        </div>
      </v-form>
    </DataPanel>

    <EntityTablePanel
      v-if="tab === 'requests'"
      title="Requests in File"
      subtitle="File entries are immutable in the DB."
      :rows="filteredRequests"
      :columns="requestColumns"
      :loading="loadingRequests"
      :error="requestsError"
      :last-updated="lastUpdatedRequests"
      :live-refresh="true"
      empty-text="No banner requests found"
      @refresh="loadRequests"
    />

    <DataPanel
      v-if="tab === 'ips'"
      title="IP Presets (File)"
      subtitle="Add new IP presets to the seed JSON file."
      :loading="loadingIps"
      :error="ipsError"
      :last-updated="lastUpdatedIps"
      @refresh="loadIps"
      class="mb-6"
    >
      <v-form @submit.prevent="submitIp">
        <v-row dense>
          <v-col cols="12" md="4">
            <v-text-field
              v-model.trim="ipForm.value"
              label="IPv4 or CIDR"
              placeholder="10.0.0.0/24"
              :disabled="loadingIps || savingIp"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="3">
            <v-text-field
              v-model.trim="ipForm.label"
              label="Label"
              :disabled="loadingIps || savingIp"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="3">
            <v-text-field
              v-model.trim="ipForm.description"
              label="Description"
              :disabled="loadingIps || savingIp"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="2">
            <v-switch
              v-model="ipForm.active"
              inset
              color="success"
              label="Active"
              :disabled="loadingIps || savingIp"
            />
          </v-col>
        </v-row>
        <div class="row-actions mt-2">
          <v-btn color="primary" type="submit" :loading="savingIp" :disabled="loadingIps">
            Add to File
          </v-btn>
        </div>
      </v-form>
    </DataPanel>

    <EntityTablePanel
      v-if="tab === 'ips'"
      title="IP Presets in File"
      subtitle="File entries are immutable in the DB."
      :rows="filteredIps"
      :columns="ipColumns"
      :loading="loadingIps"
      :error="ipsError"
      :last-updated="lastUpdatedIps"
      :live-refresh="true"
      empty-text="No IP presets found"
      @refresh="loadIps"
    />
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import DataPanel from "../components/ui/DataPanel.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";

const defaultRuleForm = () => ({
  rule_id: "",
  label: "",
  pattern: "",
  flags: 0,
  category: "",
  service: "",
  protocol: "",
  product: "",
  active: true,
});

const defaultRequestForm = () => ({
  name: "",
  proto: "tcp",
  scope: "generic",
  port: 0,
  payload_format: "text",
  payload_encoded: "",
  description: "",
  active: true,
});

const defaultIpForm = () => ({
  value: "",
  label: "",
  description: "",
  active: true,
});

export default {
  name: "FileCatalogView",
  components: {
    ViewHeader,
    DataPanel,
    EntityTablePanel,
  },
  data() {
    return {
      store,
      tab: "rules",
      search: "",
      loadingRules: false,
      loadingRequests: false,
      loadingIps: false,
      savingRule: false,
      savingRequest: false,
      savingIp: false,
      rulesError: "",
      requestsError: "",
      ipsError: "",
      lastUpdatedRules: "",
      lastUpdatedRequests: "",
      lastUpdatedIps: "",
      rules: [],
      requests: [],
      ips: [],
      ruleForm: defaultRuleForm(),
      requestForm: defaultRequestForm(),
      ipForm: defaultIpForm(),
      ruleColumns: [
        { key: "id", label: "ID" },
        { key: "label", label: "Label" },
        { key: "pattern", label: "Pattern" },
        { key: "category", label: "Category" },
        { key: "service", label: "Service" },
        { key: "protocol", label: "Protocol" },
        { key: "active", label: "Active" },
      ],
      requestColumns: [
        { key: "request_key", label: "Key" },
        { key: "name", label: "Name" },
        { key: "proto", label: "Proto" },
        { key: "scope", label: "Scope" },
        { key: "port", label: "Port" },
        { key: "payload_format", label: "Format" },
        { key: "active", label: "Active" },
      ],
      ipColumns: [
        { key: "value", label: "Value" },
        { key: "label", label: "Label" },
        { key: "description", label: "Description" },
        { key: "active", label: "Active" },
      ],
    };
  },
  computed: {
    loadingAny() {
      return this.loadingRules || this.loadingRequests || this.loadingIps;
    },
    requestProtoItems() {
      return ["tcp", "udp"];
    },
    payloadFormatItems() {
      return ["text", "hex", "base64"];
    },
    requestScopeItems() {
      return this.requestForm.proto === "udp"
        ? [
            { label: "Generic", value: "generic" },
            { label: "Port Override", value: "port_override" },
          ]
        : [
            { label: "Generic", value: "generic" },
            { label: "HTTP", value: "http" },
            { label: "Port Override", value: "port_override" },
          ];
    },
    filteredRules() {
      const q = String(this.search || "").trim().toLowerCase();
      if (!q) return this.rules;
      return this.rules.filter((item) => {
        const text = [item.id, item.label, item.pattern, item.category, item.service, item.protocol]
          .map((value) => String(value == null ? "" : value).toLowerCase())
          .join(" ");
        return text.includes(q);
      });
    },
    filteredRequests() {
      const q = String(this.search || "").trim().toLowerCase();
      if (!q) return this.requests;
      return this.requests.filter((item) => {
        const text = [item.request_key, item.name, item.proto, item.scope, item.port, item.payload_format]
          .map((value) => String(value == null ? "" : value).toLowerCase())
          .join(" ");
        return text.includes(q);
      });
    },
    filteredIps() {
      const q = String(this.search || "").trim().toLowerCase();
      if (!q) return this.ips;
      return this.ips.filter((item) => {
        const text = [item.value, item.label, item.description]
          .map((value) => String(value == null ? "" : value).toLowerCase())
          .join(" ");
        return text.includes(q);
      });
    },
  },
  mounted() {
    this.loadAll();
  },
  methods: {
    loadAll() {
      return Promise.all([this.loadRules(), this.loadRequests(), this.loadIps()]);
    },
    loadRules() {
      this.loadingRules = true;
      this.rulesError = "";
      return this.store.fetchJsonPromise("/api/catalog/file/banner-rules")
        .then((payload) => {
          this.rules = this.store.extractArray(payload);
          this.lastUpdatedRules = new Date().toLocaleTimeString();
        })
        .catch((err) => {
          this.rulesError = err.message || "Failed to load file rules";
          this.lastUpdatedRules = "";
        })
        .finally(() => {
          this.loadingRules = false;
        });
    },
    loadRequests() {
      this.loadingRequests = true;
      this.requestsError = "";
      return this.store.fetchJsonPromise("/api/catalog/file/banner-requests")
        .then((payload) => {
          this.requests = this.store.extractArray(payload);
          this.lastUpdatedRequests = new Date().toLocaleTimeString();
        })
        .catch((err) => {
          this.requestsError = err.message || "Failed to load file requests";
          this.lastUpdatedRequests = "";
        })
        .finally(() => {
          this.loadingRequests = false;
        });
    },
    loadIps() {
      this.loadingIps = true;
      this.ipsError = "";
      return this.store.fetchJsonPromise("/api/catalog/file/ip-presets")
        .then((payload) => {
          this.ips = this.store.extractArray(payload);
          this.lastUpdatedIps = new Date().toLocaleTimeString();
        })
        .catch((err) => {
          this.ipsError = err.message || "Failed to load file IP presets";
          this.lastUpdatedIps = "";
        })
        .finally(() => {
          this.loadingIps = false;
        });
    },
    submitRule() {
      this.savingRule = true;
      this.rulesError = "";
      const payload = {
        rule_id: this.ruleForm.rule_id,
        label: this.ruleForm.label,
        pattern: this.ruleForm.pattern,
        flags: Number(this.ruleForm.flags || 0),
        category: this.ruleForm.category,
        service: this.ruleForm.service,
        protocol: this.ruleForm.protocol,
        product: this.ruleForm.product,
        active: Boolean(this.ruleForm.active),
      };
      return this.store.fetchJsonPromise("/api/catalog/file/banner-rules", {
        method: "POST",
        body: JSON.stringify(payload),
      })
        .then(() => {
          this.ruleForm = defaultRuleForm();
          return this.loadRules();
        })
        .catch((err) => {
          this.rulesError = err.message || "Failed to append rule";
        })
        .finally(() => {
          this.savingRule = false;
        });
    },
    submitRequest() {
      this.savingRequest = true;
      this.requestsError = "";
      const payload = {
        name: this.requestForm.name,
        proto: this.requestForm.proto,
        scope: this.requestForm.scope,
        port: Number(this.requestForm.scope === "port_override" ? this.requestForm.port : 0),
        payload_format: this.requestForm.payload_format,
        payload_encoded: this.requestForm.payload_encoded,
        description: this.requestForm.description,
        active: Boolean(this.requestForm.active),
      };
      return this.store.fetchJsonPromise("/api/catalog/file/banner-requests", {
        method: "POST",
        body: JSON.stringify(payload),
      })
        .then(() => {
          this.requestForm = defaultRequestForm();
          return this.loadRequests();
        })
        .catch((err) => {
          this.requestsError = err.message || "Failed to append request";
        })
        .finally(() => {
          this.savingRequest = false;
        });
    },
    submitIp() {
      this.savingIp = true;
      this.ipsError = "";
      const payload = {
        value: this.ipForm.value,
        label: this.ipForm.label,
        description: this.ipForm.description,
        active: Boolean(this.ipForm.active),
      };
      return this.store.fetchJsonPromise("/api/catalog/file/ip-presets", {
        method: "POST",
        body: JSON.stringify(payload),
      })
        .then(() => {
          this.ipForm = defaultIpForm();
          return this.loadIps();
        })
        .catch((err) => {
          this.ipsError = err.message || "Failed to append IP preset";
        })
        .finally(() => {
          this.savingIp = false;
        });
    },
  },
};
</script>

<style scoped>
.row-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.mono-clamp {
  display: inline-block;
  max-width: 560px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  font-family: "IBM Plex Mono", "Fira Code", "JetBrains Mono", monospace;
  font-size: 0.82rem;
}

@media (max-width: 960px) {
  .mono-clamp {
    max-width: 250px;
  }
}
</style>
