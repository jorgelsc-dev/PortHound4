<template>
  <div>
    <ViewHeader
      overline="Catalog"
      title="Scanner Catalog Manager"
      description="Manage regex extraction rules, banner probe requests, and IP presets."
      :refresh-loading="loadingAny"
      @refresh="loadAll"
    />

    <v-tabs v-model="tab" color="primary" class="mb-4">
      <v-tab value="rules">Regex Rules</v-tab>
      <v-tab value="requests">Banner Requests</v-tab>
      <v-tab value="ips">IP Presets</v-tab>
    </v-tabs>

    <DataPanel
      v-if="tab === 'rules'"
      title="Banner Regex Rules"
      subtitle="Built-in rules are read-only. Custom rules can be edited and deleted."
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
          <v-col cols="12" md="2" class="d-flex align-center ga-2">
            <v-btn
              color="primary"
              type="submit"
              :loading="savingRule"
              :disabled="loadingRules"
            >
              {{ ruleForm.id ? "Update" : "Add" }}
            </v-btn>
            <v-btn
              v-if="ruleForm.id"
              variant="text"
              color="warning"
              :disabled="loadingRules || savingRule"
              @click="resetRuleForm"
            >
              Cancel
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
      title="Regex Rules"
      subtitle="Entries loaded from file are immutable."
      :rows="filteredRules"
      :columns="ruleColumns"
      :loading="loadingRules"
      :error="rulesError"
      :last-updated="lastUpdatedRules"
      empty-text="No regex rules found"
      @refresh="loadRules"
    >
      <template #cell-source="{ item }">
        <v-chip size="x-small" :color="item.mutable ? 'primary' : 'grey'" variant="tonal">
          {{ item.source || (item.mutable ? "user" : "builtin") }}
        </v-chip>
      </template>
      <template #cell-active="{ value }">
        <v-chip size="x-small" :color="value ? 'success' : 'warning'" variant="tonal">
          {{ value ? "yes" : "no" }}
        </v-chip>
      </template>
      <template #cell-pattern="{ value }">
        <span class="mono-clamp">{{ value }}</span>
      </template>
      <template #cell-actions="{ item }">
        <div class="row-actions">
          <v-btn
            size="x-small"
            color="info"
            variant="tonal"
            :disabled="!item.mutable || loadingRules || savingRule"
            @click="startEditRule(item)"
          >
            Edit
          </v-btn>
          <v-btn
            size="x-small"
            color="error"
            variant="tonal"
            :disabled="!item.mutable || loadingRules || savingRule"
            @click="deleteRule(item)"
          >
            Delete
          </v-btn>
        </div>
      </template>
    </EntityTablePanel>

    <DataPanel
      v-if="tab === 'requests'"
      title="Banner Probe Requests"
      subtitle="Manage TCP/UDP requests used by banner workers."
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
              max="65535"
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
          rows="4"
          auto-grow
          :disabled="loadingRequests || savingRequest"
          variant="outlined"
          density="comfortable"
        />
        <div class="d-flex align-center ga-2">
          <v-btn
            color="primary"
            type="submit"
            :loading="savingRequest"
            :disabled="loadingRequests"
          >
            {{ requestForm.id ? "Update" : "Add" }}
          </v-btn>
          <v-btn
            v-if="requestForm.id"
            variant="text"
            color="warning"
            :disabled="loadingRequests || savingRequest"
            @click="resetRequestForm"
          >
            Cancel
          </v-btn>
        </div>
      </v-form>
    </DataPanel>

    <EntityTablePanel
      v-if="tab === 'requests'"
      title="Banner Requests"
      subtitle="Custom requests are immediately used by new banner workers."
      :rows="filteredRequests"
      :columns="requestColumns"
      :loading="loadingRequests"
      :error="requestsError"
      :last-updated="lastUpdatedRequests"
      empty-text="No banner requests found"
      @refresh="loadRequests"
    >
      <template #cell-source="{ item }">
        <v-chip size="x-small" :color="item.mutable ? 'primary' : 'grey'" variant="tonal">
          {{ item.source || (item.mutable ? "user" : "builtin") }}
        </v-chip>
      </template>
      <template #cell-active="{ value }">
        <v-chip size="x-small" :color="value ? 'success' : 'warning'" variant="tonal">
          {{ value ? "yes" : "no" }}
        </v-chip>
      </template>
      <template #cell-payload_preview="{ value }">
        <span class="mono-clamp">{{ value }}</span>
      </template>
      <template #cell-actions="{ item }">
        <div class="row-actions">
          <v-btn
            size="x-small"
            color="info"
            variant="tonal"
            :disabled="!item.mutable || loadingRequests || savingRequest"
            @click="startEditRequest(item)"
          >
            Edit
          </v-btn>
          <v-btn
            size="x-small"
            color="error"
            variant="tonal"
            :disabled="!item.mutable || loadingRequests || savingRequest"
            @click="deleteRequest(item)"
          >
            Delete
          </v-btn>
        </div>
      </template>
    </EntityTablePanel>

    <DataPanel
      v-if="tab === 'ips'"
      title="IP Presets"
      subtitle="Store reusable IPv4 or CIDR values."
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
        <div class="d-flex align-center ga-2">
          <v-btn
            color="primary"
            type="submit"
            :loading="savingIp"
            :disabled="loadingIps"
          >
            {{ ipForm.id ? "Update" : "Add" }}
          </v-btn>
          <v-btn
            v-if="ipForm.id"
            variant="text"
            color="warning"
            :disabled="loadingIps || savingIp"
            @click="resetIpForm"
          >
            Cancel
          </v-btn>
        </div>
      </v-form>
    </DataPanel>

    <EntityTablePanel
      v-if="tab === 'ips'"
      title="IP Presets"
      subtitle="Built-in presets are read-only."
      :rows="filteredIps"
      :columns="ipColumns"
      :loading="loadingIps"
      :error="ipsError"
      :last-updated="lastUpdatedIps"
      empty-text="No IP presets found"
      @refresh="loadIps"
    >
      <template #cell-source="{ item }">
        <v-chip size="x-small" :color="item.mutable ? 'primary' : 'grey'" variant="tonal">
          {{ item.source || (item.mutable ? "user" : "builtin") }}
        </v-chip>
      </template>
      <template #cell-active="{ value }">
        <v-chip size="x-small" :color="value ? 'success' : 'warning'" variant="tonal">
          {{ value ? "yes" : "no" }}
        </v-chip>
      </template>
      <template #cell-actions="{ item }">
        <div class="row-actions">
          <v-btn
            size="x-small"
            color="info"
            variant="tonal"
            :disabled="!item.mutable || loadingIps || savingIp"
            @click="startEditIp(item)"
          >
            Edit
          </v-btn>
          <v-btn
            size="x-small"
            color="error"
            variant="tonal"
            :disabled="!item.mutable || loadingIps || savingIp"
            @click="deleteIp(item)"
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

function defaultRuleForm() {
  return {
    id: null,
    rule_id: "",
    label: "",
    pattern: "",
    flags: 0,
    category: "",
    service: "",
    protocol: "",
    product: "",
    active: true,
  };
}

function defaultRequestForm() {
  return {
    id: null,
    name: "",
    proto: "tcp",
    scope: "generic",
    port: 0,
    payload_format: "text",
    payload_encoded: "",
    description: "",
    active: true,
  };
}

function defaultIpForm() {
  return {
    id: null,
    value: "",
    label: "",
    description: "",
    active: true,
  };
}

export default {
  name: "CatalogView",
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
        { key: "rule_id", label: "Rule ID" },
        { key: "label", label: "Label" },
        { key: "pattern", label: "Pattern" },
        { key: "source", label: "Source" },
        { key: "active", label: "Active" },
        { key: "actions", label: "Actions" },
      ],
      requestColumns: [
        { key: "id", label: "ID" },
        { key: "proto", label: "Proto" },
        { key: "scope", label: "Scope" },
        { key: "port", label: "Port" },
        { key: "name", label: "Name" },
        { key: "payload_preview", label: "Payload Preview" },
        { key: "source", label: "Source" },
        { key: "active", label: "Active" },
        { key: "actions", label: "Actions" },
      ],
      ipColumns: [
        { key: "id", label: "ID" },
        { key: "value", label: "Value" },
        { key: "label", label: "Label" },
        { key: "description", label: "Description" },
        { key: "source", label: "Source" },
        { key: "active", label: "Active" },
        { key: "actions", label: "Actions" },
      ],
      requestProtoItems: ["tcp", "udp"],
      payloadFormatItems: ["text", "hex", "base64"],
    };
  },
  computed: {
    apiBase() {
      return this.store.state.apiBase;
    },
    loadingAny() {
      return this.loadingRules || this.loadingRequests || this.loadingIps;
    },
    requestScopeItems() {
      if (this.requestForm.proto === "udp") {
        return [
          { label: "Generic", value: "generic" },
          { label: "Port Override", value: "port_override" },
        ];
      }
      return [
        { label: "Generic", value: "generic" },
        { label: "HTTP", value: "http" },
        { label: "Port Override", value: "port_override" },
      ];
    },
    filteredRules() {
      const q = String(this.search || "").trim().toLowerCase();
      if (!q) return this.rules;
      return this.rules.filter((item) => {
        const text = [
          item.id,
          item.rule_id,
          item.label,
          item.pattern,
          item.category,
          item.service,
          item.protocol,
          item.product,
          item.source,
        ]
          .map((value) => String(value == null ? "" : value).toLowerCase())
          .join(" ");
        return text.includes(q);
      });
    },
    filteredRequests() {
      const q = String(this.search || "").trim().toLowerCase();
      if (!q) return this.requests;
      return this.requests.filter((item) => {
        const text = [
          item.id,
          item.name,
          item.proto,
          item.scope,
          item.port,
          item.payload_preview,
          item.description,
          item.source,
        ]
          .map((value) => String(value == null ? "" : value).toLowerCase())
          .join(" ");
        return text.includes(q);
      });
    },
    filteredIps() {
      const q = String(this.search || "").trim().toLowerCase();
      if (!q) return this.ips;
      return this.ips.filter((item) => {
        const text = [
          item.id,
          item.value,
          item.label,
          item.description,
          item.source,
        ]
          .map((value) => String(value == null ? "" : value).toLowerCase())
          .join(" ");
        return text.includes(q);
      });
    },
  },
  watch: {
    apiBase() {
      this.loadAll();
    },
    "requestForm.proto"(value) {
      if (value === "udp" && this.requestForm.scope === "http") {
        this.requestForm.scope = "generic";
      }
    },
    "requestForm.scope"(value) {
      if (value !== "port_override") {
        this.requestForm.port = 0;
      }
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
      return this.store.fetchJsonPromise("/api/catalog/banner-rules/")
        .then((payload) => {
          this.rules = this.store.extractArray(payload);
          this.lastUpdatedRules = new Date().toLocaleTimeString();
        })
        .catch((err) => {
          this.rulesError = err.message || "Failed to load regex rules";
          this.lastUpdatedRules = "";
        })
        .finally(() => {
          this.loadingRules = false;
        });
    },
    loadRequests() {
      this.loadingRequests = true;
      this.requestsError = "";
      return this.store.fetchJsonPromise("/api/catalog/banner-requests/")
        .then((payload) => {
          this.requests = this.store.extractArray(payload);
          this.lastUpdatedRequests = new Date().toLocaleTimeString();
        })
        .catch((err) => {
          this.requestsError = err.message || "Failed to load banner requests";
          this.lastUpdatedRequests = "";
        })
        .finally(() => {
          this.loadingRequests = false;
        });
    },
    loadIps() {
      this.loadingIps = true;
      this.ipsError = "";
      return this.store.fetchJsonPromise("/api/catalog/ip-presets/")
        .then((payload) => {
          this.ips = this.store.extractArray(payload);
          this.lastUpdatedIps = new Date().toLocaleTimeString();
        })
        .catch((err) => {
          this.ipsError = err.message || "Failed to load IP presets";
          this.lastUpdatedIps = "";
        })
        .finally(() => {
          this.loadingIps = false;
        });
    },
    resetRuleForm() {
      this.ruleForm = defaultRuleForm();
    },
    startEditRule(item) {
      if (!item || !item.mutable) return;
      this.ruleForm = {
        id: item.id,
        rule_id: item.rule_id || "",
        label: item.label || "",
        pattern: item.pattern || "",
        flags: Number(item.flags || 0),
        category: item.category || "",
        service: item.service || "",
        protocol: item.protocol || "",
        product: item.product || "",
        active: Boolean(item.active),
      };
      this.tab = "rules";
    },
    submitRule() {
      this.savingRule = true;
      this.rulesError = "";
      const method = this.ruleForm.id ? "PUT" : "POST";
      const payload = {
        id: this.ruleForm.id,
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
      return this.store.fetchJsonPromise("/api/catalog/banner-rules/", {
        method,
        body: JSON.stringify(payload),
      })
        .then(() => {
          this.resetRuleForm();
          return this.loadRules();
        })
        .catch((err) => {
          this.rulesError = err.message || "Failed to save regex rule";
        })
        .finally(() => {
          this.savingRule = false;
        });
    },
    deleteRule(item) {
      if (!item || !item.mutable) return;
      if (!window.confirm(`Delete rule ${item.rule_id || item.id}?`)) return;
      this.savingRule = true;
      this.rulesError = "";
      return this.store.fetchJsonPromise("/api/catalog/banner-rules/", {
        method: "DELETE",
        body: JSON.stringify({ id: item.id }),
      })
        .then(() => {
          if (this.ruleForm.id === item.id) this.resetRuleForm();
          return this.loadRules();
        })
        .catch((err) => {
          this.rulesError = err.message || "Failed to delete regex rule";
        })
        .finally(() => {
          this.savingRule = false;
        });
    },
    resetRequestForm() {
      this.requestForm = defaultRequestForm();
    },
    startEditRequest(item) {
      if (!item || !item.mutable) return;
      this.requestForm = {
        id: item.id,
        name: item.name || "",
        proto: item.proto || "tcp",
        scope: item.scope || "generic",
        port: Number(item.port || 0),
        payload_format: item.payload_format || "text",
        payload_encoded: item.payload_encoded || "",
        description: item.description || "",
        active: Boolean(item.active),
      };
      this.tab = "requests";
    },
    submitRequest() {
      this.savingRequest = true;
      this.requestsError = "";
      const method = this.requestForm.id ? "PUT" : "POST";
      const payload = {
        id: this.requestForm.id,
        name: this.requestForm.name,
        proto: this.requestForm.proto,
        scope: this.requestForm.scope,
        port: Number(this.requestForm.scope === "port_override" ? this.requestForm.port : 0),
        payload_format: this.requestForm.payload_format,
        payload_encoded: this.requestForm.payload_encoded,
        description: this.requestForm.description,
        active: Boolean(this.requestForm.active),
      };
      return this.store.fetchJsonPromise("/api/catalog/banner-requests/", {
        method,
        body: JSON.stringify(payload),
      })
        .then(() => {
          this.resetRequestForm();
          return this.loadRequests();
        })
        .catch((err) => {
          this.requestsError = err.message || "Failed to save banner request";
        })
        .finally(() => {
          this.savingRequest = false;
        });
    },
    deleteRequest(item) {
      if (!item || !item.mutable) return;
      if (!window.confirm(`Delete request ${item.name || item.id}?`)) return;
      this.savingRequest = true;
      this.requestsError = "";
      return this.store.fetchJsonPromise("/api/catalog/banner-requests/", {
        method: "DELETE",
        body: JSON.stringify({ id: item.id }),
      })
        .then(() => {
          if (this.requestForm.id === item.id) this.resetRequestForm();
          return this.loadRequests();
        })
        .catch((err) => {
          this.requestsError = err.message || "Failed to delete banner request";
        })
        .finally(() => {
          this.savingRequest = false;
        });
    },
    resetIpForm() {
      this.ipForm = defaultIpForm();
    },
    startEditIp(item) {
      if (!item || !item.mutable) return;
      this.ipForm = {
        id: item.id,
        value: item.value || "",
        label: item.label || "",
        description: item.description || "",
        active: Boolean(item.active),
      };
      this.tab = "ips";
    },
    submitIp() {
      this.savingIp = true;
      this.ipsError = "";
      const method = this.ipForm.id ? "PUT" : "POST";
      const payload = {
        id: this.ipForm.id,
        value: this.ipForm.value,
        label: this.ipForm.label,
        description: this.ipForm.description,
        active: Boolean(this.ipForm.active),
      };
      return this.store.fetchJsonPromise("/api/catalog/ip-presets/", {
        method,
        body: JSON.stringify(payload),
      })
        .then(() => {
          this.resetIpForm();
          return this.loadIps();
        })
        .catch((err) => {
          this.ipsError = err.message || "Failed to save IP preset";
        })
        .finally(() => {
          this.savingIp = false;
        });
    },
    deleteIp(item) {
      if (!item || !item.mutable) return;
      if (!window.confirm(`Delete IP preset ${item.value}?`)) return;
      this.savingIp = true;
      this.ipsError = "";
      return this.store.fetchJsonPromise("/api/catalog/ip-presets/", {
        method: "DELETE",
        body: JSON.stringify({ id: item.id }),
      })
        .then(() => {
          if (this.ipForm.id === item.id) this.resetIpForm();
          return this.loadIps();
        })
        .catch((err) => {
          this.ipsError = err.message || "Failed to delete IP preset";
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
  gap: 6px;
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
