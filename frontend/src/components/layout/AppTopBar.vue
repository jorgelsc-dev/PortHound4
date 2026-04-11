<template>
  <v-app-bar color="transparent" flat height="74" class="top-bar">
    <v-container class="d-flex align-center app-topbar">
      <v-btn
        icon="mdi-menu"
        variant="text"
        class="d-md-none"
        aria-label="Open navigation menu"
        @click="$emit('open-drawer')"
      />
      <v-avatar size="44" class="mr-3">
        <v-img :src="brandIconSrc" alt="PortHound" />
      </v-avatar>
      <div>
        <div class="text-subtitle-1 font-weight-bold">PortHound</div>
        <div class="text-caption text-medium-emphasis">Network Scanner &amp; Banner Intel</div>
      </div>

      <v-spacer />

      <v-tabs
        class="d-none d-md-flex top-tabs"
        color="primary"
        density="compact"
        align-with-title
      >
        <v-tab
          v-for="item in navItems"
          :key="item.to"
          :to="item.to"
          :exact="item.to === '/'"
        >
          {{ item.label }}
        </v-tab>
      </v-tabs>

      <v-spacer />

      <v-btn
        class="d-none d-lg-flex mr-2"
        color="warning"
        variant="outlined"
        size="small"
        prepend-icon="mdi-currency-btc"
        :href="btcSupportLink"
        target="_blank"
        rel="noopener noreferrer"
      >
        Support BTC
      </v-btn>
      <v-chip
        class="mr-2"
        :color="wsStateColor"
        variant="tonal"
        size="small"
        prepend-icon="mdi-access-point"
      >
        {{ wsStateLabel }}
      </v-chip>
      <v-chip
        v-if="compactApiBase"
        class="d-none d-lg-flex"
        variant="outlined"
        size="small"
        prepend-icon="mdi-link-variant"
      >
        {{ compactApiBase }}
      </v-chip>
    </v-container>
  </v-app-bar>
</template>

<script>
export default {
  name: "AppTopBar",
  props: {
    navItems: {
      type: Array,
      default: () => [],
    },
    apiBaseLabel: {
      type: String,
      default: "",
    },
    wsStatus: {
      type: String,
      default: "offline",
    },
  },
  emits: ["open-drawer"],
  computed: {
    wsStateLabel() {
      const value = String(this.wsStatus || "").trim().toLowerCase();
      if (value === "online") return "WS Online";
      if (value === "connecting") return "WS Connecting";
      if (value === "error") return "WS Error";
      return "WS Offline";
    },
    wsStateColor() {
      const value = String(this.wsStatus || "").trim().toLowerCase();
      if (value === "online") return "success";
      if (value === "connecting") return "info";
      if (value === "error") return "error";
      return "warning";
    },
    compactApiBase() {
      const raw = String(this.apiBaseLabel || "").trim();
      if (!raw) return "";
      try {
        const parsed = new URL(raw);
        return `${parsed.protocol}//${parsed.host}`;
      } catch (err) {
        return raw;
      }
    },
    btcSupportLink() {
      return "https://mempool.space/address/bc1q3lhxpr9yantvefmvhpd2h4lu0ykf3t45zvuve2";
    },
    brandIconSrc() {
      const base = (typeof process !== "undefined" && process.env && process.env.BASE_URL)
        ? process.env.BASE_URL
        : "/";
      return `${String(base).replace(/\/?$/, "/")}brand-icon.png`;
    },
  },
};
</script>

<style scoped>
.top-bar {
  border-bottom: 1px solid rgba(97, 176, 221, 0.2);
  backdrop-filter: blur(16px);
  background: linear-gradient(
    180deg,
    rgba(10, 16, 27, 0.93) 0%,
    rgba(10, 16, 27, 0.72) 72%,
    rgba(10, 16, 27, 0.2) 100%
  );
}

.app-topbar {
  max-width: 1560px;
  width: 100%;
}

.top-tabs :deep(.v-tab) {
  min-width: 72px;
  font-weight: 600;
  letter-spacing: 0.04em;
}
</style>
