<template>
  <v-sheet class="hero-banner" rounded="xl">
    <v-row align="center" class="pa-6 pa-md-8">
      <v-col cols="12" md="7">
        <div class="text-overline text-primary">Network intelligence</div>
        <div class="text-h4 text-md-h3 font-weight-bold">PortHound Recon Console</div>
        <div class="text-body-1 text-medium-emphasis mt-2">
          Operational view for discovering hosts, services, and banners with
          continuous flow and precise target control.
        </div>
        <div class="d-flex flex-wrap ga-3 mt-4">
          <v-btn color="primary" variant="flat" to="/targets">Create Target</v-btn>
          <v-btn color="success" variant="outlined" to="/map">Open Atlas</v-btn>
          <v-btn color="info" variant="outlined" to="/explorer">Open Explorer</v-btn>
          <v-btn color="secondary" variant="text" to="/api">API Docs</v-btn>
        </div>
        <v-alert
          class="usage-notice mt-5"
          type="warning"
          variant="tonal"
          density="comfortable"
          icon="mdi-shield-check-outline"
        >
          Authorized use only. Run PortHound exclusively against systems, networks, and IP ranges
          for which you have explicit permission. Operators are responsible for complying with
          national regulations and the laws and rules of every country involved in the activity.
        </v-alert>
      </v-col>
      <v-col cols="12" md="5">
        <v-card variant="tonal" color="surface" class="pa-5 api-card">
          <div class="text-subtitle-2 font-weight-medium">Direct Access</div>
          <div class="text-caption text-medium-emphasis">
            Open the active PortHound endpoint directly from here.
          </div>
          <div class="text-body-2 font-weight-medium mt-4 direct-link-value">
            {{ appLinkLabel }}
          </div>
          <div class="d-flex flex-wrap ga-2 mt-4">
            <v-btn
              color="primary"
              variant="flat"
              :href="appLink"
              target="_blank"
              rel="noopener noreferrer"
            >
              Open Live App
            </v-btn>
          </div>
        </v-card>
      </v-col>
    </v-row>
  </v-sheet>
</template>

<script>
export default {
  name: "AppHero",
  props: {
    apiBaseDraft: {
      type: String,
      default: "",
    },
    apiBaseLabel: {
      type: String,
      default: "",
    },
  },
  emits: ["update:api-base-draft", "save-api-base", "reset-api-base"],
  computed: {
    appLink() {
      const value = String(this.apiBaseLabel || "").trim();
      return value || "/";
    },
    appLinkLabel() {
      const value = String(this.appLink || "").trim();
      return value || "/";
    },
  },
};
</script>

<style scoped>
.hero-banner {
  position: relative;
  overflow: hidden;
  background: radial-gradient(
      110% 140% at -8% -24%,
      rgba(53, 196, 237, 0.24),
      transparent 58%
    ),
    radial-gradient(
      90% 110% at 110% -30%,
      rgba(244, 176, 79, 0.18),
      transparent 63%
    ),
    linear-gradient(122deg, rgba(13, 21, 32, 0.98), rgba(8, 14, 23, 0.98));
  border: 1px solid rgba(88, 176, 224, 0.26);
  box-shadow: 0 26px 50px rgba(3, 7, 14, 0.42), inset 0 0 0 1px rgba(255, 255, 255, 0.03);
}

.hero-banner::before {
  content: "";
  position: absolute;
  left: -8%;
  right: -8%;
  bottom: -80px;
  height: 220px;
  background: radial-gradient(
    60% 100% at 50% 100%,
    rgba(90, 182, 228, 0.2),
    rgba(90, 182, 228, 0)
  );
  pointer-events: none;
}

.api-card {
  border: 1px solid rgba(118, 191, 232, 0.24);
  background: linear-gradient(180deg, rgba(16, 26, 39, 0.9), rgba(11, 18, 28, 0.82));
  box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.03);
}

.usage-notice {
  border: 1px solid rgba(255, 196, 118, 0.18);
  background: linear-gradient(180deg, rgba(38, 26, 14, 0.74), rgba(26, 20, 12, 0.54)) !important;
}

.direct-link-value {
  padding: 0.9rem 1rem;
  border-radius: 14px;
  border: 1px solid rgba(118, 191, 232, 0.18);
  background: rgba(12, 21, 34, 0.72);
  color: rgba(202, 230, 255, 0.96);
  word-break: break-all;
 }

.hero-banner :deep(.v-btn) {
  letter-spacing: 0.04em;
}
</style>
