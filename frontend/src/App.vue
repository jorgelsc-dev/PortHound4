<template>
  <v-app class="porthound-app">
    <AppSidebar
      :open="drawer"
      :nav-items="navItems"
      @update:open="drawer = $event"
    />

    <AppTopBar
      :nav-items="navItems"
      :api-base-label="apiBaseLabel"
      :ws-status="wsStatus"
      @open-drawer="drawer = true"
    />

    <v-main class="app-main" :class="{ 'app-main--map': isMapRoute }">
      <v-container :fluid="isMapRoute" class="app-container" :class="{ 'app-container--map': isMapRoute }">
        <AppHero
          v-if="showHero"
          :api-base-draft="apiBaseDraft"
          :api-base-label="apiBaseLabel"
          @update:api-base-draft="apiBaseDraft = $event"
          @save-api-base="applyApiBase"
          @reset-api-base="resetApiBase"
        />

        <div :class="showHero ? 'mt-8' : isMapRoute ? 'mt-0' : 'mt-3'">
          <router-view v-slot="{ Component }">
            <transition name="view-fade" mode="out-in">
              <component :is="Component" />
            </transition>
          </router-view>
        </div>
      </v-container>
    </v-main>
  </v-app>
</template>

<script>
import store from "./state/appStore";
import AppSidebar from "./components/layout/AppSidebar.vue";
import AppTopBar from "./components/layout/AppTopBar.vue";
import AppHero from "./components/layout/AppHero.vue";

export default {
  name: "App",
  components: {
    AppSidebar,
    AppTopBar,
    AppHero,
  },
  data() {
    return {
      store,
      drawer: false,
      apiBaseDraft: store.state.apiBase,
      navItems: [
        { label: "Dashboard", to: "/", icon: "mdi-view-dashboard" },
        { label: "Charts", to: "/charts", icon: "mdi-chart-box-outline" },
        { label: "Map", to: "/map", icon: "mdi-earth" },
        { label: "Explorer", to: "/explorer", icon: "mdi-magnify-expand" },
        { label: "Agents", to: "/agents", icon: "mdi-server-network" },
        { label: "Targets", to: "/targets", icon: "mdi-target" },
        { label: "Ports", to: "/ports", icon: "mdi-ethernet" },
        { label: "Banners", to: "/banners", icon: "mdi-card-text" },
        { label: "Tags", to: "/tags", icon: "mdi-tag-outline" },
        { label: "Catalog", to: "/catalog", icon: "mdi-database-edit-outline" },
        { label: "Seed Files", to: "/catalog-files", icon: "mdi-file-cog-outline" },
        { label: "API", to: "/api", icon: "mdi-api" },
      ],
    };
  },
  computed: {
    apiBaseLabel() {
      return this.store.state.apiBase || "";
    },
    wsStatus() {
      return this.store.state.wsStatus || "offline";
    },
    showHero() {
      const name = String((this.$route && this.$route.name) || "").toLowerCase();
      return name === "dashboard" || name === "explorer";
    },
    isMapRoute() {
      const name = String((this.$route && this.$route.name) || "").toLowerCase();
      return name === "map";
    },
  },
  watch: {
    "store.state.apiBase"(value) {
      this.apiBaseDraft = value;
    },
  },
  methods: {
    applyApiBase() {
      this.store.setApiBase(this.apiBaseDraft);
    },
    resetApiBase() {
      this.apiBaseDraft = this.store.suggestApiBaseFromLocation();
      this.store.setApiBase(this.apiBaseDraft);
    },
  },
};
</script>

<style scoped>
.app-container {
  max-width: 1560px;
  width: 100%;
}

.app-container--map {
  max-width: none;
  padding-left: 10px;
  padding-right: 10px;
}

.app-main {
  padding-bottom: 40px;
}

.app-main--map {
  padding-bottom: 12px;
}

.view-fade-enter-active,
.view-fade-leave-active {
  transition: opacity 0.2s ease, transform 0.22s ease;
}

.view-fade-enter-from,
.view-fade-leave-to {
  opacity: 0;
  transform: translateY(6px);
}

@media (max-width: 959px) {
  .app-main {
    padding-bottom: 24px;
  }

  .app-container--map {
    padding-left: 6px;
    padding-right: 6px;
  }
}
</style>
