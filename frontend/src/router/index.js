import { createRouter, createWebHistory } from "vue-router";

import DashboardView from "../views/DashboardView.vue";
import MapWorldView from "../views/MapWorldView.vue";
import ExplorerView from "../views/ExplorerView.vue";
import AgentsView from "../views/AgentsView.vue";
import TargetsView from "../views/TargetsView.vue";
import PortsView from "../views/PortsView.vue";
import BannersView from "../views/BannersView.vue";
import TagsView from "../views/TagsView.vue";
import ApiView from "../views/ApiView.vue";

const routes = [
  { path: "/", name: "dashboard", component: DashboardView },
  { path: "/map", name: "map", component: MapWorldView },
  { path: "/explorer", name: "explorer", component: ExplorerView },
  { path: "/agents", name: "agents", component: AgentsView },
  { path: "/targets", name: "targets", component: TargetsView },
  { path: "/ports", name: "ports", component: PortsView },
  { path: "/banners", name: "banners", component: BannersView },
  { path: "/tags", name: "tags", component: TagsView },
  { path: "/api", name: "api", component: ApiView },
];

const router = createRouter({
  history: createWebHistory(process.env.BASE_URL || "/"),
  routes,
  scrollBehavior() {
    return { left: 0, top: 0 };
  },
});

export default router;
