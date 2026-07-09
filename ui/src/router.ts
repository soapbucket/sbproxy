import { createRouter, createWebHistory } from "vue-router";

const routes = [
  {
    path: "/",
    name: "overview",
    component: () => import("./views/OverviewView.vue"),
    meta: { title: "Overview" },
  },
  {
    path: "/keys",
    name: "keys",
    component: () => import("./views/KeysView.vue"),
    meta: { title: "Keys" },
  },
  {
    path: "/credentials",
    name: "credentials",
    component: () => import("./views/CredentialsView.vue"),
    meta: { title: "Credentials" },
  },
  {
    path: "/config",
    name: "config",
    component: () => import("./views/ConfigView.vue"),
    meta: { title: "Config" },
  },
  {
    path: "/logs",
    name: "logs",
    component: () => import("./views/LogsView.vue"),
    meta: { title: "Logs" },
  },
  {
    path: "/metrics",
    name: "metrics",
    component: () => import("./views/MetricsView.vue"),
    meta: { title: "Metrics" },
  },
  {
    path: "/spend",
    name: "spend",
    component: () => import("./views/SpendView.vue"),
    meta: { title: "Spend" },
  },
  {
    path: "/prompts",
    name: "prompts",
    component: () => import("./views/PromptsView.vue"),
    meta: { title: "Prompts" },
  },
  {
    path: "/playground",
    name: "playground",
    component: () => import("./views/PlaygroundView.vue"),
    meta: { title: "Playground" },
  },
  {
    path: "/cache",
    name: "cache",
    component: () => import("./views/CacheView.vue"),
    meta: { title: "Cache" },
  },
  {
    path: "/model-host",
    name: "model-host",
    component: () => import("./views/ModelHostView.vue"),
    meta: { title: "Model host" },
  },
  {
    path: "/audit",
    name: "audit",
    component: () => import("./views/AuditView.vue"),
    meta: { title: "Audit" },
  },
  {
    path: "/cluster",
    name: "cluster",
    component: () => import("./views/ClusterView.vue"),
    meta: { title: "Cluster" },
  },
  { path: "/:pathMatch(.*)*", redirect: "/" },
];

// History mode with the `/admin/ui/` base. The admin server does SPA
// fallback to index.html so refreshing a deep link resolves.
export const router = createRouter({
  history: createWebHistory("/admin/ui/"),
  routes,
});
