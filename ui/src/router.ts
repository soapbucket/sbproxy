import { createMemoryHistory, createRouter, createWebHistory } from "vue-router";

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
    path: "/sessions",
    name: "sessions",
    component: () => import("./views/SessionsView.vue"),
    meta: { title: "Sessions" },
  },
  {
    path: "/sessions/:sessionId",
    name: "session-detail",
    component: () => import("./views/SessionDetailView.vue"),
    meta: { title: "Session detail" },
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
    path: "/ai-performance",
    name: "ai-performance",
    component: () => import("./views/AiPerformanceView.vue"),
    meta: { title: "AI performance" },
  },
  {
    path: "/guardrails",
    name: "guardrails",
    component: () => import("./views/GuardrailsView.vue"),
    meta: { title: "Guardrails" },
  },
  {
    path: "/alerts",
    name: "alerts",
    component: () => import("./views/AlertsView.vue"),
    meta: { title: "Alerts" },
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
    path: "/storage",
    name: "storage",
    component: () => import("./views/StorageView.vue"),
    meta: { title: "Storage" },
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
  history:
    import.meta.env.MODE === "test"
      ? createMemoryHistory("/admin/ui/")
      : createWebHistory("/admin/ui/"),
  routes,
});
