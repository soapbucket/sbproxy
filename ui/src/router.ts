import { createMemoryHistory, createRouter, createWebHistory } from "vue-router";
import { useAuth } from "./composables/useAuth";

const routes = [
  {
    path: "/",
    name: "overview",
    component: () => import("./views/OverviewView.vue"),
    meta: { title: "Overview" },
  },
  {
    path: "/get-started",
    name: "get-started",
    component: () => import("./views/GetStartedView.vue"),
    meta: { title: "Get started" },
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
    path: "/jobs",
    name: "jobs",
    component: () => import("./views/JobsView.vue"),
    meta: { title: "Jobs" },
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
  {
    path: "/compression",
    name: "compression",
    component: () => import("./views/CompressionView.vue"),
    meta: { title: "Compression" },
  },
  {
    path: "/users",
    name: "users",
    component: () => import("./views/UsersView.vue"),
    meta: { title: "Users" },
  },
  {
    path: "/login",
    name: "login",
    component: () => import("./views/LoginView.vue"),
    meta: { title: "Sign in", public: true },
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

// Send an unauthenticated visitor to the login route rather than swapping
// the form in beneath whatever URL they asked for. The destination rides
// along as `next` so signing in returns them where they were headed, which
// is what makes a bookmarked deep link survive a session expiry.
//
// The guard waits for the initial session check: routing before it settles
// would bounce an authenticated operator to the login page on every cold
// load.
router.beforeEach(async (to) => {
  const { authenticated, ready, refresh } = useAuth();
  if (!ready.value) {
    await refresh();
  }
  if (authenticated.value) {
    // Nothing to sign in to; keep the login route out of the history.
    return to.name === "login" ? { path: "/" } : true;
  }
  if (to.meta.public) {
    return true;
  }
  return { name: "login", query: to.fullPath === "/" ? {} : { next: to.fullPath } };
});
