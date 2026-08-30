import { watch } from "vue";
import { createMemoryHistory, createRouter, createWebHistory } from "vue-router";
import { useAuth } from "./composables/useAuth";

const routes = [
  {
    path: "/",
    name: "overview",
    component: () => import("./views/OverviewView.vue"),
    meta: { title: "Overview", documentation: "admin-ui" },
  },
  {
    path: "/get-started",
    name: "get-started",
    component: () => import("./views/GetStartedView.vue"),
    meta: { title: "Get started", documentation: "quickstart-serve" },
  },
  {
    path: "/keys",
    name: "keys",
    component: () => import("./views/KeysView.vue"),
    meta: { title: "Keys", documentation: "key-management" },
  },
  {
    path: "/agents",
    name: "agents",
    component: () => import("./views/AgentsView.vue"),
    meta: { title: "Agents", documentation: "agent-registry" },
  },
  {
    path: "/notifications",
    name: "notifications",
    component: () => import("./views/NotificationsView.vue"),
    meta: { title: "Notifications", documentation: "notifications" },
  },
  {
    path: "/credentials",
    name: "credentials",
    component: () => import("./views/CredentialsView.vue"),
    meta: { title: "Credentials", documentation: "admin-ui" },
  },
  {
    path: "/config",
    name: "config",
    component: () => import("./views/ConfigView.vue"),
    meta: { title: "Config", documentation: "configuration" },
  },
  {
    path: "/extensions",
    name: "extensions",
    component: () => import("./views/ExtensionsView.vue"),
    meta: { title: "Extensions", documentation: "admin-ui" },
  },
  {
    path: "/logs",
    name: "logs",
    component: () => import("./views/LogsView.vue"),
    meta: { title: "Logs", documentation: "admin-ui" },
  },
  {
    path: "/sessions",
    name: "sessions",
    component: () => import("./views/SessionsView.vue"),
    meta: { title: "Sessions", documentation: "admin-ui" },
  },
  {
    path: "/sessions/:sessionId",
    name: "session-detail",
    component: () => import("./views/SessionDetailView.vue"),
    meta: { title: "Session detail", documentation: "admin-ui" },
  },
  {
    path: "/routing-decisions",
    name: "routing-decisions",
    component: () => import("./views/RoutingDecisionsView.vue"),
    meta: { title: "Routing decisions", documentation: "admin-ui" },
  },
  {
    path: "/mcp-approvals",
    name: "mcp-approvals",
    component: () => import("./views/McpApprovalsView.vue"),
    meta: { title: "MCP approvals", documentation: "cedar-policy" },
  },
  {
    path: "/metrics",
    name: "metrics",
    component: () => import("./views/MetricsView.vue"),
    meta: { title: "Metrics", documentation: "observability" },
  },
  {
    path: "/spend",
    name: "spend",
    component: () => import("./views/SpendView.vue"),
    meta: { title: "Spend", documentation: "ai-usage-ledger" },
  },
  {
    path: "/reports",
    name: "reports",
    component: () => import("./views/ReportsView.vue"),
    meta: { title: "Reports", documentation: "admin-ui" },
  },
  {
    path: "/meter",
    name: "meter",
    component: () => import("./views/MeterView.vue"),
    meta: { title: "Meter", documentation: "ai-usage-ledger" },
  },
  {
    path: "/ai-performance",
    name: "ai-performance",
    component: () => import("./views/AiPerformanceView.vue"),
    meta: { title: "AI performance", documentation: "admin-ui" },
  },
  {
    path: "/guardrails",
    name: "guardrails",
    component: () => import("./views/GuardrailsView.vue"),
    meta: { title: "Guardrails", documentation: "guardrails" },
  },
  {
    path: "/alerts",
    name: "alerts",
    component: () => import("./views/AlertsView.vue"),
    meta: { title: "Alerts", documentation: "admin-ui" },
  },
  {
    path: "/prompts",
    name: "prompts",
    component: () => import("./views/PromptsView.vue"),
    meta: { title: "Prompts", documentation: "admin-ui" },
  },
  {
    path: "/playground",
    name: "playground",
    component: () => import("./views/PlaygroundView.vue"),
    meta: { title: "Playground", documentation: "ai-gateway" },
  },
  {
    path: "/cache",
    name: "cache",
    component: () => import("./views/CacheView.vue"),
    meta: { title: "Cache", documentation: "admin-ui" },
  },
  {
    path: "/model-host",
    name: "model-host",
    component: () => import("./views/ModelHostView.vue"),
    meta: { title: "Model host", documentation: "model-host" },
  },
  {
    path: "/jobs",
    name: "jobs",
    component: () => import("./views/JobsView.vue"),
    meta: { title: "Jobs", documentation: "model-host" },
  },
  {
    path: "/storage",
    name: "storage",
    component: () => import("./views/StorageView.vue"),
    meta: { title: "Storage", documentation: "admin-ui" },
  },
  {
    path: "/audit",
    name: "audit",
    component: () => import("./views/AuditView.vue"),
    meta: { title: "Audit", documentation: "audit-log" },
  },
  {
    path: "/cluster",
    name: "cluster",
    component: () => import("./views/ClusterView.vue"),
    meta: { title: "Cluster", documentation: "mesh-replication" },
  },
  {
    path: "/compression",
    name: "compression",
    component: () => import("./views/CompressionView.vue"),
    meta: { title: "Compression", documentation: "ai-context-compression" },
  },
  {
    path: "/users",
    name: "users",
    component: () => import("./views/UsersView.vue"),
    meta: { title: "Users", documentation: "admin" },
  },
  {
    path: "/operators",
    name: "operators",
    component: () => import("./views/OperatorsView.vue"),
    meta: { title: "Operators", documentation: "admin" },
  },
  {
    path: "/login",
    name: "login",
    component: () => import("./views/LoginView.vue"),
    meta: { title: "Sign in", public: true, documentation: "admin-ui" },
  },
  {
    path: "/:pathMatch(.*)*",
    redirect: "/",
    // Redirect-only records have no view to document, but remain explicit so
    // the route coverage guard distinguishes them from an omitted mapping.
    meta: { documentation: null },
  },
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

// The other half of the same story: a session that lapses mid-use surfaces
// as a 401 on whatever panel polled next, and the API client flips
// `authenticated` false through `useAuth`'s unauthorized handler. The guard
// above only runs on a navigation, so nothing moved. The operator was left
// on the page they were reading with the chrome gone and every panel
// reporting "Not authorized".
//
// Send them to the sign-in route, carrying the destination the way the
// guard does, so signing back in returns them where they were. This is the
// client-side half of WOR-2688: the server now answers the console's 401s
// without `WWW-Authenticate`, so no browser dialog interrupts, and this
// app's own login page is the only thing that asks for credentials.
watch(useAuth().authenticated, (isAuthenticated) => {
  if (isAuthenticated) return;
  const current = router.currentRoute.value;
  // Already there (a failed sign-in attempt, say): pushing again would be a
  // duplicate navigation and would drop the `next` already in the query.
  if (current.name === "login") return;
  void router.push({
    name: "login",
    query: current.fullPath === "/" ? {} : { next: current.fullPath },
  });
});
