<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { api, asList, ApiError, type TargetHealth } from "../api";
import { useAsync } from "../composables/useAsync";
import { formatMs } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const openapi = useAsync(() => api.openapi());
const drift = useAsync(() => api.drift());
const targetsReq = useAsync(() => api.targets());

function refresh() {
  openapi.run();
  drift.run();
  targetsReq.run();
}
onMounted(refresh);

// ---- openapi summary ----
const showRawSpec = ref(false);

const specInfo = computed(() => {
  const s = openapi.data.value as any;
  return {
    title: s?.info?.title ?? "OpenAPI",
    version: s?.info?.version ?? "",
    openapi: s?.openapi ?? "",
  };
});

const servers = computed<string[]>(() => {
  const s = openapi.data.value as any;
  const arr = Array.isArray(s?.servers) ? s.servers : [];
  return arr.map((x: any) => x?.url ?? String(x)).filter(Boolean);
});

const paths = computed(() => {
  const s = openapi.data.value as any;
  const p = s?.paths;
  if (!p || typeof p !== "object") return [];
  return Object.entries(p).map(([path, ops]) => ({
    path,
    methods: ops && typeof ops === "object"
      ? Object.keys(ops as object)
          .filter((m) => ["get", "post", "put", "patch", "delete", "head", "options"].includes(m.toLowerCase()))
          .map((m) => m.toUpperCase())
      : [],
  }));
});

const rawSpec = computed(() => JSON.stringify(openapi.data.value ?? {}, null, 2));

// ---- drift ----
const driftInSync = computed<boolean | null>(() => {
  const d = drift.data.value as any;
  if (!d) return null;
  // Real server shape (GET /admin/drift): a `drift` boolean, true = drifted.
  if (typeof d.drift === "boolean") return !d.drift;
  if (typeof d.in_sync === "boolean") return d.in_sync;
  if (typeof d.drifted === "boolean") return !d.drifted;
  // Empty diff / no changes implies in sync.
  if (typeof d.diff === "string") return d.diff.trim().length === 0;
  if (Array.isArray(d.changes)) return d.changes.length === 0;
  return null;
});

const driftDetail = computed(() => {
  const d = drift.data.value as any;
  if (!d) return "";
  // Real server shape: loaded vs on-disk content hashes plus context.
  if (d.loaded_content_hash !== undefined || d.on_disk_content_hash !== undefined) {
    return JSON.stringify(
      {
        config_path: d.config_path,
        loaded_revision: d.loaded_revision,
        loaded_content_hash: d.loaded_content_hash,
        on_disk_content_hash: d.on_disk_content_hash,
        on_disk_size_bytes: d.on_disk_size_bytes,
        checked_at: d.checked_at,
      },
      null,
      2,
    );
  }
  if (typeof d.diff === "string" && d.diff.trim()) return d.diff;
  if (Array.isArray(d.changes) && d.changes.length) {
    return d.changes.map((c: unknown) => JSON.stringify(c)).join("\n");
  }
  // Fall back to showing on-disk vs loaded if present.
  if (d.on_disk !== undefined || d.loaded !== undefined) {
    return JSON.stringify({ on_disk: d.on_disk, loaded: d.loaded }, null, 2);
  }
  return "";
});

// ---- targets ----
const targets = computed<TargetHealth[]>(() =>
  asList<TargetHealth>(targetsReq.data.value, "targets", "items", "data"),
);

function targetHealthy(t: TargetHealth): string {
  if (typeof t.healthy === "boolean") return t.healthy ? "healthy" : "unhealthy";
  return String(t.status ?? "unknown");
}

// ---- reload ----
const reloadBusy = ref(false);
const reloadMsg = ref<string | null>(null);
const reloadError = ref<ApiError | null>(null);

async function reload() {
  if (!confirm("Reload configuration from disk? Active config will be replaced by the on-disk version.")) {
    return;
  }
  reloadBusy.value = true;
  reloadMsg.value = null;
  reloadError.value = null;
  try {
    await api.reload();
    reloadMsg.value = "Reload requested. Refreshing drift and targets.";
    drift.run();
    targetsReq.run();
  } catch (e) {
    reloadError.value = e instanceof ApiError ? e : new ApiError(0, String(e));
  } finally {
    reloadBusy.value = false;
  }
}
</script>

<template>
  <PageHeader
    title="Config"
    subtitle="The running configuration: emitted OpenAPI surface, on-disk drift, and per-target health."
  >
    <template #actions>
      <button class="sb-btn" @click="refresh">Refresh</button>
      <button class="sb-btn sb-btn--primary" :disabled="reloadBusy" @click="reload">
        {{ reloadBusy ? "Reloading..." : "Reload config" }}
      </button>
    </template>
  </PageHeader>

  <p class="ok-line" v-if="reloadMsg">{{ reloadMsg }}</p>
  <ErrorState v-if="reloadError" :error="reloadError" title="Reload failed" @retry="reload" />

  <!-- Drift -->
  <section class="section">
    <div class="section__head">
      <h2>Configuration drift</h2>
      <StatusBadge
        v-if="driftInSync !== null"
        :label="driftInSync ? 'in sync' : 'drifted'"
        :tone="driftInSync ? 'ok' : 'warn'"
      />
    </div>
    <ErrorState v-if="drift.error.value" :error="drift.error.value" @retry="drift.run" />
    <div v-else class="sb-card">
      <p class="sb-muted" v-if="driftInSync === true">
        The on-disk configuration matches what is loaded in memory.
      </p>
      <p class="sb-muted" v-else-if="driftInSync === false">
        The on-disk configuration differs from what is loaded. Reload to apply the on-disk version.
      </p>
      <p class="sb-faint" v-else>Drift state could not be determined from the response.</p>
      <pre class="sb-code" v-if="driftDetail" style="margin-top: 12px">{{ driftDetail }}</pre>
    </div>
  </section>

  <!-- OpenAPI -->
  <section class="section">
    <div class="section__head">
      <h2>OpenAPI surface</h2>
      <button class="sb-btn sb-btn--sm" @click="showRawSpec = !showRawSpec">
        {{ showRawSpec ? "Hide raw JSON" : "View raw JSON" }}
      </button>
    </div>
    <ErrorState v-if="openapi.error.value" :error="openapi.error.value" @retry="openapi.run" />
    <template v-else>
      <div class="sb-card" style="margin-bottom: 16px">
        <div class="meta-row">
          <span><strong>{{ specInfo.title }}</strong></span>
          <span class="sb-faint" v-if="specInfo.version">v{{ specInfo.version }}</span>
          <span class="sb-faint" v-if="specInfo.openapi">OpenAPI {{ specInfo.openapi }}</span>
        </div>
        <div class="origins" v-if="servers.length">
          <span class="sb-eyebrow">Origins</span>
          <div class="tags">
            <span class="tag sb-mono" v-for="s in servers" :key="s">{{ s }}</span>
          </div>
        </div>
      </div>

      <pre class="sb-code" v-if="showRawSpec">{{ rawSpec }}</pre>

      <EmptyState v-else-if="!paths.length" message="No paths in the emitted spec." />
      <div class="table-wrap" v-else>
        <table class="sb-table">
          <thead>
            <tr>
              <th>Path</th>
              <th>Methods</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="p in paths" :key="p.path">
              <td class="sb-mono">{{ p.path }}</td>
              <td>
                <span class="method" v-for="m in p.methods" :key="m">{{ m }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </section>

  <!-- Targets -->
  <section class="section">
    <h2>Target health</h2>
    <ErrorState v-if="targetsReq.error.value" :error="targetsReq.error.value" @retry="targetsReq.run" />
    <EmptyState v-else-if="!targets.length" message="No upstream targets reported." />
    <div class="table-wrap" v-else>
      <table class="sb-table">
        <thead>
          <tr>
            <th>Target</th>
            <th>Health</th>
            <th>Breaker</th>
            <th>Latency</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(t, i) in targets" :key="i">
            <td class="sb-mono">{{ t.name ?? t.target ?? t.url ?? "unknown" }}</td>
            <td><StatusBadge :label="targetHealthy(t)" /></td>
            <td>
              <StatusBadge
                v-if="t.breaker ?? t.breaker_state"
                :label="String(t.breaker ?? t.breaker_state)"
              />
              <span class="sb-faint" v-else>n/a</span>
            </td>
            <td>{{ formatMs(t.latency_ms) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<style scoped>
.section {
  margin-bottom: var(--sb-space-6);
}
.section h2 {
  margin-bottom: var(--sb-space-4);
}
.section__head {
  display: flex;
  align-items: center;
  gap: var(--sb-space-3);
  margin-bottom: var(--sb-space-4);
}
.section__head h2 {
  margin-bottom: 0;
}
.meta-row {
  display: flex;
  gap: var(--sb-space-4);
  align-items: baseline;
  flex-wrap: wrap;
}
.origins {
  margin-top: var(--sb-space-4);
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.tag {
  font-size: 0.78rem;
  padding: 2px 10px;
  border-radius: var(--sb-radius-pill);
  background: var(--sb-surface-2);
  color: var(--sb-text-muted);
  border: 1px solid var(--sb-border);
}
.table-wrap {
  border: 1px solid var(--sb-border);
  border-radius: var(--sb-radius);
  overflow-x: auto;
}
.method {
  display: inline-block;
  font-family: var(--sb-font-mono);
  font-size: 0.72rem;
  font-weight: 600;
  padding: 1px 7px;
  margin-right: 4px;
  border-radius: var(--sb-radius-sm);
  background: var(--sb-accent-tint);
  color: var(--sb-accent);
}
.ok-line {
  background: var(--sb-ok-bg);
  border: 1px solid rgba(15, 158, 110, 0.3);
  border-radius: var(--sb-radius-sm);
  padding: 8px 12px;
  color: var(--sb-ok);
  font-size: 0.85rem;
}
</style>
