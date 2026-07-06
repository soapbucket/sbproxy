<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { api, ApiError, type ModelHostStatus, type ResidentModel } from "../api";
import { useAsync } from "../composables/useAsync";
import { parsePrometheus, findFamily, histogramAvgByLabel } from "../lib/metrics";
import { formatBytes } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatCard from "../components/StatCard.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const req = useAsync(() => api.modelHostStatus());
const metricsReq = useAsync(() => api.metrics());
function refresh() {
  req.run();
  metricsReq.run();
}
onMounted(refresh);

// ---- load / evict (WOR-1765) ----
const loadName = ref("");
const busy = ref("");
const banner = ref<{ tone: "ok" | "err"; text: string } | null>(null);

async function act(label: string, fn: () => Promise<unknown>, ok: string) {
  if (busy.value) return;
  busy.value = label;
  banner.value = null;
  try {
    await fn();
    banner.value = { tone: "ok", text: ok };
    refresh();
  } catch (e) {
    const msg = e instanceof ApiError ? e.hint : e instanceof Error ? e.message : "Failed.";
    banner.value = { tone: "err", text: msg };
  } finally {
    busy.value = "";
  }
}
const loadModel = () =>
  act("load", () => api.modelHostLoad(loadName.value.trim()), `Loading "${loadName.value.trim()}".`);
const evictModel = (name: string) =>
  act(`evict:${name}`, () => api.modelHostEvict(name), `Evicted "${name}".`);

const status = computed<ModelHostStatus | null>(() => req.data.value);
const serving = computed(() => !!status.value?.serving);
const models = computed<ResidentModel[]>(() => status.value?.models ?? []);
const vram = computed(() => status.value?.vram);

// Avg tok/s per model name from the throughput histogram (WOR-895).
const tps = computed(() => {
  const text = metricsReq.data.value;
  if (!text) return new Map<string, number>();
  const rows = histogramAvgByLabel(
    findFamily(parsePrometheus(text), "sbproxy_ai_output_throughput_tokens_per_second"),
    "model",
  );
  return new Map(rows.map((r) => [r.key, r.value]));
});
function tpsFor(name?: string): string {
  const v = name ? tps.value.get(name) : undefined;
  return v !== undefined ? `${v.toFixed(1)} tok/s` : "-";
}
function stateLabel(s: ResidentModel["state"]): string {
  if (typeof s === "string") return s;
  if (s && typeof s === "object") return Object.keys(s)[0] ?? "unknown";
  return "unknown";
}
function stateTone(s: ResidentModel["state"]): "ok" | "warn" | "err" | "neutral" {
  const l = stateLabel(s).toLowerCase();
  if (l.includes("ready")) return "ok";
  if (l.includes("fail")) return "err";
  if (l.includes("load")) return "warn";
  return "neutral";
}
</script>

<template>
  <PageHeader
    title="Model host"
    subtitle="Locally served models: residency, VRAM, and token throughput."
  >
    <template #actions>
      <button class="sb-btn sb-btn--sm" @click="refresh">Refresh</button>
    </template>
  </PageHeader>

  <ErrorState v-if="req.error.value" :error="req.error.value" @retry="refresh" />
  <EmptyState
    v-else-if="req.data.value !== null && !serving"
    message="No local model host configured. Add a serve: block to an ai_proxy provider to serve models on this node."
  />
  <template v-else>
    <div class="grid">
      <StatCard label="Resident models" :value="models.length" tone="accent" />
      <StatCard
        label="VRAM used"
        :value="formatBytes(vram?.used_bytes)"
        :sub="vram?.budget_bytes ? `of ${formatBytes(vram.budget_bytes)}` : undefined"
      />
      <StatCard label="VRAM free" :value="formatBytes(vram?.free_bytes)" />
    </div>

    <p v-if="banner" class="banner" :class="`banner--${banner.tone}`">{{ banner.text }}</p>

    <div class="sb-card panel">
      <h3>Load a model</h3>
      <div class="action">
        <input
          v-model="loadName"
          class="sb-input"
          placeholder="catalog id or hf:Org/Repo:QUANT"
          @keydown.enter="loadModel"
        />
        <button class="sb-btn" :disabled="!loadName.trim() || busy === 'load'" @click="loadModel">
          {{ busy === "load" ? "Loading..." : "Load" }}
        </button>
      </div>
      <p class="sb-faint">
        Spawns the engine and makes the model resident. keep_alive is set in
        config; evicting frees its VRAM immediately.
      </p>
    </div>

    <div class="sb-card panel" v-if="models.length">
      <h3>Resident models</h3>
      <div class="table-wrap">
        <table class="sb-table">
          <thead>
            <tr>
              <th>Model</th><th>State</th><th>VRAM</th><th>Keep-alive</th>
              <th>Throughput</th><th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(m, i) in models" :key="i">
              <td class="sb-mono">{{ m.name ?? "unknown" }}</td>
              <td><StatusBadge :label="stateLabel(m.state)" :tone="stateTone(m.state)" /></td>
              <td>{{ formatBytes(m.vram_bytes) }}</td>
              <td>{{ m.keep_alive_secs != null ? `${m.keep_alive_secs}s` : "-" }}</td>
              <td>{{ tpsFor(m.name) }}</td>
              <td>
                <button
                  v-if="m.name"
                  class="sb-btn sb-btn--sm"
                  :disabled="busy === `evict:${m.name}`"
                  @click="evictModel(m.name)"
                >
                  {{ busy === `evict:${m.name}` ? "Evicting..." : "Evict" }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="sb-card panel" v-if="vram?.devices?.length">
      <h3>GPU devices</h3>
      <div class="table-wrap">
        <table class="sb-table">
          <thead>
            <tr><th>#</th><th>Device</th><th>Total</th><th>Free</th></tr>
          </thead>
          <tbody>
            <tr v-for="d in vram.devices" :key="d.index">
              <td>{{ d.index }}</td>
              <td>{{ d.name }}</td>
              <td>{{ formatBytes(d.total_bytes) }}</td>
              <td>{{ formatBytes(d.free_bytes) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </template>
</template>

<style scoped>
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: var(--sb-space-4);
  margin-bottom: var(--sb-space-5);
}
.panel {
  margin-bottom: var(--sb-space-4);
}
.panel h3 {
  margin-bottom: var(--sb-space-3);
}
.table-wrap {
  overflow-x: auto;
}
.action {
  display: flex;
  align-items: center;
  gap: var(--sb-space-3);
  margin-bottom: var(--sb-space-3);
  flex-wrap: wrap;
}
.action .sb-input {
  max-width: 360px;
}
.banner {
  padding: var(--sb-space-3) var(--sb-space-4);
  border-radius: var(--sb-radius-sm);
  margin-bottom: var(--sb-space-4);
  font-size: 0.9rem;
}
.banner--ok {
  background: var(--sb-accent-tint);
  color: var(--sb-accent);
}
.banner--err {
  background: #fdecea;
  color: #c0392b;
}
</style>
