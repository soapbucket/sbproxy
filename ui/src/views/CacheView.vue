<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { api, ApiError, type CacheStatus } from "../api";
import { useAsync } from "../composables/useAsync";
import { parsePrometheus, findFamily, sumSamples } from "../lib/metrics";
import { formatNumber } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatCard from "../components/StatCard.vue";
import ErrorState from "../components/ErrorState.vue";

const statusReq = useAsync(() => api.cacheStatus());
const metricsReq = useAsync(() => api.metrics());
const semanticReq = useAsync(() => api.semanticCache());

function refresh() {
  statusReq.run();
  metricsReq.run();
  semanticReq.run();
}
onMounted(refresh);

// Semantic (embedding) cache decisions, flattened per origin. Only shown
// when at least one AI origin has an embedding cache with recorded
// lookups.
const semanticCaches = computed(() =>
  (semanticReq.data.value?.caches ?? []).filter((c) => c.recent.length > 0),
);
function decisionTone(reason: string): string {
  return reason === "hit" ? "var(--sb-accent)" : "var(--sb-text-muted)";
}

const status = computed<CacheStatus | null>(() => statusReq.data.value ?? null);
const enabled = computed(() => !!status.value?.enabled);
const backend = computed(() => status.value?.backend ?? "n/a");
const prefixSupported = computed(() => !!status.value?.prefix_purge_supported);

// Hit / miss from the Prometheus scrape (sbproxy_cache_hits_total{result}).
const cacheHits = computed(() => {
  const text = metricsReq.data.value;
  if (!text) return { hits: 0, misses: 0 };
  const fam = findFamily(parsePrometheus(text), "sbproxy_cache_hits_total");
  return {
    hits: sumSamples(fam, { result: "hit" }),
    misses: sumSamples(fam, { result: "miss" }),
  };
});
const hitRate = computed(() => {
  const { hits, misses } = cacheHits.value;
  const total = hits + misses;
  return total > 0 ? (hits / total) * 100 : undefined;
});

// ---- purge + evict actions ----
const purgeKey = ref("");
const purgePrefix = ref("");
const evictId = ref("");
const busy = ref("");
const banner = ref<{ tone: "ok" | "err"; text: string } | null>(null);

async function run(label: string, fn: () => Promise<unknown>, ok: string) {
  if (busy.value) return;
  busy.value = label;
  banner.value = null;
  try {
    await fn();
    banner.value = { tone: "ok", text: ok };
    refresh();
  } catch (e) {
    const msg = e instanceof ApiError ? `${e.hint}` : e instanceof Error ? e.message : "Failed.";
    banner.value = { tone: "err", text: msg };
  } finally {
    busy.value = "";
  }
}

const purgeAll = () =>
  run("all", () => api.cachePurge({}), "Purged the entire response cache.");
const purgeByKey = () =>
  run("key", () => api.cachePurge({ key: purgeKey.value }), `Purged key "${purgeKey.value}".`);
const purgeByPrefix = () =>
  run(
    "prefix",
    () => api.cachePurge({ prefix: purgePrefix.value }),
    `Purged entries under "${purgePrefix.value}".`,
  );
const evictKey = () =>
  run("evict", () => api.evictKeyPolicy(evictId.value), `Evicted cached policy for "${evictId.value}".`);
const evictAllPolicies = () =>
  run("evict-all", () => api.evictKeyPolicy(), "Evicted all cached key policies.");
</script>

<template>
  <PageHeader
    title="Cache"
    subtitle="Response-cache status and eviction, plus dynamic key-policy cache invalidation."
  >
    <template #actions>
      <button class="sb-btn sb-btn--sm" @click="refresh">Refresh</button>
    </template>
  </PageHeader>

  <ErrorState v-if="statusReq.error.value" :error="statusReq.error.value" @retry="refresh" />
  <template v-else>
    <p v-if="banner" class="banner" :class="`banner--${banner.tone}`">{{ banner.text }}</p>

    <div class="grid">
      <StatCard
        label="Response cache"
        :value="enabled ? 'enabled' : 'disabled'"
        :tone="enabled ? 'accent' : 'default'"
        :sub="enabled ? `backend: ${backend}` : 'no origin enables response_cache'"
      />
      <StatCard label="Hits" :value="formatNumber(cacheHits.hits)" />
      <StatCard label="Misses" :value="formatNumber(cacheHits.misses)" />
      <StatCard
        label="Hit rate"
        :value="hitRate !== undefined ? `${hitRate.toFixed(1)}%` : 'n/a'"
      />
    </div>

    <div class="sb-card panel">
      <h3>Purge response cache</h3>
      <p class="sb-faint" v-if="!enabled">
        The response cache is not enabled in the running config.
      </p>
      <template v-else>
        <div class="action">
          <button class="sb-btn" :disabled="busy === 'all'" @click="purgeAll">
            Purge everything
          </button>
          <span class="sb-faint">Clears the whole {{ backend }} cache.</span>
        </div>
        <div class="action">
          <input v-model="purgeKey" class="sb-input" placeholder="cache key" />
          <button class="sb-btn" :disabled="!purgeKey || busy === 'key'" @click="purgeByKey">
            Purge key
          </button>
        </div>
        <div class="action">
          <input
            v-model="purgePrefix"
            class="sb-input"
            placeholder="key prefix"
            :disabled="!prefixSupported"
          />
          <button
            class="sb-btn"
            :disabled="!purgePrefix || !prefixSupported || busy === 'prefix'"
            @click="purgeByPrefix"
          >
            Purge prefix
          </button>
          <span class="sb-faint" v-if="!prefixSupported">
            Prefix purge is not supported on the {{ backend }} backend.
          </span>
        </div>
      </template>
    </div>

    <div class="sb-card panel">
      <h3>Evict key-policy cache</h3>
      <p class="sb-faint">
        Force a key's cached policy to reload from the keystore. On a shared
        Redis keystore this fans out to every replica.
      </p>
      <div class="action">
        <input v-model="evictId" class="sb-input" placeholder="key id" />
        <button class="sb-btn" :disabled="!evictId || busy === 'evict'" @click="evictKey">
          Evict key
        </button>
      </div>
      <div class="action">
        <button class="sb-btn" :disabled="busy === 'evict-all'" @click="evictAllPolicies">
          Evict all policies
        </button>
      </div>
    </div>

    <div class="sb-card panel" v-if="semanticCaches.length">
      <h3>Semantic cache decisions</h3>
      <p class="sb-faint">
        Recent embedding-cache lookups and why each hit or missed
        (no_entry / expired / below_threshold / cross_scope).
      </p>
      <div v-for="c in semanticCaches" :key="c.origin" class="semantic">
        <div class="semantic__origin sb-mono">{{ c.origin }}</div>
        <div class="table-wrap">
          <table class="sb-table">
            <thead>
              <tr><th>Reason</th><th>Score</th><th>Threshold</th><th>Scope</th></tr>
            </thead>
            <tbody>
              <tr v-for="(d, i) in c.recent" :key="i">
                <td>
                  <span :style="{ color: decisionTone(d.reason), fontWeight: 600 }">
                    {{ d.reason }}
                  </span>
                </td>
                <td>{{ d.score != null ? d.score.toFixed(3) : "-" }}</td>
                <td>{{ d.threshold.toFixed(2) }}</td>
                <td class="sb-mono sb-muted">{{ d.scope || "-" }}</td>
              </tr>
            </tbody>
          </table>
        </div>
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
.action {
  display: flex;
  align-items: center;
  gap: var(--sb-space-3);
  margin-top: var(--sb-space-3);
  flex-wrap: wrap;
}
.action .sb-input {
  max-width: 320px;
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
.semantic {
  margin-top: var(--sb-space-4);
}
.semantic__origin {
  font-size: 0.82rem;
  color: var(--sb-text-muted);
  margin-bottom: var(--sb-space-2);
}
.table-wrap {
  overflow-x: auto;
}
</style>
