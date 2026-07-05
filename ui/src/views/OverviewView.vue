<script setup lang="ts">
import { computed, onMounted } from "vue";
import { api, asList, type HealthComponent, type ResidentModel } from "../api";
import { useAsync } from "../composables/useAsync";
import { formatBytes, formatDuration, formatNumber } from "../lib/format";
import PageHeader from "../components/PageHeader.vue";
import StatCard from "../components/StatCard.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const health = useAsync(() => api.health());
const stats = useAsync(() => api.stats());
const modelHost = useAsync(() => api.modelHostStatus());

function refresh() {
  health.run();
  stats.run();
  modelHost.run();
}
onMounted(refresh);

// Health components can arrive as an array or a map of name -> value.
const healthComponents = computed<HealthComponent[]>(() => {
  const h = health.data.value;
  if (!h) return [];
  const raw = h.components ?? h.checks;
  if (Array.isArray(raw)) return raw as HealthComponent[];
  if (raw && typeof raw === "object") {
    return Object.entries(raw).map(([name, v]) => {
      if (v && typeof v === "object") {
        return { name, ...(v as object) } as HealthComponent;
      }
      return { name, status: String(v) };
    });
  }
  return [];
});

const uptime = computed(() => {
  const h = health.data.value;
  if (!h) return undefined;
  if (typeof h.uptime_seconds === "number") return formatDuration(h.uptime_seconds);
  return h.uptime;
});

// Stats is a loosely shaped object. Show every scalar entry as a tile.
const statTiles = computed(() => {
  const s = stats.data.value as Record<string, unknown> | null;
  if (!s || typeof s !== "object") return [];
  return Object.entries(s)
    .filter(([, v]) => typeof v === "number" || typeof v === "string")
    .slice(0, 12)
    .map(([k, v]) => ({
      label: k.replace(/_/g, " "),
      value: typeof v === "number" ? formatNumber(v) : String(v),
    }));
});

const residentModels = computed<ResidentModel[]>(() => {
  const m = modelHost.data.value;
  if (!m) return [];
  return asList<ResidentModel>(m.models ?? m.resident ?? m, "models", "resident");
});

const vram = computed(() => {
  const m = modelHost.data.value;
  if (!m) return null;
  const used = m.vram_used_bytes ?? m.vram_used;
  const total = m.vram_total_bytes ?? m.vram_total;
  if (used === undefined && total === undefined) return null;
  return { used, total };
});
</script>

<template>
  <PageHeader
    title="Overview"
    subtitle="Live health, aggregate stats, and the local model host at a glance."
  >
    <template #actions>
      <button class="sb-btn" @click="refresh">Refresh</button>
    </template>
  </PageHeader>

  <!-- Health -->
  <section class="section">
    <div class="section__head">
      <h2>Health</h2>
      <StatusBadge
        v-if="health.data.value"
        :label="String((health.data.value as any).status ?? 'unknown')"
      />
    </div>
    <ErrorState v-if="health.error.value" :error="health.error.value" @retry="health.run" />
    <div v-else class="grid">
      <StatCard
        label="Status"
        :value="String((health.data.value as any)?.status ?? '...')"
        tone="accent"
      />
      <StatCard label="Version" :value="String((health.data.value as any)?.version ?? 'n/a')" />
      <StatCard label="Uptime" :value="uptime ?? 'n/a'" />
      <StatCard label="Components" :value="healthComponents.length || '0'" />
    </div>
    <div class="card-list" v-if="healthComponents.length">
      <div class="check" v-for="(c, i) in healthComponents" :key="i">
        <span class="check__name sb-mono">{{ c.name ?? "component" }}</span>
        <span class="check__detail sb-muted" v-if="c.detail || c.message">
          {{ c.detail ?? c.message }}
        </span>
        <StatusBadge :label="String(c.status ?? 'unknown')" />
      </div>
    </div>
  </section>

  <!-- Stats -->
  <section class="section">
    <h2>Stats</h2>
    <ErrorState v-if="stats.error.value" :error="stats.error.value" @retry="stats.run" />
    <EmptyState v-else-if="!statTiles.length" message="No stats reported by /api/stats." />
    <div v-else class="grid">
      <StatCard v-for="t in statTiles" :key="t.label" :label="t.label" :value="t.value" />
    </div>
  </section>

  <!-- Model host -->
  <section class="section">
    <h2>Model host</h2>
    <ErrorState v-if="modelHost.error.value" :error="modelHost.error.value" @retry="modelHost.run" />
    <template v-else>
      <div class="grid" v-if="vram">
        <StatCard label="VRAM used" :value="formatBytes(vram.used)" />
        <StatCard label="VRAM total" :value="formatBytes(vram.total)" />
        <StatCard label="Resident models" :value="residentModels.length" />
      </div>
      <EmptyState
        v-if="!residentModels.length"
        message="No resident models. The model host may be idle or not enabled."
      />
      <table class="sb-table" v-else>
        <thead>
          <tr>
            <th>Model</th>
            <th>State</th>
            <th>Engine</th>
            <th>VRAM</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(m, i) in residentModels" :key="i">
            <td class="sb-mono">{{ m.name ?? m.id ?? "unknown" }}</td>
            <td><StatusBadge :label="String(m.state ?? m.status ?? 'unknown')" /></td>
            <td class="sb-muted">{{ m.engine ?? "n/a" }}</td>
            <td>{{ formatBytes(m.vram_bytes ?? m.vram) }}</td>
          </tr>
        </tbody>
      </table>
    </template>
  </section>
</template>

<style scoped>
.section {
  margin-bottom: var(--sb-space-6);
}
.section__head {
  display: flex;
  align-items: center;
  gap: var(--sb-space-3);
  margin-bottom: var(--sb-space-4);
}
.section h2 {
  margin-bottom: var(--sb-space-4);
}
.section__head h2 {
  margin-bottom: 0;
}
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: var(--sb-space-4);
  margin-bottom: var(--sb-space-4);
}
.card-list {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--sb-border);
  border-radius: var(--sb-radius);
  overflow: hidden;
}
.check {
  display: flex;
  align-items: center;
  gap: var(--sb-space-4);
  padding: 10px 14px;
  border-bottom: 1px solid var(--sb-border);
}
.check:last-child {
  border-bottom: none;
}
.check__name {
  font-size: 0.85rem;
  min-width: 160px;
}
.check__detail {
  flex: 1;
  font-size: 0.82rem;
}
</style>
