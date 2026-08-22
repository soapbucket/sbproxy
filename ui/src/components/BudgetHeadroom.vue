<script setup lang="ts">
/**
 * Budget headroom: how close the money is to the wall.
 *
 * Three sub-blocks, deliberately kept apart, because sbproxy has three
 * unrelated budget systems and merging them into one bar would claim a
 * relationship that does not exist:
 *
 *  (a) per-key dollar caps, from the governance ledger, which is the
 *      only place a cap and its consumption are both named;
 *  (b) `sbproxy_ai_budget_utilization_ratio{scope}`, a gauge with no
 *      identity, which can say how full the fullest budget in a scope is
 *      and cannot say whose it is;
 *  (c) workspace rate-limit budgets, which are request-rate tiers rather
 *      than money, rendered by the component that owns the resume
 *      control.
 *
 * (a) costs one request per key, so the fan-out is bounded and the view
 * says what it left out. `metadata.truncated`, applied to a limit we
 * chose ourselves.
 */
import { computed, onMounted, ref, watch } from "vue";
import {
  api,
  asList,
  ApiError,
  type AdminKey,
  type GovernanceSnapshot,
} from "../api";
import { useAsync } from "../composables/useAsync";
import { formatTime, formatUsd } from "../lib/format";
import { budgetBar, selectCappedKeys, utilizationByScope } from "../lib/cost-trust";
import { findFamily, type MetricFamily } from "../lib/metrics";
import ErrorState from "./ErrorState.vue";
import EmptyState from "./EmptyState.vue";
import StatusBadge from "./StatusBadge.vue";
import WorkspaceBudgets from "./WorkspaceBudgets.vue";

const props = defineProps<{
  /** Parsed `/metrics` families, scraped once by the page. */
  families: MetricFamily[];
  /**
   * This window's rollup spend per key id, when the page is grouped by
   * API key. Decides which capped keys are worth a usage request; absent
   * means fall back to ordering by the size of the cap.
   */
  spendByKey?: Record<string, number>;
}>();

/** One usage request per key is the cost, so the list stops here. */
const FAN_OUT_LIMIT = 20;

const keysReq = useAsync(() => api.keys());
const keys = computed<AdminKey[]>(() =>
  asList<AdminKey>(keysReq.data.value, "keys", "items", "data"),
);

const selection = computed(() =>
  selectCappedKeys(keys.value, props.spendByKey, FAN_OUT_LIMIT),
);

const usage = ref<Record<string, GovernanceSnapshot>>({});
const usageFailed = ref<Record<string, string>>({});
let fanOut = 0;

async function loadUsage() {
  const rows = selection.value.rows;
  const invocation = ++fanOut;
  const loaded: Record<string, GovernanceSnapshot> = {};
  const failed: Record<string, string> = {};
  await Promise.all(
    rows.map(async (row) => {
      try {
        loaded[row.id] = await api.keyUsage(row.id);
      } catch (e) {
        // One key's ledger being unreachable is that key's row saying so,
        // not the whole panel failing.
        failed[row.id] = e instanceof ApiError ? e.hint : String(e);
      }
    }),
  );
  if (invocation !== fanOut) return;
  usage.value = loaded;
  usageFailed.value = failed;
}

onMounted(() => {
  void keysReq.run();
});

// Re-fan-out only when the set of keys changes. The ledger's counters do
// not follow the page's window, so switching windows re-orders the list
// without needing twenty fresh requests.
watch(
  () => selection.value.rows.map((row) => row.id).join(","),
  () => void loadUsage(),
);

function refresh() {
  void keysReq.run().then(() => loadUsage());
}
defineExpose({ refresh });

interface HeadroomRow {
  id: string;
  label: string;
  capUsd: number;
  bar: ReturnType<typeof budgetBar>;
  resetAtMillis: number | null;
  /** Set when this key's ledger could not be read. */
  error?: string;
  /** Set when the policy declares a cap the ledger does not enforce. */
  ledgerHasNoCap: boolean;
}

const rows = computed<HeadroomRow[]>(() =>
  selection.value.rows.map((row) => {
    const snapshot = usage.value[row.id];
    const counter = snapshot?.total_micro_usd;
    return {
      id: row.id,
      label: row.label,
      capUsd: row.capUsd,
      bar: counter ? budgetBar(counter) : undefined,
      resetAtMillis: counter?.reset_at_millis ?? null,
      error: usageFailed.value[row.id],
      ledgerHasNoCap: Boolean(counter) && counter?.limit === null,
    };
  }),
);

/**
 * A cap read off a degraded counter is a number that may already be
 * wrong. Say so on the panel rather than rendering it as fact.
 */
const degradedBackends = computed(() => {
  const seen = new Set<string>();
  for (const snapshot of Object.values(usage.value)) {
    if (snapshot.backend.status !== "healthy") seen.add(snapshot.backend.status);
  }
  return [...seen].sort();
});

const approximateBackend = computed(() =>
  Object.values(usage.value).some(
    (snapshot) => snapshot.backend.consistency === "approximate",
  ),
);

const orderNote = computed(() =>
  selection.value.orderedBy === "spend"
    ? "highest spend in this window first"
    : "largest cap first",
);

// (b) The scope gauge. Absent entirely on a deployment with no AI
// budgets configured, which is not the same as every budget reading 0%.
const utilizationFamily = computed(() =>
  findFamily(props.families, "sbproxy_ai_budget_utilization_ratio"),
);
const scopes = computed(() => utilizationByScope(utilizationFamily.value));
</script>

<template>
  <section class="panel">
    <h2>Budget headroom</h2>

    <h3>Per-key dollar caps</h3>
    <ErrorState
      v-if="keysReq.error.value"
      :error="keysReq.error.value"
      title="Could not list keys"
      @retry="refresh"
    />
    <EmptyState
      v-else-if="!keysReq.loading.value && !rows.length"
      message="No key carries a dollar cap. Set max_budget_usd on a key, or grant a budget override, and its headroom appears here."
    />
    <template v-else-if="rows.length">
      <p class="hint" v-if="selection.truncated">
        Showing {{ rows.length }} of {{ selection.total }} capped keys,
        {{ orderNote }}.
      </p>
      <p class="hint" v-if="degradedBackends.length">
        The governance backend is reporting
        {{ degradedBackends.join(" and ") }}. These balances may be behind
        what the request path is enforcing.
      </p>
      <p class="hint" v-else-if="approximateBackend">
        This backend settles approximately, so a balance can lag the last
        few requests.
      </p>
      <ul class="caps">
        <li v-for="row in rows" :key="row.id" class="cap">
          <div class="cap__head">
            <span class="cap__name sb-mono">{{ row.label }}</span>
            <span v-if="row.bar" class="cap__figures">
              {{ formatUsd(row.bar.usedUsd) }} used,
              {{ formatUsd(row.bar.reservedUsd) }} held, of
              {{ formatUsd(row.bar.limitUsd) }}
              <StatusBadge
                :label="`${(row.bar.ratio * 100).toFixed(0)}%`"
                :tone="row.bar.tone"
              />
            </span>
            <span v-else-if="row.error" class="cap__figures sb-faint">
              headroom not reported: {{ row.error }}
            </span>
            <span v-else-if="row.ledgerHasNoCap" class="cap__figures sb-faint">
              the policy declares {{ formatUsd(row.capUsd) }} and the ledger
              enforces no dollar cap
            </span>
            <span v-else class="cap__figures sb-faint">reading the ledger</span>
          </div>
          <div class="cap__track" v-if="row.bar">
            <!-- Money already settled, then money committed and not yet
                 settled. Hiding the held segment understates the wall by
                 exactly that much. -->
            <div
              class="cap__used"
              :style="{
                width: `${row.bar.usedPct}%`,
                background: `var(--sb-${row.bar.tone === 'ok' ? 'chart-1' : row.bar.tone})`,
              }"
            />
            <div
              class="cap__held"
              :style="{
                width: `${row.bar.reservedPct}%`,
                background: `var(--sb-${row.bar.tone === 'ok' ? 'chart-1' : row.bar.tone})`,
              }"
            />
          </div>
          <p class="cap__foot sb-faint" v-if="row.bar">
            {{ formatUsd(row.bar.remainingUsd) }} left,
            {{
              row.resetAtMillis === null
                ? "no reset"
                : `resets ${formatTime(row.resetAtMillis)}`
            }}
          </p>
        </li>
      </ul>
    </template>

    <h3>Utilization by scope</h3>
    <p class="hint">
      Highest single budget in each scope. This gauge carries no identity,
      so it cannot say which workspace or which key.
    </p>
    <p v-if="scopes === undefined" class="hint sb-faint">
      Budget utilization is not reported. The gauge appears once an AI
      budget is configured.
    </p>
    <p v-else-if="!scopes.length" class="hint sb-faint">
      No scope has reported a utilization sample yet.
    </p>
    <div v-else class="scopes">
      <div class="scope" v-for="scope in scopes" :key="scope.scope">
        <div class="scope__head">
          <span class="sb-mono">{{ scope.scope }}</span>
          <StatusBadge
            :label="`${(scope.ratio * 100).toFixed(0)}%`"
            :tone="scope.tone"
          />
        </div>
        <div class="scope__track">
          <div
            class="scope__fill"
            :style="{
              width: `${Math.min(100, scope.ratio * 100)}%`,
              background: `var(--sb-${scope.tone === 'ok' ? 'chart-1' : scope.tone})`,
            }"
          />
        </div>
      </div>
    </div>

    <!-- (c) Rate-limit tiers, not money. Its own component, because it
         owns the resume control and the 404-means-not-configured case. -->
    <WorkspaceBudgets only-when-noteworthy />
  </section>
</template>

<style scoped>
.panel {
  margin-bottom: 24px;
}
.panel h2 {
  font-size: 13px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--sb-text-muted);
  margin: 0 0 8px;
}
.panel h3 {
  font-size: 13px;
  font-weight: 600;
  color: var(--sb-text);
  margin: 20px 0 6px;
}
.hint {
  font-size: 13px;
  color: var(--sb-text-muted);
  margin: 4px 0 8px;
}
.caps {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.cap__head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 12px;
  font-size: 0.8rem;
  flex-wrap: wrap;
}
.cap__name {
  font-size: 0.74rem;
  color: var(--sb-text-muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 55%;
}
.cap__figures {
  font-variant-numeric: tabular-nums;
  display: inline-flex;
  align-items: baseline;
  gap: 8px;
}
.cap__track {
  display: flex;
  height: 8px;
  margin-top: 5px;
  background: var(--sb-bg-sunken);
}
.cap__used {
  height: 100%;
}
.cap__held {
  height: 100%;
  opacity: 0.42;
}
.cap__foot {
  margin: 4px 0 0;
  font-size: 0.72rem;
}
.scopes {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 10px 24px;
}
.scope__head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  font-size: 0.74rem;
  margin-bottom: 4px;
}
.scope__track {
  height: 6px;
  background: var(--sb-bg-sunken);
}
.scope__fill {
  height: 100%;
}
</style>
