<script setup lang="ts">
/*
 * Agents: the owner-approval queue and the verified catalog.
 *
 * The queue is the reason this page exists. A pending registration is a
 * question somebody has to answer, and until this landed the only way to
 * see one was a curl against the admin API. The catalog is read only here:
 * it comes from a signed feed, so the only mutation this page offers is
 * "verify the file again".
 */
import { computed, onMounted, ref } from "vue";
import {
  api,
  type AgentCatalogResponse,
  type AgentRegistration,
  type AgentRegistrationState,
  type AgentRegistrySummary,
} from "../api";
import { useAsync } from "../composables/useAsync";
import PageHeader from "../components/PageHeader.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";
import StatCard from "../components/StatCard.vue";
import StatusBadge from "../components/StatusBadge.vue";

const summary = useAsync(() => api.agentRegistrySummary());
const registrations = useAsync(() => api.agentRegistrations());
const catalog = useAsync(() => api.agentRegistryCatalog());

const filter = ref<AgentRegistrationState | "all">("pending");
const reasons = ref<Record<string, string>>({});
const busy = ref<string | null>(null);
const notice = ref<string | null>(null);

function refreshAll() {
  summary.run();
  registrations.run();
  catalog.run();
}
onMounted(refreshAll);

/*
 * A 404 from every route means `proxy.agent_registry` is absent or
 * disabled. That is a configuration state, not a failure, and rendering it
 * as an error is how an operator ends up debugging a working proxy.
 */
const notConfigured = computed(
  () => !!summary.error.value && String(summary.error.value).includes("404"),
);

const stats = computed<AgentRegistrySummary | null>(() => summary.data.value ?? null);

const rows = computed<AgentRegistration[]>(() => {
  const items = registrations.data.value?.items ?? [];
  return filter.value === "all"
    ? items
    : items.filter((row) => row.state === filter.value);
});

const catalogData = computed<AgentCatalogResponse | null>(() => catalog.data.value ?? null);

function badgeTone(state: AgentRegistrationState): "ok" | "warn" | "err" | "neutral" {
  switch (state) {
    case "approved":
      return "ok";
    case "pending":
      return "warn";
    case "rejected":
    case "revoked":
      return "err";
    default:
      return "neutral";
  }
}

async function decide(
  row: AgentRegistration,
  decision: "approve" | "reject" | "revoke",
) {
  busy.value = row.agent_id;
  notice.value = null;
  try {
    await api.agentRegistrationDecide(
      row.agent_id,
      decision,
      reasons.value[row.agent_id]?.trim() || undefined,
    );
    delete reasons.value[row.agent_id];
    notice.value = `${row.agent_id} ${decision}d.`;
    refreshAll();
  } catch (error) {
    notice.value = String(error);
  } finally {
    busy.value = null;
  }
}

async function refreshFeed() {
  busy.value = "__feed";
  notice.value = null;
  try {
    const result = await api.agentRegistryRefresh();
    notice.value = `Catalog reverified: ${result.entries} entries.`;
    refreshAll();
  } catch (error) {
    notice.value = String(error);
  } finally {
    busy.value = null;
  }
}
</script>

<template>
  <PageHeader
    title="Agents"
    subtitle="The owner-approval queue for agents that registered themselves, and the signed catalog of agents somebody else vouched for."
  />

  <EmptyState
    v-if="notConfigured"
    message="proxy.agent_registry is not configured on this proxy. Set agent_registry.enabled and agent_registry.store_path to open the approval queue; see docs/agent-registry.md."
  />

  <ErrorState
    v-else-if="summary.error.value && !stats"
    :error="summary.error.value"
    title="Could not load the agent registry"
    @retry="refreshAll"
  />

  <template v-else>
    <div v-if="stats" class="stats">
      <StatCard label="Pending" :value="String(stats.pending)" />
      <StatCard label="Approved" :value="String(stats.approved)" />
      <StatCard label="Rejected" :value="String(stats.rejected)" />
      <StatCard label="Revoked" :value="String(stats.revoked)" />
      <StatCard label="Catalog" :value="String(stats.catalog_entries)" />
    </div>

    <p v-if="notice" class="notice sb-mono">{{ notice }}</p>

    <h2 class="section">Approval queue</h2>

    <div class="filters sb-mono">
      <button
        v-for="option in (['pending', 'approved', 'rejected', 'revoked', 'all'] as const)"
        :key="option"
        class="sb-btn sb-btn--sm"
        :class="{ 'sb-btn--primary': filter === option }"
        @click="filter = option"
      >
        {{ option }}
      </button>
    </div>

    <EmptyState
      v-if="!rows.length && !registrations.loading.value"
      message="No registrations in this state. A submission arrives through POST /admin/agent-registry/registrations."
    />

    <div v-else class="sb-card table-wrap">
      <table class="sb-table">
        <thead>
          <tr>
            <th>Agent</th>
            <th>Vendor</th>
            <th>Purpose</th>
            <th>State</th>
            <th>Decided by</th>
            <th>Decision</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="row.agent_id">
            <td class="sb-mono">{{ row.agent_id }}</td>
            <td>{{ row.metadata.vendor }}</td>
            <td class="sb-mono">{{ row.metadata.purpose }}</td>
            <td>
              <StatusBadge :tone="badgeTone(row.state)" :label="row.state" />
            </td>
            <td class="sb-mono">{{ row.decided_by || "-" }}</td>
            <td>
              <div v-if="row.state === 'pending' || row.state === 'approved'" class="decide">
                <input
                  v-model="reasons[row.agent_id]"
                  class="sb-input reason"
                  type="text"
                  placeholder="reason"
                />
                <button
                  v-if="row.state === 'pending'"
                  class="sb-btn sb-btn--sm"
                  :disabled="busy === row.agent_id"
                  @click="decide(row, 'approve')"
                >
                  approve
                </button>
                <button
                  v-if="row.state === 'pending'"
                  class="sb-btn sb-btn--sm"
                  :disabled="busy === row.agent_id || !reasons[row.agent_id]?.trim()"
                  :title="
                    reasons[row.agent_id]?.trim()
                      ? 'Reject permanently. This description cannot be resubmitted.'
                      : 'A rejection needs a reason: it refuses this description for good.'
                  "
                  @click="decide(row, 'reject')"
                >
                  reject
                </button>
                <button
                  v-if="row.state === 'approved'"
                  class="sb-btn sb-btn--sm"
                  :disabled="busy === row.agent_id"
                  @click="decide(row, 'revoke')"
                >
                  revoke
                </button>
              </div>
              <span v-else class="sb-mono muted">{{ row.reason || "-" }}</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <h2 class="section">Verified catalog</h2>

    <p v-if="stats && !stats.feed_configured" class="note">
      No feed is configured, so the catalog can only hold what the store last
      cached. Set <code class="sb-mono">agent_registry.feed_path</code>,
      <code class="sb-mono">agent_registry.key_directory_path</code>, and
      <code class="sb-mono">agent_registry.bootstrap_keys</code> to refresh it.
    </p>
    <p v-else-if="stats && stats.bootstrap_keys === 0" class="note">
      A feed is configured but no bootstrap keys are, so no key directory can
      be trusted and every refresh will be refused. Nothing is baked into the
      binary on purpose.
    </p>
    <div v-else class="feed-actions">
      <button class="sb-btn sb-btn--sm" :disabled="busy === '__feed'" @click="refreshFeed">
        reverify feed
      </button>
      <span v-if="catalogData?.expired" class="expired sb-mono">
        expired at {{ catalogData?.expires_at }}
      </span>
    </div>

    <EmptyState
      v-if="!catalogData?.entries?.length && !catalog.loading.value"
      message="The catalog is empty. It fills from a signed feed; nothing is applied unless the signature verifies."
    />

    <div v-else class="sb-card table-wrap">
      <table class="sb-table">
        <thead>
          <tr>
            <th>Agent</th>
            <th>Vendor</th>
            <th>Purpose</th>
            <th>Reputation</th>
            <th>Flags</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="entry in catalogData?.entries ?? []" :key="entry.agent_id">
            <td class="sb-mono">{{ entry.agent_id }}</td>
            <td>{{ entry.vendor }}</td>
            <td class="sb-mono">{{ entry.purpose }}</td>
            <td class="sb-mono">{{ entry.reputation_score }}</td>
            <td class="sb-mono">{{ entry.flags.join(", ") || "-" }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </template>
</template>

<style scoped>
.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}
.section {
  margin: 28px 0 12px;
  font-size: 16px;
}
.filters {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
  flex-wrap: wrap;
}
.table-wrap {
  overflow-x: auto;
}
.decide {
  display: flex;
  gap: 6px;
  align-items: center;
}
.reason {
  min-width: 160px;
}
.feed-actions {
  display: flex;
  gap: 12px;
  align-items: center;
  margin-bottom: 12px;
}
.expired {
  color: var(--sb-muted);
}
.muted {
  color: var(--sb-muted);
}
.notice {
  margin: 0 0 16px;
  font-size: 13px;
}
.note {
  margin: 0 0 14px;
  color: var(--sb-muted);
  font-size: 13px;
  max-width: 68ch;
}
</style>
