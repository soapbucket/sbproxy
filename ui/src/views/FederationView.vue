<script setup lang="ts">
/*
 * Federation: the OpenID Federation identity this proxy publishes, and
 * what it requires of a peer.
 *
 * `GET /admin/federation` shipped ahead of this page with a note beside
 * it saying the console was separate scope, and until now the only way
 * to read it was curl. The route exists at all because the crate's own
 * `/admin/status` is never mounted in this process: sbproxy serves the
 * well-known endpoints off the Pingora request path rather than the
 * crate's axum router.
 *
 * Two halves, and the second is the one people forget. What this proxy
 * publishes is discoverable by anyone who fetches the entity statement.
 * What it *requires* of a peer is not, and a peer verifier that is
 * present but not required is a control that looks configured and
 * enforces nothing.
 */
import { computed, onMounted } from "vue";
import { api, type FederationStatus } from "../api";
import { useAsync } from "../composables/useAsync";
import PageHeader from "../components/PageHeader.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";
import StatCard from "../components/StatCard.vue";
import StatusBadge from "../components/StatusBadge.vue";

const federation = useAsync(() => api.federation());
onMounted(federation.run);

const status = computed<FederationStatus | null>(() => federation.data.value ?? null);

/*
 * A process with no `federation` block answers `{"enabled": false}`
 * rather than 404, so this is read off the body rather than off an error
 * status. That is the whole reason the route was built to answer instead
 * of 404ing, and rendering it as an error would send an operator to
 * debug a proxy that is working exactly as configured.
 */
const notConfigured = computed(
  () => federation.succeeded.value && status.value?.enabled === false,
);

const peerTrust = computed(() => status.value?.peer_trust ?? null);

/*
 * `cache_remaining_secs` is null when the entity statement could not be
 * built, which is the same failure the well-known route answers 503
 * with. The route deliberately keeps the rest of the response readable
 * in that state, so say what null means rather than printing a blank.
 */
const cacheRemaining = computed(() => {
  const remaining = status.value?.cache_remaining_secs;
  if (remaining === null) return "unavailable";
  if (remaining === undefined) return "n/a";
  return `${remaining}s`;
});

/*
 * A verifier that is configured but not required verifies a peer
 * statement when one is presented and admits a peer that presents none.
 * That is a legitimate rollout posture and a bad surprise to discover
 * during an incident, so it gets its own words rather than a boolean.
 */
const peerTrustSummary = computed(() => {
  const trust = peerTrust.value;
  if (!trust || !trust.configured) {
    return "No peer verifier is configured. A peer's entity statement is not checked.";
  }
  return trust.required
    ? "A peer must present an entity statement, and it is verified against the pinned anchors."
    : "A peer statement is verified when presented, and a peer that presents none is still admitted.";
});
</script>

<template>
  <PageHeader
    title="Federation"
    subtitle="The OpenID Federation entity this proxy publishes, and what it requires of a peer."
  >
    <template #actions>
      <button class="sb-btn" :disabled="federation.loading.value" @click="federation.run">
        {{ federation.loading.value ? "Loading..." : "Refresh" }}
      </button>
    </template>
  </PageHeader>

  <EmptyState
    v-if="notConfigured"
    message="OpenID Federation is not configured on this node. Add a federation block to publish an entity configuration and to verify a peer's."
  />
  <ErrorState
    v-else-if="federation.error.value"
    :error="federation.error.value"
    @retry="federation.run"
  />
  <template v-else-if="status?.enabled">
    <section class="section">
      <div class="section__head">
        <h2>Published identity</h2>
        <span class="sb-faint">What a peer resolving this proxy sees</span>
      </div>
      <div class="stat-grid">
        <StatCard label="published keys" :value="status.published_keys ?? 0" />
        <StatCard label="authority hints" :value="status.authority_hints ?? 0" />
        <StatCard label="trust marks" :value="status.trust_marks ?? 0" />
        <StatCard label="statement cacheable for" :value="cacheRemaining" />
      </div>
      <div class="table-wrap">
        <table class="sb-table">
          <tbody>
            <tr>
              <th>Entity ID</th>
              <td class="sb-mono">{{ status.entity_id }}</td>
            </tr>
            <tr>
              <th>Signing key</th>
              <td class="sb-mono">
                {{ status.signing_kid }}
                <span class="sb-faint">({{ status.signing_algorithm }})</span>
              </td>
            </tr>
            <tr>
              <th>Statement lifetime</th>
              <td class="sb-mono">
                {{ status.lifetime_secs }}s, refreshed {{ status.refresh_margin_secs }}s early
              </td>
            </tr>
            <tr>
              <th>Metadata policy</th>
              <td>
                <StatusBadge
                  :label="status.metadata_policy_configured ? 'configured' : 'none'"
                  :tone="status.metadata_policy_configured ? 'ok' : 'neutral'"
                />
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <section class="section">
      <div class="section__head">
        <h2>Peer trust</h2>
        <span class="sb-faint">What this proxy requires of a peer</span>
        <StatusBadge
          :label="peerTrust?.configured ? 'configured' : 'not configured'"
          :tone="peerTrust?.configured ? 'ok' : 'warn'"
        />
      </div>
      <p class="sb-faint">{{ peerTrustSummary }}</p>
      <div class="table-wrap" v-if="peerTrust?.configured">
        <table class="sb-table">
          <tbody>
            <tr>
              <th>Enforcement</th>
              <td>
                <StatusBadge
                  :label="peerTrust.required ? 'required' : 'optional'"
                  :tone="peerTrust.required ? 'ok' : 'warn'"
                />
              </td>
            </tr>
            <tr>
              <th>Header</th>
              <td class="sb-mono">{{ peerTrust.header }}</td>
            </tr>
            <tr>
              <th>Pinned anchors</th>
              <td class="sb-mono">{{ peerTrust.pinned_anchors ?? 0 }}</td>
            </tr>
            <tr>
              <th>Cached peer decisions</th>
              <td class="sb-mono">{{ peerTrust.cached_peer_decisions ?? 0 }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </template>
</template>

<style scoped>
.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: var(--sb-space-3);
  margin-bottom: var(--sb-space-4);
}
</style>
