<script setup lang="ts">
/*
 * Licensing: the CoMP marketplace bridge and the OLP issuer, per origin.
 *
 * `GET /admin/licensing` shipped under WOR-2673 with a note in
 * `docs/admin-api-reference.md` saying the console page was separate
 * scope. Until now an operator running `comp:` could not ask what the
 * proxy was publishing short of fetching the manifest as a buyer would
 * and counting tiers by hand.
 *
 * Nothing secret is on this page because nothing secret is on the route:
 * a signing key is named by its `kid`, the content-key seed is reported
 * as present or absent, and the revocation store is named by variant
 * because a Redis URL routinely carries a password in its userinfo.
 * Keep it that way: read named fields, never render the response blob.
 */
import { computed, onMounted } from "vue";
import { api, type LicensingOrigin } from "../api";
import { useAsync } from "../composables/useAsync";
import PageHeader from "../components/PageHeader.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";
import StatusBadge from "../components/StatusBadge.vue";

const licensing = useAsync(() => api.licensing());
onMounted(licensing.run);

const origins = computed<LicensingOrigin[]>(
  () => licensing.data.value?.origins ?? [],
);

/*
 * `enabled: false` means no origin has either a CoMP bridge or an OLP
 * issuer. A configuration state, not a fault, and read off the body
 * because the route answers 200 rather than 404 for exactly this reason.
 */
const notConfigured = computed(
  () => licensing.succeeded.value && licensing.data.value?.enabled === false,
);

/*
 * The one thing on this page worth paging someone about.
 *
 * `active_signing_kid` is null until a rotation has been activated, and
 * every quote request fails closed until one is. That reads as a
 * mysterious total outage from the buyer side, and as a blank field
 * here, so it gets promoted to a banner rather than left in a table.
 */
const unactivated = computed(() =>
  origins.value.filter(
    (origin) => origin.comp.enabled && !origin.comp.active_signing_kid,
  ),
);

/*
 * Only OLP tiers are redeemable for a token. A catalog carrying `cap` or
 * `public` tiers reports a larger total, and an operator reading
 * "12 tiers" while seeing one redeem a day needs to know that eleven of
 * them were never redeemable in the first place.
 */
function tierSummary(origin: LicensingOrigin): string {
  const total = origin.comp.tier_count ?? 0;
  const redeemable = origin.comp.olp_tier_count ?? 0;
  if (total === redeemable) return `${total} tiers, all redeemable`;
  return `${total} tiers, ${redeemable} redeemable for a token`;
}
</script>

<template>
  <PageHeader
    title="Licensing"
    subtitle="CoMP marketplace bridges and OLP issuers: what each origin publishes and which keys are live."
  >
    <template #actions>
      <button class="sb-btn" :disabled="licensing.loading.value" @click="licensing.run">
        {{ licensing.loading.value ? "Loading..." : "Refresh" }}
      </button>
    </template>
  </PageHeader>

  <EmptyState
    v-if="notConfigured"
    message="No origin on this node has a CoMP marketplace bridge or an OLP issuer configured."
  />
  <ErrorState
    v-else-if="licensing.error.value"
    :error="licensing.error.value"
    @retry="licensing.run"
  />
  <template v-else>
    <div v-if="unactivated.length" class="warn-banner">
      <strong>No rotation activated</strong>
      <p>
        {{ unactivated.map((o) => o.hostname).join(", ") }}
        has a bridge with no active quote-signing key. Every quote request fails
        closed until a rotation is activated.
      </p>
    </div>

    <section v-for="origin in origins" :key="origin.hostname" class="section">
      <div class="section__head">
        <h2 class="sb-mono">{{ origin.hostname }}</h2>
        <StatusBadge
          :label="origin.comp.enabled ? 'comp' : 'no comp'"
          :tone="origin.comp.enabled ? 'ok' : 'neutral'"
        />
        <StatusBadge
          :label="origin.olp.enabled ? 'olp' : 'no olp'"
          :tone="origin.olp.enabled ? 'ok' : 'neutral'"
        />
      </div>

      <div class="table-wrap" v-if="origin.comp.enabled">
        <table class="sb-table">
          <tbody>
            <tr>
              <th>Publisher</th>
              <td>
                {{ origin.comp.publisher_name }}
                <span class="sb-faint sb-mono">{{ origin.comp.publisher_domain }}</span>
              </td>
            </tr>
            <tr>
              <th>Catalog</th>
              <td>{{ tierSummary(origin) }}</td>
            </tr>
            <tr>
              <th>Active signing key</th>
              <td>
                <span v-if="origin.comp.active_signing_kid" class="sb-mono">
                  {{ origin.comp.active_signing_kid }}
                </span>
                <StatusBadge v-else label="none activated" tone="err" />
                <span class="sb-faint">
                  {{ origin.comp.trusted_kid_count ?? 0 }} trusted
                </span>
              </td>
            </tr>
            <tr>
              <th>Manifest</th>
              <td class="sb-mono">
                {{ origin.comp.manifest_hash }}
                <span class="sb-faint">generated {{ origin.comp.generated_at }}</span>
              </td>
            </tr>
            <tr>
              <th>Endpoints</th>
              <td class="sb-mono endpoints">
                <span>{{ origin.comp.endpoints?.manifest }}</span>
                <span>{{ origin.comp.endpoints?.quote }}</span>
                <span>{{ origin.comp.endpoints?.redeem }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="table-wrap" v-if="origin.olp.enabled">
        <table class="sb-table">
          <tbody>
            <tr>
              <th>OLP issuer</th>
              <td class="sb-mono">{{ origin.olp.issuer }}</td>
            </tr>
            <tr>
              <th>Signing key</th>
              <td class="sb-mono">{{ origin.olp.signing_kid }}</td>
            </tr>
            <tr>
              <th>Token defaults</th>
              <td class="sb-mono">
                scope {{ origin.olp.default_scope }}, ttl
                {{ origin.olp.default_ttl_secs }}s
              </td>
            </tr>
            <tr>
              <th>Content key claim</th>
              <td>
                <StatusBadge
                  :label="origin.olp.content_key_configured ? 'stamped' : 'not stamped'"
                  :tone="origin.olp.content_key_configured ? 'ok' : 'neutral'"
                />
              </td>
            </tr>
            <tr>
              <th>Introspection and revocation</th>
              <td>
                <template v-if="origin.olp.introspect?.enabled">
                  <span class="sb-mono">
                    {{ origin.olp.introspect.introspect_path }},
                    {{ origin.olp.introspect.revoke_path }}
                  </span>
                  <div class="sb-faint">
                    revocation state in
                    {{ origin.olp.introspect.revocation_store }}
                  </div>
                </template>
                <StatusBadge v-else label="not mounted" tone="neutral" />
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </template>
</template>

<style scoped>
.warn-banner {
  border: 1px solid var(--sb-border-strong);
  border-left: 3px solid var(--sb-err);
  border-radius: var(--sb-radius);
  padding: var(--sb-space-4);
  margin-bottom: var(--sb-space-4);
}
.warn-banner p {
  margin: var(--sb-space-2) 0 0;
  color: var(--sb-text-muted);
}
.endpoints {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
</style>
