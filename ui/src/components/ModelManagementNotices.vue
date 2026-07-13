<script setup lang="ts">
import type { ApiError } from "../api";
import type { DeploymentConflictState } from "../lib/model-management";
import ErrorState from "./ErrorState.vue";
import StatusBadge from "./StatusBadge.vue";

defineProps<{
  banner: { tone: "ok" | "warn" | "err"; text: string } | null;
  statusError: ApiError | null;
  hasStatus: boolean;
  desiredError: ApiError | null;
  catalogError: ApiError | null;
  clusterAuthorityError: ApiError | null;
  clusterBundleError: ApiError | null;
  clusterAuthorityMode: boolean;
  initialClusterBundleAbsent: boolean;
  catalogLoaded: boolean;
  catalogModelCount: number;
  previewOnlyCatalog: boolean;
  blockers: readonly string[];
  blockerRecommendation?: string | null;
  conflict: DeploymentConflictState | null;
  editorOpen: boolean;
  mutationError: string | null;
  mutationBusy: boolean;
  conflictRetryAllowed: boolean;
}>();

defineEmits<{
  (event: "retry-status"): void;
  (event: "retry-desired"): void;
  (event: "retry-catalog"): void;
  (event: "retry-authority"): void;
  (event: "retry-bundle"): void;
  (event: "retry-conflict"): void;
  (event: "reload-conflict"): void;
  (event: "dismiss-conflict"): void;
}>();
</script>

<template>
  <p
    v-if="banner"
    class="banner"
    :class="`banner--${banner.tone}`"
    :role="banner.tone === 'err' ? 'alert' : 'status'"
    :aria-live="banner.tone === 'err' ? 'assertive' : 'polite'"
  >
    {{ banner.text }}
  </p>

  <ErrorState
    v-if="statusError && !hasStatus"
    :error="statusError"
    title="Could not load runtime lifecycle status"
    @retry="$emit('retry-status')"
  />
  <section
    v-else-if="statusError"
    class="metadata-warning"
    aria-label="Runtime refresh warning"
    role="status"
    aria-live="polite"
  >
    <div>
      <strong>Showing the last loaded runtime lifecycle status.</strong>
      <p>{{ statusError.hint }}</p>
    </div>
    <button class="sb-btn sb-btn--sm" @click="$emit('retry-status')">Retry runtime</button>
  </section>

  <section
    v-if="desiredError"
    class="metadata-warning metadata-warning--error"
    aria-label="Desired state warning"
    role="alert"
  >
    <div>
      <strong>Desired deployment metadata is unavailable.</strong>
      <p>Runtime lifecycle status and controls remain available. {{ desiredError.hint }}</p>
    </div>
    <button class="sb-btn sb-btn--sm" @click="$emit('retry-desired')">Retry desired state</button>
  </section>

  <section
    v-if="catalogError"
    class="metadata-warning metadata-warning--error"
    aria-label="Catalog warning"
    role="alert"
  >
    <div>
      <strong>The active model catalog is unavailable.</strong>
      <p>Existing lifecycle controls remain available, but deployment editing is paused.</p>
    </div>
    <button class="sb-btn sb-btn--sm" @click="$emit('retry-catalog')">Retry catalog</button>
  </section>

  <section
    v-if="clusterAuthorityMode && clusterAuthorityError"
    class="metadata-warning"
    aria-label="Cluster authority warning"
    role="alert"
  >
    <div>
      <strong>Cluster authority state could not be verified.</strong>
      <p>Signed publication is paused. Lifecycle controls remain local and available.</p>
    </div>
    <button class="sb-btn sb-btn--sm" @click="$emit('retry-authority')">Retry authority</button>
  </section>

  <section
    v-if="
      clusterAuthorityMode &&
      clusterBundleError &&
      !initialClusterBundleAbsent
    "
    class="metadata-warning"
    aria-label="Signed bundle warning"
    role="alert"
  >
    <div>
      <strong>The active signed deployment bundle could not be verified.</strong>
      <p>Signed publication is paused while current bundle state is unavailable.</p>
    </div>
    <button class="sb-btn sb-btn--sm" @click="$emit('retry-bundle')">Retry bundle</button>
  </section>

  <section
    v-if="catalogLoaded && catalogModelCount === 0"
    class="catalog-notice catalog-notice--empty"
    role="status"
    aria-live="polite"
  >
    <StatusBadge label="No deployable variants" tone="warn" />
    <div>
      <h3>The active catalog cannot create a deployment</h3>
      <p>Add a complete stable or preview variant with at least one engine and accelerator, then refresh this view.</p>
    </div>
  </section>
  <section v-else-if="previewOnlyCatalog" class="catalog-notice" role="status" aria-live="polite">
    <StatusBadge label="Preview catalog" tone="warn" />
    <div>
      <h3>All selectable variants are preview</h3>
      <p>Preview variants remain selectable. Review their compatibility evidence and license before publishing.</p>
    </div>
  </section>

  <section
    v-if="blockers.length"
    class="sb-card blockers"
    aria-labelledby="blockers-heading"
    role="alert"
  >
    <div>
      <p class="sb-eyebrow">Local admission</p>
      <h2 id="blockers-heading">Serving is blocked on this host</h2>
    </div>
    <ul>
      <li
        v-for="(blocker, blockerIndex) in blockers"
        :key="`${blockerIndex}:${blocker}`"
      >
        {{ blocker }}
      </li>
    </ul>
    <p v-if="blockerRecommendation" class="sb-faint">
      Recommended fix: <span class="sb-mono">{{ blockerRecommendation }}</span>
    </p>
    <p class="sb-faint">Run <span class="sb-mono">sbproxy doctor</span> on this host for the full report.</p>
  </section>

  <section v-if="conflict && !editorOpen" class="conflict-banner" role="alert">
    <div>
      <strong>Desired state changed before your replacement was accepted.</strong>
      <p>
        Conflict response {{ conflict.status }}. Expected revision
        {{ conflict.expectedRevision ?? "none" }}. Your removal draft is preserved.
      </p>
      <pre class="raw-conflict">{{ conflict.body || "(empty response body)" }}</pre>
      <p v-if="conflict.comparison">
        Current revision {{ conflict.currentRevision ?? "none" }}:
        {{ conflict.comparison.added.length }} added,
        {{ conflict.comparison.changed.length }} changed,
        {{ conflict.comparison.removed.length }} removed compared with the current map.
      </p>
      <p v-else>
        {{ conflict.reloadError || "Current authority state is still loading." }}
      </p>
    </div>
    <div class="conflict-actions">
      <button class="sb-btn sb-btn--sm" :disabled="mutationBusy" @click="$emit('dismiss-conflict')">
        Dismiss draft
      </button>
      <button
        v-if="!conflict.comparison"
        class="sb-btn sb-btn--sm"
        :disabled="mutationBusy"
        @click="$emit('reload-conflict')"
      >
        {{ mutationBusy ? "Reloading..." : "Reload current state" }}
      </button>
      <button
        class="sb-btn sb-btn--primary sb-btn--sm"
        :disabled="mutationBusy || !conflictRetryAllowed"
        @click="$emit('retry-conflict')"
      >
        {{ mutationBusy ? "Saving..." : "Retry replacement" }}
      </button>
    </div>
  </section>
  <section v-else-if="mutationError && !editorOpen" class="mutation-error" role="alert">
    <strong>Desired state was not changed.</strong>
    <span>{{ mutationError }}</span>
  </section>
</template>

<style scoped>
.banner {
  padding: var(--sb-space-3) var(--sb-space-4);
  margin: 0 0 var(--sb-space-4);
  border: 1px solid transparent;
  border-radius: var(--sb-radius-sm);
  font-size: 0.84rem;
}

.banner--ok {
  color: var(--sb-ok);
  background: var(--sb-ok-bg);
  border-color: var(--sb-ok);
}

.banner--warn {
  color: var(--sb-warn-fg);
  background: var(--sb-warn-bg);
  border-color: var(--sb-warn);
}

.banner--err {
  color: var(--sb-err);
  background: var(--sb-err-bg);
  border-color: var(--sb-err);
}

.metadata-warning,
.catalog-notice,
.conflict-banner,
.mutation-error {
  display: flex;
  align-items: flex-start;
  gap: var(--sb-space-3);
  padding: var(--sb-space-3) var(--sb-space-4);
  margin-bottom: var(--sb-space-4);
  border-radius: var(--sb-radius);
  font-size: 0.8rem;
  min-width: 0;
  overflow-wrap: anywhere;
}

.metadata-warning > div,
.catalog-notice > div,
.conflict-banner > div {
  min-width: 0;
}

.metadata-warning {
  color: var(--sb-warn-fg);
  background: var(--sb-warn-bg);
  border: 1px solid var(--sb-warn);
}

.metadata-warning--error {
  color: var(--sb-err);
  background: var(--sb-err-bg);
  border-color: var(--sb-err);
}

.metadata-warning p,
.catalog-notice p,
.conflict-banner p {
  margin: 2px 0 0;
}

.metadata-warning button {
  margin-left: auto;
}

.catalog-notice {
  background: var(--sb-surface);
  border: 1px solid var(--sb-border-strong);
}

.catalog-notice h3 {
  font-size: 0.86rem;
}

.catalog-notice p,
.mutation-error span {
  color: var(--sb-text-muted);
}

.catalog-notice--empty {
  border-color: var(--sb-warn);
}

.blockers {
  display: grid;
  grid-template-columns: minmax(220px, 0.7fr) minmax(0, 1.3fr);
  gap: var(--sb-space-4);
  margin-bottom: var(--sb-space-5);
  border-left: 4px solid var(--sb-err);
}

.blockers .sb-eyebrow {
  margin: 0 0 var(--sb-space-1);
}

.blockers ul {
  margin: 0;
  padding-left: 1.2em;
}

.blockers > p {
  grid-column: 1 / -1;
  margin: 0;
}

.conflict-banner {
  justify-content: space-between;
  color: var(--sb-warn-fg);
  background: var(--sb-warn-bg);
  border: 1px solid var(--sb-warn);
}

.conflict-actions {
  display: flex;
  gap: var(--sb-space-2);
  flex: none;
}

.raw-conflict {
  max-width: 100%;
  margin: var(--sb-space-2) 0;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.mutation-error {
  color: var(--sb-err);
  background: var(--sb-err-bg);
  border: 1px solid var(--sb-err);
}

@media (max-width: 760px) {
  .metadata-warning,
  .conflict-banner,
  .mutation-error {
    align-items: flex-start;
    flex-direction: column;
  }

  .metadata-warning button {
    margin-left: 0;
  }

  .blockers {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 520px) {
  .conflict-actions {
    flex-direction: column;
    width: 100%;
  }
}
</style>
