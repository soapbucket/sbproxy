<script setup lang="ts">
/*
 * Notifications: outbound webhook subscriptions and the deadletter queue.
 *
 * The deadletter queue is the reason this page exists. A delivery that used
 * its whole attempt budget is the one outcome that needs a human, and until
 * this landed the only way to see one was a curl against the admin API.
 *
 * The signing secret appears exactly once, in the response to the call that
 * minted it. This page shows it in a dismissible banner and never stores
 * it: there is no read path that could get it back.
 */
import { computed, onMounted, ref } from "vue";
import {
  api,
  ApiError,
  type NotifierSummary,
  type NotifyDeadLetter,
  type NotifySubscription,
} from "../api";
import { useAsync } from "../composables/useAsync";
import PageHeader from "../components/PageHeader.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";
import StatCard from "../components/StatCard.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ClickToCopy from "../components/ClickToCopy.vue";

const summary = useAsync(() => api.notifySummary());
const subscriptions = useAsync(() => api.notifySubscriptions());
const deadletters = useAsync(() =>
  api.notifyDeadletters(deadletterCursor.value ?? undefined),
);

const newUrl = ref("");
/*
 * Empty, not "*". This shipped pre-filled with the wildcard, so the
 * shortest path through the page was paste a URL, click subscribe, and
 * receive one webhook delivery per proxied request from a worker that
 * cannot serve them. The server refuses a wildcard without the box below
 * now; the default here is what stops an operator meeting that refusal by
 * accident in the first place.
 */
const newFilters = ref("");
const allowFirehose = ref(false);
const mintedSecret = ref<string | null>(null);
const deadletterCursor = ref<string | null>(null);
const busy = ref<string | null>(null);
const notice = ref<string | null>(null);

function refreshAll() {
  summary.run();
  subscriptions.run();
  // Back to the first page: an action that changed the queue makes a
  // cursor into the middle of the old one meaningless.
  deadletterCursor.value = null;
  deadletters.run();
}
onMounted(refreshAll);

/*
 * A 404 means `proxy.notifications` is absent or disabled. That is a
 * configuration state, not a failure, and rendering it as an error is how
 * an operator ends up debugging a working proxy.
 *
 * Read off the status the fetch wrapper carries rather than by looking for
 * "404" in the rendered message: a 500 whose body happens to contain that
 * string would otherwise render as a configuration state and hide a real
 * fault.
 */
const notConfigured = computed(
  () => summary.error.value instanceof ApiError && summary.error.value.status === 404,
);

const stats = computed<NotifierSummary | null>(() => summary.data.value ?? null);
const rows = computed<NotifySubscription[]>(() => subscriptions.data.value?.items ?? []);
const dead = computed<NotifyDeadLetter[]>(() => deadletters.data.value?.items ?? []);
const moreDeadletters = computed<string | null>(() => deadletters.data.value?.next ?? null);

function parseFilters(raw: string): string[] {
  return raw
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

async function run(key: string, work: () => Promise<string>) {
  busy.value = key;
  notice.value = null;
  try {
    notice.value = await work();
    refreshAll();
  } catch (error) {
    notice.value = String(error);
  } finally {
    busy.value = null;
  }
}

async function create() {
  const url = newUrl.value.trim();
  const filters = parseFilters(newFilters.value);
  await run("__create", async () => {
    const result = await api.notifyCreateSubscription(
      url,
      filters,
      allowFirehose.value,
    );
    // Shown once, here. There is no route that returns it again.
    mintedSecret.value = result.signing_secret;
    newUrl.value = "";
    newFilters.value = "";
    allowFirehose.value = false;
    return `Created ${result.subscription.subscription_id}.`;
  });
}

/* Whether the typed filters would need the firehose acknowledgement, so
 * the checkbox appears when it is relevant rather than always. */
const needsFirehose = computed(() =>
  parseFilters(newFilters.value).some(
    (filter) =>
      filter === "*" ||
      (filter.endsWith("*") &&
        ["request_started", "request_completed", "request_error"].some((event) =>
          event.startsWith(filter.slice(0, -1)),
        )),
  ),
);

async function setActive(row: NotifySubscription, active: boolean) {
  await run(row.subscription_id, async () => {
    await api.notifySetActive(row.subscription_id, active);
    return `${row.subscription_id} ${active ? "resumed" : "paused"}.`;
  });
}

async function rotate(row: NotifySubscription) {
  // Confirmed, like every other irreversible operation in this console.
  // Rotating invalidates the receiver's signing secret immediately and no
  // read path returns the old one, so a misclick means re-onboarding the
  // customer.
  if (
    !confirm(
      `Rotate the signing key for ${row.subscription_id}? The receiver's current secret stops working immediately.`,
    )
  ) {
    return;
  }
  await run(row.subscription_id, async () => {
    const result = await api.notifyRotate(row.subscription_id);
    mintedSecret.value = result.signing_secret;
    return `Rotated ${row.subscription_id}. The previous secret stopped working immediately.`;
  });
}

async function remove(row: NotifySubscription) {
  if (
    !confirm(
      `Delete ${row.subscription_id}? Its filters and signing key go with it and cannot be restored.`,
    )
  ) {
    return;
  }
  await run(row.subscription_id, async () => {
    await api.notifyDeleteSubscription(row.subscription_id);
    return `Deleted ${row.subscription_id}. Its deadletters were kept.`;
  });
}

async function replay(record: NotifyDeadLetter) {
  await run(record.delivery_id, async () => {
    const result = await api.notifyReplay(record.delivery_id);
    return `Replayed ${result.event_id}.`;
  });
}

async function discard(record: NotifyDeadLetter) {
  if (
    !confirm(
      `Discard ${record.delivery_id} without replaying it? The receiver never gets this event.`,
    )
  ) {
    return;
  }
  await run(record.delivery_id, async () => {
    await api.notifyDiscardDeadletter(record.delivery_id);
    return `Discarded ${record.delivery_id}.`;
  });
}

function loadMoreDeadletters() {
  const cursor = moreDeadletters.value;
  if (!cursor) return;
  deadletterCursor.value = cursor;
  deadletters.run();
}
</script>

<template>
  <PageHeader
    title="Notifications"
    subtitle="Outbound webhook subscriptions, and the deliveries that ran out of attempts."
  />

  <EmptyState
    v-if="notConfigured"
    message="proxy.notifications is not configured on this proxy. Set notifications.enabled and notifications.store_path to manage webhook subscriptions; see docs/notifications.md."
  />

  <ErrorState
    v-else-if="summary.error.value && !stats"
    :error="summary.error.value"
    title="Could not load the notifier"
    @retry="refreshAll"
  />

  <template v-else>
    <div v-if="stats" class="stats">
      <StatCard label="Subscriptions" :value="String(stats.subscriptions)" />
      <StatCard label="Active" :value="String(stats.active_subscriptions)" />
      <StatCard
        label="Deadletters"
        :value="String(stats.deadletters)"
        :sub="`of ${stats.deadletter_capacity}`"
      />
      <StatCard label="Attempts" :value="String(stats.max_attempts)" sub="per delivery" />
    </div>

    <div v-if="mintedSecret" class="sb-card secret">
      <p class="secret__title">
        Signing secret. This is the only time it is shown.
      </p>
      <ClickToCopy :value="mintedSecret" label="signing secret" />
      <button class="sb-btn sb-btn--sm" @click="mintedSecret = null">dismiss</button>
    </div>

    <p v-if="notice" class="notice sb-mono">{{ notice }}</p>

    <h2 class="section">Subscriptions</h2>

    <div class="sb-card create">
      <input
        v-model="newUrl"
        class="sb-input"
        type="text"
        placeholder="https://customer.example.com/hooks/sbproxy"
      />
      <input
        v-model="newFilters"
        class="sb-input filters"
        type="text"
        placeholder="key_minted, key_revoked, or key_* (required)"
      />
      <button
        class="sb-btn sb-btn--sm sb-btn--primary"
        :disabled="busy === '__create' || !newUrl.trim() || !parseFilters(newFilters).length"
        @click="create"
      >
        subscribe
      </button>
    </div>

    <label v-if="needsFirehose" class="firehose">
      <input v-model="allowFirehose" type="checkbox" />
      <span>
        This filter reaches the per-request lifecycle events, which fire once
        per proxied request. That is one webhook delivery per request, and the
        queue starts dropping under any real traffic. Tick to confirm.
      </span>
    </label>

    <EmptyState
      v-if="!rows.length && !subscriptions.loading.value"
      message="No subscriptions. Name the events you want, or a family like key_*; the per-request lifecycle events need an explicit acknowledgement because they fire once per request. See the events documentation for the list."
    />

    <div v-else class="sb-card table-wrap">
      <table class="sb-table">
        <thead>
          <tr>
            <th>Subscription</th>
            <th>Destination</th>
            <th>Events</th>
            <th>Key</th>
            <th>State</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="row.subscription_id">
            <td class="sb-mono">{{ row.subscription_id }}</td>
            <td class="sb-mono url">{{ row.url }}</td>
            <td class="sb-mono">{{ row.event_types.join(", ") }}</td>
            <td class="sb-mono">{{ row.signing_key_id }}</td>
            <td>
              <StatusBadge
                :tone="row.active ? 'ok' : 'neutral'"
                :label="row.active ? 'active' : 'paused'"
              />
            </td>
            <td>
              <div class="actions">
                <button
                  class="sb-btn sb-btn--sm"
                  :disabled="busy === row.subscription_id"
                  @click="setActive(row, !row.active)"
                >
                  {{ row.active ? "pause" : "resume" }}
                </button>
                <button
                  class="sb-btn sb-btn--sm"
                  :disabled="busy === row.subscription_id"
                  title="Mint a new signing key. The previous secret stops working immediately."
                  @click="rotate(row)"
                >
                  rotate
                </button>
                <button
                  class="sb-btn sb-btn--sm"
                  :disabled="busy === row.subscription_id"
                  title="Delete the subscription. Its deadletters are kept."
                  @click="remove(row)"
                >
                  delete
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <h2 class="section">Deadletter queue</h2>

    <EmptyState
      v-if="!dead.length && !deadletters.loading.value"
      message="Nothing has run out of attempts. A delivery lands here once it has used its budget, or immediately on a refusal that will not change, and stays until it is replayed or discarded."
    />

    <div v-else class="sb-card table-wrap">
      <table class="sb-table">
        <thead>
          <tr>
            <th>Delivery</th>
            <th>Event</th>
            <th>Type</th>
            <th>Attempts</th>
            <th>Last status</th>
            <th>Reason</th>
            <th>Moved</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="record in dead" :key="record.delivery_id">
            <td class="sb-mono">{{ record.delivery_id }}</td>
            <td class="sb-mono">{{ record.event_id }}</td>
            <td class="sb-mono">{{ record.event_type }}</td>
            <td class="sb-mono">{{ record.attempts }}</td>
            <td class="sb-mono">{{ record.last_status ?? "-" }}</td>
            <td class="sb-mono">{{ record.last_reason }}</td>
            <td class="sb-mono">{{ record.moved_at }}</td>
            <td>
              <div class="actions">
                <button
                  class="sb-btn sb-btn--sm"
                  :disabled="busy === record.delivery_id"
                  title="Re-send under the original event id. The record leaves the queue once the worker takes it."
                  @click="replay(record)"
                >
                  replay
                </button>
                <button
                  class="sb-btn sb-btn--sm"
                  :disabled="busy === record.delivery_id"
                  title="Drop the record without replaying it. The receiver never gets this event."
                  @click="discard(record)"
                >
                  discard
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
      <button
        v-if="moreDeadletters"
        class="sb-btn sb-btn--sm more"
        @click="loadMoreDeadletters"
      >
        load more
      </button>
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
.create {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 12px;
  flex-wrap: wrap;
}
.create .sb-input {
  flex: 1 1 260px;
}
.filters {
  flex: 1 1 200px;
}
.secret {
  display: flex;
  gap: 12px;
  align-items: center;
  flex-wrap: wrap;
  margin-bottom: 16px;
}
.secret__title {
  margin: 0;
  font-weight: 600;
}
.table-wrap {
  overflow-x: auto;
}
.url {
  max-width: 32ch;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.actions {
  display: flex;
  gap: 6px;
}
.notice {
  margin: 0 0 16px;
  font-size: 13px;
}
.firehose {
  display: flex;
  gap: 8px;
  align-items: flex-start;
  margin: 0 0 12px;
  font-size: 13px;
  max-width: 70ch;
}
.more {
  margin: 12px;
}
</style>
