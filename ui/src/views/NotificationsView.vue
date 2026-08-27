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
const deadletters = useAsync(() => api.notifyDeadletters());

const newUrl = ref("");
const newFilters = ref("*");
const mintedSecret = ref<string | null>(null);
const busy = ref<string | null>(null);
const notice = ref<string | null>(null);

function refreshAll() {
  summary.run();
  subscriptions.run();
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
    const result = await api.notifyCreateSubscription(url, filters);
    // Shown once, here. There is no route that returns it again.
    mintedSecret.value = result.signing_secret;
    newUrl.value = "";
    return `Created ${result.subscription.subscription_id}.`;
  });
}

async function setActive(row: NotifySubscription, active: boolean) {
  await run(row.subscription_id, async () => {
    await api.notifySetActive(row.subscription_id, active);
    return `${row.subscription_id} ${active ? "resumed" : "paused"}.`;
  });
}

async function rotate(row: NotifySubscription) {
  await run(row.subscription_id, async () => {
    const result = await api.notifyRotate(row.subscription_id);
    mintedSecret.value = result.signing_secret;
    return `Rotated ${row.subscription_id}. The previous secret stopped working immediately.`;
  });
}

async function remove(row: NotifySubscription) {
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
        placeholder="*, key.*, or key_minted, key_revoked"
      />
      <button
        class="sb-btn sb-btn--sm sb-btn--primary"
        :disabled="busy === '__create' || !newUrl.trim() || !parseFilters(newFilters).length"
        @click="create"
      >
        subscribe
      </button>
    </div>

    <EmptyState
      v-if="!rows.length && !subscriptions.loading.value"
      message="No subscriptions. Every typed proxy event is available; see the events documentation for the list."
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
      message="Nothing has run out of attempts. A delivery lands here after three failed attempts and stays until it is replayed."
    />

    <div v-else class="sb-card table-wrap">
      <table class="sb-table">
        <thead>
          <tr>
            <th>Delivery</th>
            <th>Event</th>
            <th>Type</th>
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
            <td class="sb-mono">{{ record.last_status ?? "-" }}</td>
            <td class="sb-mono">{{ record.last_reason }}</td>
            <td class="sb-mono">{{ record.moved_at }}</td>
            <td>
              <button
                class="sb-btn sb-btn--sm"
                :disabled="busy === record.delivery_id"
                title="Re-send under the original event id. The record leaves the queue."
                @click="replay(record)"
              >
                replay
              </button>
            </td>
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
</style>
