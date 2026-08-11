<script setup lang="ts">
/**
 * Workspace rate-limit budgets, with the manual resume control (WOR-1764).
 *
 * WOR-2353: this lived only inside the Audit view, under `/audit`, with
 * no nav entry and no cross-reference from anywhere. An operator whose
 * workspace had auto-suspended and who went looking for a way to resume
 * it would check Overview, Keys, or something rate-limit-shaped, and find
 * nothing: the one control that does it sat under a heading with no
 * thematic connection to rate limiting.
 *
 * Extracted to a component rather than moved, so it can appear on
 * Overview (where operators already look for anything needing attention)
 * and stay on Audit beside the budget audit trail, without two copies of
 * the fetch and resume logic drifting apart.
 */
import { computed, onMounted, ref } from "vue";
import { api, ApiError, type WorkspaceStatus } from "../api";
import { useAsync } from "../composables/useAsync";
import { toast } from "../composables/useToasts";
import StatusBadge from "./StatusBadge.vue";
import EmptyState from "./EmptyState.vue";

const props = withDefaults(
  defineProps<{
    /** Hide the section entirely when nothing is suspended. Overview uses
     *  this so a healthy fleet does not grow a permanently empty card. */
    onlyWhenNoteworthy?: boolean;
  }>(),
  { onlyWhenNoteworthy: false },
);

const emit = defineEmits<{ (e: "resumed"): void }>();

const budgetReq = useAsync(() => api.budgetSnapshot());
onMounted(budgetReq.run);

const budgets = computed<WorkspaceStatus[]>(() =>
  Array.isArray(budgetReq.data.value) ? budgetReq.data.value : [],
);

// A 404 means the running config has no `rate_limits` block at all, which
// is not an error worth showing; it just means there is nothing to
// govern.
const budgetConfigured = computed(
  () =>
    !(
      budgetReq.error.value instanceof ApiError &&
      budgetReq.error.value.status === 404
    ),
);

const anySuspended = computed(() => budgets.value.some((b) => b.suspended));

const visible = computed(
  () =>
    budgetConfigured.value &&
    (!props.onlyWhenNoteworthy || anySuspended.value),
);

const busy = ref("");
async function resume(ws: string) {
  if (busy.value) return;
  busy.value = ws;
  try {
    await api.resumeWorkspace(ws);
    toast.success(`Resumed "${ws}"`);
    budgetReq.run();
    emit("resumed");
  } catch (e) {
    toast.error(e, "Resume workspace");
  } finally {
    busy.value = "";
  }
}

function tierTone(tier?: string): "ok" | "warn" | "err" | "neutral" {
  switch (tier) {
    case "auto_suspend":
      return "err";
    case "throttle":
      return "warn";
    case "soft":
      return "warn";
    case "normal":
      return "ok";
    default:
      return "neutral";
  }
}

defineExpose({ refresh: budgetReq.run });
</script>

<template>
  <section class="section" v-if="visible">
    <h2>Workspace budgets</h2>
    <EmptyState
      v-if="!budgets.length"
      message="No workspaces have tripped the rate-limit budget yet."
    />
    <div v-else class="table-wrap">
      <table class="sb-table">
        <thead>
          <tr><th>Workspace</th><th>Tier</th><th>Cooldown</th><th></th></tr>
        </thead>
        <tbody>
          <tr v-for="b in budgets" :key="b.workspace">
            <td class="sb-mono">{{ b.workspace }}</td>
            <td><StatusBadge :label="b.tier ?? 'unknown'" :tone="tierTone(b.tier)" /></td>
            <td>{{ b.cooldown_secs != null ? `${b.cooldown_secs}s` : "-" }}</td>
            <td>
              <button
                v-if="b.suspended && b.workspace"
                class="sb-btn sb-btn--sm"
                :disabled="busy === b.workspace"
                @click="resume(b.workspace)"
              >
                {{ busy === b.workspace ? "Resuming..." : "Resume" }}
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<style scoped>
.section {
  margin-top: 24px;
}
.table-wrap {
  overflow-x: auto;
}
</style>
