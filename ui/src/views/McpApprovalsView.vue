<script setup lang="ts">
import { computed, onMounted } from "vue";
import {
  api,
  holdStateLabel,
  type McpHold,
} from "../api";
import { useAsync } from "../composables/useAsync";
import { useAuth } from "../composables/useAuth";
import { toast } from "../composables/useToasts";
import PageHeader from "../components/PageHeader.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const { username } = useAuth();
const req = useAsync(() => api.mcpApprovals(), {
  pollMs: 5_000,
  refreshLabel: "MCP approvals",
});
const holds = computed<McpHold[]>(() => req.data.value?.holds ?? []);
const enabled = computed(() => req.data.value?.enabled ?? false);

onMounted(() => {
  req.run();
});

function label(hold: McpHold): string {
  return holdStateLabel(hold.state);
}

async function decide(hold: McpHold, approve: boolean) {
  const by = username.value || "operator";
  try {
    if (approve) {
      await api.approveMcpHold(hold.id, by);
      toast.success(`Approved ${hold.tool_name}`);
    } else {
      await api.denyMcpHold(hold.id, by);
      toast.success(`Denied ${hold.tool_name}`);
    }
    req.run();
  } catch (err) {
    toast.error(err, approve ? "Approve" : "Deny");
  }
}
</script>

<template>
  <div>
    <PageHeader
      title="MCP approvals"
      subtitle="Parked tool calls waiting for a human. Approving one snapshot lets the next matching retry through once. An unanswered hold expires fail-closed: it never becomes an allow."
    />
    <ErrorState v-if="req.error.value" :error="req.error.value" @retry="req.run()" />
    <EmptyState
      v-else-if="!req.loading.value && !enabled"
      message="No mcp action has approval: configured. Cedar @confirm stays a labelled refusal until you add an approval store."
    />
    <EmptyState
      v-else-if="!req.loading.value && !holds.length"
      message="No pending or recently decided holds."
    />
    <table v-else class="sb-table">
      <thead>
        <tr>
          <th>State</th>
          <th>Tool</th>
          <th>Origin</th>
          <th>Principal</th>
          <th>Reason</th>
          <th>Hold</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="hold in holds" :key="hold.id">
          <td><StatusBadge :label="label(hold)" /></td>
          <td class="sb-mono">{{ hold.tool_name }}</td>
          <td class="sb-mono">{{ hold.origin }}</td>
          <td class="sb-mono">{{ hold.principal_id }}</td>
          <td>{{ hold.reason }}</td>
          <td class="sb-mono">{{ hold.id }}</td>
          <td>
            <template v-if="label(hold) === 'pending'">
              <button class="sb-btn sb-btn--sm" @click="decide(hold, true)">Approve</button>
              <button class="sb-btn sb-btn--sm" @click="decide(hold, false)">Deny</button>
            </template>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
