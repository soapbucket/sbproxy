<script setup lang="ts">
import { computed, onMounted } from "vue";
import { api, type OperatorSummary } from "../api";
import { useAsync } from "../composables/useAsync";
import PageHeader from "../components/PageHeader.vue";
import ErrorState from "../components/ErrorState.vue";
import EmptyState from "../components/EmptyState.vue";

const req = useAsync(() => api.operators());
onMounted(req.run);

const rows = computed<OperatorSummary[]>(() =>
  Array.isArray(req.data.value) ? req.data.value : [],
);

function roleLabel(role: OperatorSummary["role"]): string {
  return role === "read_only" ? "Read only" : "Admin";
}
</script>

<template>
  <PageHeader
    title="Operators"
    subtitle="Configured RBAC operators. Managed via config, not this page."
  />

  <ErrorState
    v-if="req.error.value && !rows.length"
    :error="req.error.value"
    title="Could not load operators"
    @retry="req.run"
  />

  <template v-else>
    <EmptyState
      v-if="!rows.length && !req.loading.value"
      message="No operators configured under proxy.admin.operators. The top-level admin credential can still sign in; see Users for the full account list."
    />

    <div v-else class="sb-card table-wrap">
      <table class="sb-table">
        <thead>
          <tr>
            <th>Username</th>
            <th>Role</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="op in rows" :key="op.username">
            <td class="sb-mono">{{ op.username }}</td>
            <td>
              <span class="role" :class="{ 'role--ro': op.role === 'read_only' }">
                {{ roleLabel(op.role) }}
              </span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <p class="note">
      Operators are defined under <code class="sb-mono">proxy.admin.operators</code> in
      config. There is no admin API to add, remove, or re-role one: edit config and
      reload. Passwords are never sent to this page. The top-level admin credential also
      signs in but is not listed here; see <code class="sb-mono">Users</code> for the
      full account list.
    </p>
  </template>
</template>

<style scoped>
.table-wrap {
  overflow-x: auto;
}
.role {
  font-weight: 600;
}
.role--ro {
  font-weight: 400;
  color: var(--sb-muted);
}
.note {
  margin-top: 14px;
  color: var(--sb-muted);
  font-size: 13px;
  max-width: 68ch;
}
</style>
