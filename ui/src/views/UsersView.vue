<script setup lang="ts">
import { computed, onMounted } from "vue";
import EmptyState from "../components/EmptyState.vue";
import ErrorState from "../components/ErrorState.vue";
import PageHeader from "../components/PageHeader.vue";
import StatCard from "../components/StatCard.vue";
import { api, type AdminUser } from "../api";
import { useAsync } from "../composables/useAsync";

const req = useAsync(() => api.adminUsers());
onMounted(req.run);

const users = computed<AdminUser[]>(() => req.data.value?.users ?? []);
const admins = computed(() => users.value.filter((u) => u.role === "admin").length);
const readOnly = computed(() => users.value.filter((u) => u.role === "read_only").length);

function roleLabel(role: AdminUser["role"]): string {
  return role === "read_only" ? "Read only" : "Admin";
}

function roleHint(role: AdminUser["role"]): string {
  return role === "read_only"
    ? "May read every view. State-changing requests are refused."
    : "May call every admin route, including config writes and key minting.";
}
</script>

<template>
  <PageHeader
    title="Users"
    subtitle="Who can sign in to this console, and what each account may do."
  />

  <ErrorState
    v-if="req.error.value && !users.length"
    :error="req.error.value"
    title="Could not load users"
    @retry="req.run"
  />

  <template v-else>
    <div class="cards">
      <StatCard label="Accounts" :value="String(users.length)" />
      <StatCard label="Admin" :value="String(admins)" />
      <StatCard label="Read only" :value="String(readOnly)" />
    </div>

    <EmptyState
      v-if="!users.length && !req.loading.value"
      message="No accounts reported. The admin server always has at least the top-level credential, so an empty list means this build could not read its own config."
    />

    <div v-else class="sb-card table-wrap">
      <table class="sb-table">
        <thead>
          <tr>
            <th>Username</th>
            <th>Role</th>
            <th>Source</th>
            <th>What this role may do</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="u in users" :key="u.username">
            <td class="sb-mono">{{ u.username }}</td>
            <td>
              <span class="role" :class="{ 'role--ro': u.role === 'read_only' }">
                {{ roleLabel(u.role) }}
              </span>
            </td>
            <td>{{ u.primary ? "Top-level credential" : "Operator" }}</td>
            <td class="hint">{{ roleHint(u.role) }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <p class="note">
      Accounts live in config, under <code class="sb-mono">admin.username</code> and
      <code class="sb-mono">admin.operators</code>. Add, remove, or re-role an account by
      editing config, then reloading. Passwords are never sent to this page, so they cannot
      be read back here or anywhere else in the console.
    </p>
  </template>
</template>

<style scoped>
.cards {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 16px;
}
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
.hint {
  color: var(--sb-muted);
}
.note {
  margin-top: 14px;
  color: var(--sb-muted);
  font-size: 13px;
  max-width: 68ch;
}
</style>
