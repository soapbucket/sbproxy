<script setup lang="ts">
import { onMounted } from "vue";
import AppSidebar from "./components/AppSidebar.vue";
import LoginView from "./views/LoginView.vue";
import { useAuth } from "./composables/useAuth";

// WOR-1758: check the session on load, then gate the app on auth.
const { authenticated, ready, refresh } = useAuth();
onMounted(refresh);
</script>

<template>
  <div v-if="!ready" class="boot">Loading...</div>
  <LoginView v-else-if="!authenticated" />
  <div v-else class="shell">
    <AppSidebar />
    <main class="content">
      <div class="content__inner">
        <RouterView />
      </div>
    </main>
  </div>
</template>

<style scoped>
.boot {
  min-height: 100vh;
  display: grid;
  place-items: center;
  color: var(--sb-text-muted);
}
.shell {
  display: flex;
  min-height: 100vh;
}
.content {
  flex: 1;
  min-width: 0;
}
.content__inner {
  max-width: var(--sb-content-max);
  margin: 0 auto;
  padding: var(--sb-space-6) var(--sb-space-6) var(--sb-space-7);
}
@media (max-width: 720px) {
  /* Stack the sidebar above the content on narrow viewports. */
  .shell {
    flex-direction: column;
  }
  .content__inner {
    padding: var(--sb-space-5) var(--sb-space-4) var(--sb-space-6);
  }
}
</style>
