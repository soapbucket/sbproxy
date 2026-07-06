<script setup lang="ts">
import AppSidebar from "./components/AppSidebar.vue";
</script>

<template>
  <div class="shell">
    <AppSidebar />
    <main class="content">
      <div class="content__inner">
        <RouterView />
      </div>
    </main>
  </div>
</template>

<style scoped>
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
