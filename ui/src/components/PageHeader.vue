<script setup lang="ts">
defineProps<{ title: string; subtitle?: string }>();
</script>

<template>
  <header class="ph">
    <div>
      <h1>{{ title }}</h1>
      <p class="ph__sub" v-if="subtitle">{{ subtitle }}</p>
    </div>
    <div class="ph__actions">
      <slot name="actions" />
    </div>
  </header>
</template>

<style scoped>
.ph {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--sb-space-4);
  margin-bottom: var(--sb-space-5);
  flex-wrap: wrap;
}
.ph__sub {
  color: var(--sb-text-muted);
  margin: 6px 0 0;
  max-width: 60ch;
}
.ph__actions {
  display: flex;
  gap: var(--sb-space-3);
  align-items: center;
  flex-wrap: wrap;
}
</style>
