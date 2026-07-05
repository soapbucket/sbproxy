<script setup lang="ts">
defineProps<{ message?: string }>();
</script>

<template>
  <div class="empty">
    <p>{{ message || "Nothing here yet." }}</p>
    <slot />
  </div>
</template>

<style scoped>
.empty {
  border: 1px dashed var(--sb-border-strong);
  border-radius: var(--sb-radius);
  padding: var(--sb-space-6);
  text-align: center;
  color: var(--sb-text-muted);
}
.empty p {
  margin: 0 0 8px;
}
</style>
