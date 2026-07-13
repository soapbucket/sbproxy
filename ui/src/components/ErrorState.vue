<script setup lang="ts">
import type { ApiError } from "../api";

defineProps<{
  error: ApiError | null;
  title?: string;
}>();
defineEmits<{ (e: "retry"): void }>();
</script>

<template>
  <div v-if="error" class="error" role="alert" aria-live="assertive">
    <div class="error__code">{{ error.status || "!" }}</div>
    <div class="error__body">
      <p class="error__title">{{ title || "Could not load this view" }}</p>
      <p class="error__hint">{{ error.hint }}</p>
      <p class="error__detail sb-mono" v-if="error.body">
        {{ error.body.slice(0, 400) }}
      </p>
      <button class="sb-btn sb-btn--sm" @click="$emit('retry')">Retry</button>
    </div>
  </div>
</template>

<style scoped>
.error {
  display: flex;
  gap: var(--sb-space-4);
  align-items: flex-start;
  background: var(--sb-err-bg);
  border: 1px solid rgba(180, 34, 63, 0.25);
  border-radius: var(--sb-radius);
  padding: var(--sb-space-5);
}
.error__code {
  font-family: var(--sb-font-mono);
  font-size: 1.4rem;
  font-weight: 700;
  color: var(--sb-err);
  line-height: 1;
  padding-top: 2px;
}
.error__title {
  font-weight: 600;
  margin: 0 0 4px;
}
.error__hint {
  color: var(--sb-text-muted);
  margin: 0 0 10px;
}
.error__detail {
  font-size: 0.76rem;
  color: var(--sb-text-faint);
  white-space: pre-wrap;
  word-break: break-word;
  margin: 0 0 10px;
  max-height: 140px;
  overflow: auto;
}
</style>
