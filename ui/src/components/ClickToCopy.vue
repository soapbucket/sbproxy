<script setup lang="ts">
import { ref } from "vue";
import { toast } from "../composables/useToasts";

const props = defineProps<{
  value: string;
  label?: string;
  hideIcon?: boolean;
}>();

const copied = ref(false);

let timeoutId: ReturnType<typeof setTimeout> | null = null;
async function copy() {
  try {
    await navigator.clipboard.writeText(props.value);
    copied.value = true;
    toast.success(`${props.label || "Value"} copied to clipboard`);
    if (timeoutId) clearTimeout(timeoutId);
    timeoutId = setTimeout(() => {
      copied.value = false;
    }, 2000);
  } catch (error) {
    toast.error(error, "Copy failed");
  }
}

import { onUnmounted } from "vue";
onUnmounted(() => {
  if (timeoutId) clearTimeout(timeoutId);
});
</script>

<template>
  <button
    class="click-to-copy sb-mono"
    :title="`Copy ${label || 'value'}`"
    @click.prevent.stop="copy"
  >
    <slot>{{ value }}</slot>
    <span v-if="!hideIcon" class="copy-icon" aria-hidden="true">
      <svg
        v-if="copied"
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
      >
        <polyline points="20 6 9 17 4 12" />
      </svg>
      <svg
        v-else
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
      >
        <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
      </svg>
    </span>
  </button>
</template>

<style scoped>
.click-to-copy {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: transparent;
  border: none;
  padding: 0;
  color: inherit;
  font: inherit;
  cursor: pointer;
  text-align: left;
  border-radius: 4px;
}
.click-to-copy:hover,
.click-to-copy:focus-visible {
  color: var(--sb-text);
  outline: none;
}
.click-to-copy:hover .copy-icon {
  opacity: 1;
}
.copy-icon {
  display: flex;
  opacity: 0;
  transition: opacity 0.15s;
  color: var(--sb-text-faint);
}
.click-to-copy:focus-visible .copy-icon {
  opacity: 1;
}
.copy-icon svg {
  width: 14px;
  height: 14px;
}
</style>
