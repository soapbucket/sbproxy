<script setup lang="ts">
import { ref } from "vue";

defineProps<{
  text: string;
}>();

const visible = ref(false);

function show() { visible.value = true; }
function hide() { visible.value = false; }
</script>

<template>
  <div class="tooltip-container" @mouseenter="show" @mouseleave="hide" @focusin="show" @focusout="hide">
    <span class="tooltip-icon" aria-hidden="true">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"></circle>
        <path d="M12 16v-4"></path>
        <path d="M12 8h.01"></path>
      </svg>
    </span>
    <div v-show="visible" class="tooltip-bubble" role="tooltip">
      {{ text }}
    </div>
  </div>
</template>

<style scoped>
.tooltip-container {
  position: relative;
  display: inline-flex;
  align-items: center;
  margin-left: 4px;
  cursor: help;
}
.tooltip-icon svg {
  width: 14px;
  height: 14px;
  color: var(--sb-text-faint);
}
.tooltip-container:hover .tooltip-icon svg {
  color: var(--sb-accent);
}
.tooltip-bubble {
  position: absolute;
  bottom: 100%;
  left: 50%;
  transform: translateX(-50%);
  margin-bottom: 8px;
  padding: 6px 10px;
  background: var(--sb-ink-strong);
  color: var(--sb-on-ink);
  font-size: 0.72rem;
  font-weight: 500;
  white-space: nowrap;
  border-radius: var(--sb-radius-sm);
  z-index: 100;
  box-shadow: var(--sb-shadow);
  pointer-events: none;
}
.tooltip-bubble::after {
  content: "";
  position: absolute;
  top: 100%;
  left: 50%;
  transform: translateX(-50%);
  border: 4px solid transparent;
  border-top-color: var(--sb-ink-strong);
}
</style>
