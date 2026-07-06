<script setup lang="ts">
import { onMounted, onUnmounted } from "vue";

const props = defineProps<{ title: string; wide?: boolean }>();
const emit = defineEmits<{ (e: "close"): void }>();

function onKey(e: KeyboardEvent) {
  if (e.key === "Escape") emit("close");
}
onMounted(() => document.addEventListener("keydown", onKey));
onUnmounted(() => document.removeEventListener("keydown", onKey));

// Reference props so it is not flagged unused under strict settings.
void props;
</script>

<template>
  <div class="scrim" @click.self="$emit('close')">
    <div class="dialog" :class="{ 'dialog--wide': wide }" role="dialog" aria-modal="true">
      <header class="dialog__head">
        <h2>{{ title }}</h2>
        <button class="close" aria-label="Close" @click="$emit('close')">×</button>
      </header>
      <div class="dialog__body">
        <slot />
      </div>
      <footer class="dialog__foot" v-if="$slots.footer">
        <slot name="footer" />
      </footer>
    </div>
  </div>
</template>

<style scoped>
.scrim {
  position: fixed;
  inset: 0;
  background: rgba(10, 22, 40, 0.45);
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding: 8vh var(--sb-space-4) var(--sb-space-4);
  z-index: 50;
  overflow-y: auto;
}
.dialog {
  background: var(--sb-surface);
  border: 1px solid var(--sb-border-strong);
  border-radius: var(--sb-radius-lg);
  box-shadow: var(--sb-shadow);
  width: 100%;
  max-width: 520px;
}
.dialog--wide {
  max-width: 780px;
}
.dialog__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--sb-space-4) var(--sb-space-5);
  border-bottom: 1px solid var(--sb-border);
}
.dialog__body {
  padding: var(--sb-space-5);
}
.dialog__foot {
  padding: var(--sb-space-4) var(--sb-space-5);
  border-top: 1px solid var(--sb-border);
  display: flex;
  justify-content: flex-end;
  gap: var(--sb-space-3);
}
.close {
  background: none;
  border: none;
  color: var(--sb-text-muted);
  font-size: 1.5rem;
  line-height: 1;
  cursor: pointer;
  padding: 0 4px;
}
.close:hover {
  color: var(--sb-text);
}
</style>
