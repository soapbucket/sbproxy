<script setup lang="ts">
import { useToasts } from "../composables/useToasts";

const { toasts, dismiss } = useToasts();

const KIND_LABEL: Record<string, string> = {
  success: "ok",
  error: "error",
  warn: "warning",
  info: "note",
};
</script>

<template>
  <div class="host" aria-live="polite" aria-atomic="false">
    <TransitionGroup name="toast">
      <div
        v-for="t in toasts"
        :key="t.id"
        class="toast"
        :class="`toast--${t.kind}`"
        :role="t.kind === 'error' ? 'alert' : 'status'"
      >
        <span class="toast__kind sb-mono">{{ KIND_LABEL[t.kind] }}</span>
        <div class="toast__body">
          <p class="toast__msg">{{ t.message }}</p>
          <p class="toast__detail" v-if="t.detail">{{ t.detail }}</p>
        </div>
        <button
          class="toast__close"
          aria-label="Dismiss notification"
          @click="dismiss(t.id)"
        >
          &times;
        </button>
      </div>
    </TransitionGroup>
  </div>
</template>

<style scoped>
.host {
  position: fixed;
  bottom: var(--sb-space-5);
  right: var(--sb-space-5);
  z-index: 100;
  display: flex;
  flex-direction: column;
  gap: var(--sb-space-2);
  width: min(380px, calc(100vw - 2 * var(--sb-space-5)));
  pointer-events: none;
}
.toast {
  pointer-events: auto;
  display: flex;
  align-items: flex-start;
  gap: var(--sb-space-3);
  background: var(--sb-surface);
  border: 1px solid var(--sb-border-ink);
  border-left-width: 3px;
  padding: 10px 12px;
}
.toast--success {
  border-left-color: var(--sb-ok);
}
.toast--error {
  border-left-color: var(--sb-err);
}
.toast--warn {
  border-left-color: var(--sb-warn);
}
.toast--info {
  border-left-color: var(--sb-info);
}
.toast__kind {
  font-size: 0.68rem;
  letter-spacing: 0.06em;
  padding-top: 3px;
  min-width: 52px;
  color: var(--sb-text-faint);
}
.toast--success .toast__kind {
  color: var(--sb-ok);
}
.toast--error .toast__kind {
  color: var(--sb-err);
}
.toast--warn .toast__kind {
  color: var(--sb-warn);
}
.toast__body {
  flex: 1;
  min-width: 0;
}
.toast__msg {
  margin: 0;
  font-size: 0.85rem;
  font-weight: 600;
  line-height: 1.35;
}
.toast__detail {
  margin: 3px 0 0;
  font-size: 0.76rem;
  color: var(--sb-text-muted);
  line-height: 1.4;
  word-break: break-word;
  max-height: 72px;
  overflow: hidden;
}
.toast__close {
  border: none;
  background: none;
  color: var(--sb-text-faint);
  font-size: 1rem;
  line-height: 1;
  padding: 2px 4px;
  cursor: pointer;
}
.toast__close:hover {
  color: var(--sb-text);
}

.toast-enter-active,
.toast-leave-active {
  transition: opacity 0.16s ease, transform 0.16s ease;
}
.toast-enter-from,
.toast-leave-to {
  opacity: 0;
  transform: translateY(6px);
}
@media (prefers-reduced-motion: reduce) {
  .toast-enter-active,
  .toast-leave-active {
    transition: none;
  }
}
</style>
