<script setup lang="ts">
import { nextTick, onMounted, onUnmounted, ref, useId } from "vue";
import { focusTargetForTab } from "../lib/dialog-focus";

const props = defineProps<{ title: string; wide?: boolean }>();
const emit = defineEmits<{ (e: "close"): void }>();
const dialog = ref<HTMLElement | null>(null);
const titleId = useId();
let previouslyFocused: HTMLElement | null = null;

function onKey(e: KeyboardEvent) {
  if (e.key === "Escape") {
    emit("close");
    return;
  }
  if (e.key !== "Tab" || !dialog.value) return;
  const focusable = [...dialog.value.querySelectorAll<HTMLElement>(
    'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [href], [tabindex]:not([tabindex="-1"])',
  )].filter((element) => {
    if (
      element.closest("[hidden]") ||
      element.closest("[inert]") ||
      element.closest('[aria-hidden="true"]')
    ) {
      return false;
    }
    let current: HTMLElement | null = element;
    while (current) {
      const style = window.getComputedStyle(current);
      if (style.display === "none" || style.visibility === "hidden") {
        return false;
      }
      if (current === dialog.value) break;
      current = current.parentElement;
    }
    return true;
  });
  if (!focusable.length) {
    e.preventDefault();
    dialog.value.focus();
    return;
  }
  const target = focusTargetForTab(
    focusable,
    document.activeElement as HTMLElement | null,
    e.shiftKey,
  );
  if (target) {
    e.preventDefault();
    target.focus();
  }
}
onMounted(async () => {
  previouslyFocused = document.activeElement as HTMLElement | null;
  document.addEventListener("keydown", onKey);
  await nextTick();
  const initial = dialog.value?.querySelector<HTMLElement>("[autofocus]");
  (initial ?? dialog.value)?.focus();
});
onUnmounted(() => {
  document.removeEventListener("keydown", onKey);
  previouslyFocused?.focus();
});

// Reference props so it is not flagged unused under strict settings.
void props;
</script>

<template>
  <div class="scrim" @click.self="$emit('close')">
    <div
      ref="dialog"
      class="dialog"
      :class="{ 'dialog--wide': wide }"
      role="dialog"
      aria-modal="true"
      :aria-labelledby="titleId"
      tabindex="-1"
    >
      <header class="dialog__head">
        <h2 :id="titleId">{{ title }}</h2>
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
  min-width: 0;
}
.dialog--wide {
  max-width: 1040px;
}
.dialog:focus {
  outline: none;
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
  min-width: 0;
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
.close:focus-visible {
  outline: 3px solid var(--sb-accent-ring);
  outline-offset: 2px;
  border-radius: var(--sb-radius-sm);
}

@media (max-width: 620px) {
  .scrim {
    padding: var(--sb-space-3);
  }

  .dialog__head,
  .dialog__body,
  .dialog__foot {
    padding-left: var(--sb-space-4);
    padding-right: var(--sb-space-4);
  }

  .dialog__foot {
    flex-wrap: wrap;
  }
}

@media (max-width: 420px) {
  .dialog__foot :deep(.sb-btn) {
    width: 100%;
  }
}
</style>
