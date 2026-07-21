<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import AppSidebar from "./components/AppSidebar.vue";
import BrandMark from "./components/BrandMark.vue";
import ToastHost from "./components/ToastHost.vue";
import LoginView from "./views/LoginView.vue";
import { useAuth } from "./composables/useAuth";
import { api } from "./api";

// WOR-1758: check the session on load, then gate the app on auth.
const { authenticated, ready, refresh } = useAuth();

// Topbar live strip: the admin host, whether /health answers, and the
// cluster size. Polled gently; a metrics-tier outage must never take
// the chrome down, so failures just flip the dot.
const hostname = window.location.host;
const healthy = ref<boolean | null>(null);
const nodeCount = ref<number | null>(null);
let liveTimer: ReturnType<typeof setInterval> | null = null;

async function pollLive() {
  try {
    await api.health();
    healthy.value = true;
  } catch {
    healthy.value = false;
  }
  try {
    const cluster = await api.clusterStatus();
    nodeCount.value = cluster.summary.total_nodes;
  } catch {
    nodeCount.value = null;
  }
}

const liveLabel = computed(() => {
  if (healthy.value === null) return "";
  const state = healthy.value ? "live" : "unreachable";
  if (nodeCount.value === null) return state;
  return `${state} · ${nodeCount.value} ${nodeCount.value === 1 ? "node" : "nodes"}`;
});

// Track auth transitions, not just the mount state: logging in
// through the form must start the strip, and logging out must stop
// polling with the operator's session.
watch(authenticated, (isAuthed) => {
  if (liveTimer) {
    clearInterval(liveTimer);
    liveTimer = null;
  }
  if (isAuthed) {
    pollLive();
    liveTimer = setInterval(pollLive, 30000);
  } else {
    healthy.value = null;
    nodeCount.value = null;
  }
});

onMounted(refresh);
onUnmounted(() => {
  if (liveTimer) clearInterval(liveTimer);
});
</script>

<template>
  <div v-if="!ready" class="boot">Loading...</div>
  <LoginView v-else-if="!authenticated" />
  <div v-else class="frame">
    <header class="topbar">
      <BrandMark />
      <span class="topbar__host sb-mono">{{ hostname }}</span>
      <span class="topbar__live sb-mono" v-if="liveLabel">
        <span
          class="topbar__dot"
          :class="{ 'topbar__dot--down': healthy === false }"
          aria-hidden="true"
        />
        {{ liveLabel }}
      </span>
    </header>
    <div class="shell">
      <AppSidebar />
      <main class="content">
        <div class="content__inner">
          <RouterView />
        </div>
      </main>
    </div>
  </div>
  <ToastHost />
</template>

<style scoped>
.boot {
  min-height: 100vh;
  display: grid;
  place-items: center;
  color: var(--sb-text-muted);
}
/* The whole app sits in one ink-framed panel on the paper page. */
.frame {
  max-width: 1400px;
  margin: var(--sb-space-4) auto;
  border: 1px solid var(--sb-border-ink);
  background: var(--sb-surface);
  min-height: calc(100vh - 2 * var(--sb-space-4));
  display: flex;
  flex-direction: column;
}
.topbar {
  display: flex;
  align-items: center;
  gap: var(--sb-space-4);
  padding: 10px var(--sb-space-5);
  border-bottom: 1px solid var(--sb-border-ink);
}
.topbar__host {
  font-size: 0.78rem;
  color: var(--sb-text-faint);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.topbar__live {
  margin-left: auto;
  font-size: 0.78rem;
  color: var(--sb-text-muted);
  display: inline-flex;
  align-items: center;
  gap: 7px;
  white-space: nowrap;
}
.topbar__dot {
  width: 7px;
  height: 7px;
  border-radius: var(--sb-radius-pill);
  background: var(--sb-accent);
}
.topbar__dot--down {
  background: var(--sb-err);
}
.shell {
  display: flex;
  flex: 1;
  min-height: 0;
}
.content {
  flex: 1;
  min-width: 0;
}
.content__inner {
  max-width: var(--sb-content-max);
  margin: 0 auto;
  padding: var(--sb-space-5) var(--sb-space-6) var(--sb-space-7);
}
@media (max-width: 720px) {
  .frame {
    margin: 0;
    border: none;
    min-height: 100vh;
  }
  /* Stack the sidebar above the content on narrow viewports. */
  .shell {
    flex-direction: column;
  }
  .content__inner {
    padding: var(--sb-space-5) var(--sb-space-4) var(--sb-space-6);
  }
  .topbar__host {
    display: none;
  }
}
</style>
