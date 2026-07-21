<script setup lang="ts">
import { useAuth } from "../composables/useAuth";

const { username, role, logout } = useAuth();

const nav = [
  { to: "/", label: "overview" },
  { to: "/keys", label: "keys" },
  { to: "/credentials", label: "credentials" },
  { to: "/config", label: "config" },
  { to: "/logs", label: "logs" },
  { to: "/metrics", label: "metrics" },
  { to: "/spend", label: "spend" },
  { to: "/ai-performance", label: "ai performance" },
  { to: "/guardrails", label: "guardrails" },
  { to: "/prompts", label: "prompts" },
  { to: "/playground", label: "playground" },
  { to: "/cache", label: "cache" },
  { to: "/model-host", label: "model host" },
  { to: "/storage", label: "storage" },
  { to: "/audit", label: "audit" },
  { to: "/cluster", label: "cluster" },
];
</script>

<template>
  <aside class="sidebar">
    <nav class="nav sb-mono">
      <RouterLink
        v-for="item in nav"
        :key="item.to"
        :to="item.to"
        class="nav__item"
        active-class="nav__item--active"
        :exact-active-class="item.to === '/' ? 'nav__item--active' : ''"
      >
        {{ item.label }}
      </RouterLink>
    </nav>
    <div class="sidebar__foot">
      <div v-if="username" class="who sb-mono">
        <span class="who__name">{{ username }}</span>
        <span class="who__role">{{ role }}</span>
      </div>
      <button class="sb-btn sb-btn--sm logout" @click="logout">Sign out</button>
    </div>
  </aside>
</template>

<style scoped>
.sidebar {
  width: var(--sb-sidebar-w);
  flex: none;
  background: var(--sb-surface);
  border-right: 1px solid var(--sb-border-ink);
  display: flex;
  flex-direction: column;
  padding: var(--sb-space-4) 0;
  position: sticky;
  top: 0;
  align-self: flex-start;
  min-height: 100%;
}
.nav {
  display: flex;
  flex-direction: column;
  flex: 1;
}
.nav__item {
  padding: 8px var(--sb-space-5);
  color: var(--sb-text-muted);
  font-size: 0.82rem;
  text-decoration: none;
  letter-spacing: 0.01em;
}
.nav__item:hover {
  background: var(--sb-surface-hover);
  color: var(--sb-text);
  text-decoration: none;
}
/* Active page reads as a solid ink block, the site's admin idiom. */
.nav__item--active,
.nav__item--active:hover {
  background: var(--sb-ink);
  color: var(--sb-on-ink);
}
.sidebar__foot {
  font-size: 0.72rem;
  padding: var(--sb-space-4) var(--sb-space-5) 0;
  border-top: 1px solid var(--sb-border);
  line-height: 1.4;
  display: flex;
  flex-direction: column;
  gap: var(--sb-space-3);
}
.who {
  display: flex;
  flex-direction: column;
}
.who__name {
  font-weight: 600;
  font-size: 0.78rem;
  color: var(--sb-text);
}
.who__role {
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--sb-text-faint);
  font-size: 0.64rem;
}
.logout {
  align-self: flex-start;
}
@media (max-width: 720px) {
  /* Collapse the sidebar into a horizontal top strip. */
  .sidebar {
    width: 100%;
    position: static;
    min-height: 0;
    flex-direction: row;
    align-items: center;
    flex-wrap: wrap;
    gap: var(--sb-space-3);
    padding: var(--sb-space-2) var(--sb-space-3);
    border-right: none;
    border-bottom: 1px solid var(--sb-border-ink);
  }
  .nav {
    flex-direction: row;
    flex-wrap: wrap;
  }
  .nav__item {
    padding: 5px 10px;
  }
  .sidebar__foot {
    display: none;
  }
}
</style>
