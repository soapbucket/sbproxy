<script setup lang="ts">
import { useAuth } from "../composables/useAuth";
import BrandMark from "./BrandMark.vue";

const { username, role, logout } = useAuth();

const nav = [
  { to: "/", label: "Overview" },
  { to: "/keys", label: "Keys" },
  { to: "/credentials", label: "Credentials" },
  { to: "/config", label: "Config" },
  { to: "/logs", label: "Logs" },
  { to: "/metrics", label: "Metrics" },
  { to: "/spend", label: "Spend" },
  { to: "/prompts", label: "Prompts" },
  { to: "/playground", label: "Playground" },
  { to: "/cache", label: "Cache" },
  { to: "/model-host", label: "Model host" },
  { to: "/audit", label: "Audit" },
  { to: "/cluster", label: "Cluster" },
];
</script>

<template>
  <aside class="sidebar">
    <BrandMark class="sidebar__brand" />
    <nav class="nav">
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
      <div v-if="username" class="who">
        <span class="who__name">{{ username }}</span>
        <span class="who__role" v-if="role">{{ role }}</span>
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
  border-right: 1px solid var(--sb-border);
  display: flex;
  flex-direction: column;
  padding: var(--sb-space-5) var(--sb-space-4);
  position: sticky;
  top: 0;
  height: 100vh;
}
.sidebar__brand {
  padding: 0 8px var(--sb-space-5);
}
.nav {
  display: flex;
  flex-direction: column;
  gap: 2px;
  flex: 1;
}
.nav__item {
  padding: 8px 12px;
  border-radius: var(--sb-radius-sm);
  color: var(--sb-text-muted);
  font-size: 0.9rem;
  font-weight: 500;
  text-decoration: none;
  border-left: 2px solid transparent;
}
.nav__item:hover {
  background: var(--sb-surface-hover);
  color: var(--sb-text);
  text-decoration: none;
}
.nav__item--active {
  background: var(--sb-accent-tint);
  color: var(--sb-accent);
  border-left-color: var(--sb-accent);
}
.sidebar__foot {
  font-size: 0.72rem;
  padding: var(--sb-space-4) 8px 0;
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
  font-size: 0.82rem;
  color: var(--sb-text);
}
.who__role {
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--sb-text-faint);
}
.logout {
  align-self: flex-start;
}
@media (max-width: 720px) {
  /* Collapse the sidebar into a horizontal top bar. */
  .sidebar {
    width: 100%;
    height: auto;
    position: static;
    flex-direction: row;
    align-items: center;
    flex-wrap: wrap;
    gap: var(--sb-space-3);
    padding: var(--sb-space-3) var(--sb-space-4);
    border-right: none;
    border-bottom: 1px solid var(--sb-border);
  }
  .sidebar__brand {
    padding: 0;
  }
  .nav {
    flex-direction: row;
    flex-wrap: wrap;
    gap: 2px;
  }
  .nav__item {
    border-left: none;
    border-bottom: 2px solid transparent;
    padding: 6px 10px;
  }
  .nav__item--active {
    border-left-color: transparent;
    border-bottom-color: var(--sb-accent);
  }
  .sidebar__foot {
    display: none;
  }
}
</style>
