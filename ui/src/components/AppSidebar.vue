<script setup lang="ts">
const nav = [
  { to: "/", label: "Overview" },
  { to: "/keys", label: "Keys" },
  { to: "/credentials", label: "Credentials" },
  { to: "/config", label: "Config" },
  { to: "/logs", label: "Logs" },
  { to: "/metrics", label: "Metrics" },
  { to: "/prompts", label: "Prompts" },
  { to: "/playground", label: "Playground" },
];
</script>

<template>
  <aside class="sidebar">
    <div class="brand">
      <span class="brand__mark">sb</span>
      <div class="brand__text">
        <span class="brand__name">SBproxy</span>
        <span class="brand__role">Admin</span>
      </div>
    </div>
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
    <div class="sidebar__foot sb-faint">
      Served at /admin/ui behind admin auth.
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
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 8px var(--sb-space-5);
}
.brand__mark {
  font-family: var(--sb-font-mono);
  font-weight: 700;
  font-size: 0.95rem;
  color: var(--sb-on-navy);
  background: var(--sb-navy);
  width: 30px;
  height: 30px;
  display: grid;
  place-items: center;
  border-radius: var(--sb-radius-sm);
}
.brand__text {
  display: flex;
  flex-direction: column;
  line-height: 1.15;
}
.brand__name {
  font-weight: 600;
}
.brand__role {
  font-size: 0.72rem;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--sb-text-faint);
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
  .brand {
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
