<script setup lang="ts">
import { ref } from "vue";
import { useAuth } from "../composables/useAuth";
import { ApiError } from "../api";

const { login } = useAuth();
const username = ref("");
const password = ref("");
const submitting = ref(false);
const error = ref("");

async function submit() {
  if (submitting.value || !username.value || !password.value) return;
  error.value = "";
  submitting.value = true;
  try {
    await login(username.value, password.value);
  } catch (e) {
    if (e instanceof ApiError && (e.status === 401 || e.status === 403)) {
      error.value = "Invalid username or password.";
    } else {
      error.value = e instanceof Error ? e.message : "Sign in failed.";
    }
  } finally {
    submitting.value = false;
  }
}
</script>

<template>
  <div class="login">
    <form class="sb-card card" @submit.prevent="submit">
      <div class="brand">
        <span class="mark">sb</span>
        <div>
          <div class="name">SBproxy</div>
          <div class="role">Admin</div>
        </div>
      </div>
      <label>
        <span class="lbl">Username</span>
        <input v-model="username" class="sb-input" autocomplete="username" />
      </label>
      <label>
        <span class="lbl">Password</span>
        <input
          v-model="password"
          type="password"
          class="sb-input"
          autocomplete="current-password"
        />
      </label>
      <p v-if="error" class="err">{{ error }}</p>
      <button
        class="sb-btn sb-btn--primary"
        :disabled="submitting || !username || !password"
        type="submit"
      >
        {{ submitting ? "Signing in..." : "Sign in" }}
      </button>
    </form>
  </div>
</template>

<style scoped>
.login {
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: var(--sb-space-5);
}
.card {
  width: 100%;
  max-width: 360px;
  display: flex;
  flex-direction: column;
  gap: var(--sb-space-4);
}
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: var(--sb-space-2);
}
.mark {
  font-family: var(--sb-font-mono);
  font-weight: 700;
  color: var(--sb-on-navy);
  background: var(--sb-navy);
  width: 32px;
  height: 32px;
  display: grid;
  place-items: center;
  border-radius: var(--sb-radius-sm);
}
.name {
  font-weight: 600;
}
.role {
  font-size: 0.72rem;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--sb-text-faint);
}
label {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.lbl {
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--sb-text-muted);
}
.err {
  color: #c0392b;
  font-size: 0.85rem;
  margin: 0;
}
</style>
