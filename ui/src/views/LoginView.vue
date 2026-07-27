<script setup lang="ts">
import { ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { useAuth } from "../composables/useAuth";
import { ApiError } from "../api";
import BrandMark from "../components/BrandMark.vue";

const { login } = useAuth();
const route = useRoute();
const router = useRouter();
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
    // Return the operator to whatever they were trying to reach. Only
    // same-app paths are honoured: `next` comes from the query string, so
    // treating it as a raw location would let a crafted link bounce a
    // freshly authenticated operator to another origin.
    const next = route.query.next;
    const target = typeof next === "string" && next.startsWith("/") && !next.startsWith("//")
      ? next
      : "/";
    await router.replace(target);
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
      <BrandMark class="card__brand" :size="30" />
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
.card__brand {
  margin-bottom: var(--sb-space-2);
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
