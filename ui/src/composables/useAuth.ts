import { ref } from "vue";
import { api, setCsrfToken } from "../api";

// Module-level (singleton) auth state shared across the app.
const authenticated = ref(false);
const username = ref("");
const role = ref("");
// True once the initial session check has completed, so the app can show
// a brief loading state instead of flashing the login form.
const ready = ref(false);

/**
 * Session-based auth for the SPA (WOR-1758). On load, `refresh()` asks
 * the server who we are (recovering the CSRF token from an existing
 * session cookie); `login()` / `logout()` drive the session explicitly.
 * Basic-auth users appear authenticated with no CSRF token, which the
 * API client handles (Basic is CSRF-exempt server-side).
 */
export function useAuth() {
  async function refresh(): Promise<void> {
    try {
      const s = await api.session();
      authenticated.value = !!s.authenticated;
      username.value = s.username ?? "";
      role.value = s.role ?? "";
      // Recover the CSRF token from an existing session cookie so a page
      // reload does not lose the ability to make mutations.
      if (s.authenticated && s.via_session && s.csrf_token) {
        setCsrfToken(s.csrf_token);
      }
    } catch {
      authenticated.value = false;
    } finally {
      ready.value = true;
    }
  }

  async function login(user: string, password: string): Promise<void> {
    const r = await api.login(user, password);
    authenticated.value = true;
    username.value = r.username;
    role.value = r.role;
  }

  async function logout(): Promise<void> {
    try {
      await api.logout();
    } finally {
      authenticated.value = false;
      username.value = "";
      role.value = "";
      setCsrfToken(null);
    }
  }

  return { authenticated, username, role, ready, refresh, login, logout };
}
