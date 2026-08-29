import { computed, type ComputedRef } from "vue";

import { useAuth } from "./useAuth";
import { hasCapability, refusalReason, type Capability } from "../lib/rbac";

/**
 * Render-time RBAC for the console (WOR-2576), the `hasCapability` shape
 * LiteLLM's admin UI gates its sections with.
 *
 * Reads the role off the live session, so a view binds
 * `:disabled="!canMutate"` and gets the right answer on the first paint
 * and again after a sign-in without wiring anything itself.
 *
 * # This hides controls. It does not authorize anything.
 *
 * Two other things are load bearing, and this composable is the least
 * important of the three:
 *
 * 1. The admin server refuses the call. `admin.rs:8043` for every
 *    state-changing method from a `read_only` operator, `admin.rs:6608`
 *    and `admin_compression.rs:489` for the two admin-only reads.
 * 2. The API client refuses to send it, at `assertCapability` in
 *    `../api`, so a control that slipped through this gate still cannot
 *    reach the wire.
 *
 * This layer exists so an operator sees a disabled control with a reason
 * instead of an enabled one that answers 403. Treat a `v-if` written
 * against it as presentation, never as a security boundary, and never
 * write a check here that has no counterpart at (1).
 */
export function useCapabilities(): {
  canMutate: ComputedRef<boolean>;
  canInspectContent: ComputedRef<boolean>;
  can: (capability: Capability) => boolean;
  whyNot: (capability: Capability) => string;
} {
  const { role } = useAuth();

  const canMutate = computed(() => hasCapability(role.value, "mutate"));
  const canInspectContent = computed(() =>
    hasCapability(role.value, "inspect_content"),
  );

  return {
    canMutate,
    canInspectContent,
    /** Whether the signed-in role carries `capability`, read once. */
    can: (capability: Capability) => hasCapability(role.value, capability),
    /**
     * The sentence to put on a disabled control's title or beside it.
     * Names the server rule rather than implying the console decided.
     */
    whyNot: (capability: Capability) => refusalReason(capability, role.value),
  };
}
