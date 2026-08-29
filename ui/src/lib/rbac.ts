/*
 * Console-side RBAC (WOR-2576).
 *
 * # What this is, and what it is emphatically not
 *
 * This module decides what the admin console *renders* and what it is
 * willing to *send*. It is not authorization. The admin server is the
 * authorization, and it stays the authorization whatever this file says:
 *
 *   - `crates/sbproxy-core/src/admin.rs:8043` refuses every
 *     state-changing method from a `read_only` operator with a 403. That
 *     rule is method-shaped and route-blind, which is why `mutate` below
 *     is keyed off the HTTP method and not off a list of routes. A route
 *     added tomorrow is covered by the server rule the day it lands, and
 *     is covered here on the same day for the same reason.
 *   - `crates/sbproxy-core/src/admin.rs:6608` refuses
 *     `GET /api/requests/{id}/content` to anything but the admin role.
 *   - `crates/sbproxy-core/src/admin_compression.rs:489` refuses the
 *     compression content record the same way.
 *
 * Those three are the enforcers. This module mirrors them so the console
 * can disable a control and say why, instead of rendering a button whose
 * only outcome is a 403 toast the operator has to interpret.
 *
 * # Why a mirror is safe even when it is wrong
 *
 * Every path through this module can only ever *refuse*. There is no
 * branch that grants anything: a call the console permits is still a
 * call the server evaluates from scratch. So the failure mode of a bug
 * here is an operator losing an affordance they were entitled to, which
 * is visible and reportable, and never an operator gaining one they were
 * not, which would be silent. That asymmetry is the reason it is
 * acceptable to keep a copy of the rule on the client at all.
 *
 * # What this cannot see
 *
 * - **Per-resource scoping.** `AdminOperator.tenant` narrows
 *   `/api/meter/*` to one billing tenant server-side. Nothing here reads
 *   it, so the console does not pre-empt a cross-tenant meter refusal;
 *   that surfaces as the server's 403.
 * - **Any role beyond the two that exist.** `AdminRole` in
 *   `crates/sbproxy-config/src/types.rs` has exactly `read_only` and
 *   `admin` today. The named-role set WOR-2576 asks for is not
 *   expressible until that enum grows. `capabilitiesFor` denies
 *   everything to a role it does not recognize precisely so that adding
 *   one server-side cannot silently render as full admin here.
 * - **Route-specific admin-only reads added after this build.** The two
 *   named above are enumerated by path. A third would read as
 *   ungated here and be refused by the server, which is the safe
 *   direction of that error but still a stale mirror. `ADMIN_ONLY_READS`
 *   is the list to extend.
 */

/** The full-access role, spelled as the server's `role_label` emits it. */
export const ADMIN_ROLE = "admin";

/** The read-only role, spelled as the server's `role_label` emits it. */
export const READ_ONLY_ROLE = "read_only";

/**
 * A thing the console may or may not do, coarse enough to correspond to
 * an actual server rule rather than to a button.
 *
 * - `mutate` mirrors the global state-changing-method rule.
 * - `inspect_content` mirrors the two routes that return captured caller
 *   content and require the admin role even to read.
 */
export type Capability = "mutate" | "inspect_content";

const ADMIN_CAPABILITIES: readonly Capability[] = ["mutate", "inspect_content"];

/**
 * The capabilities a role carries.
 *
 * Default deny. Anything that is not exactly `admin` or exactly
 * `read_only`, including a differently-cased spelling, a padded string,
 * an absent role, or a role this build has never heard of, gets nothing.
 *
 * The comparison is deliberately exact rather than trimmed or
 * lowercased. The server emits these two literals from `role_label`, so
 * a value that does not match one of them did not come from the code
 * path this mirror was written against, and guessing at its intent is
 * how a mirror drifts into inventing permissions.
 *
 * A fresh set per call, deliberately. A shared instance handed to a view
 * is a piece of mutable privilege state that any caller could widen for
 * every later reader, and this is the one module where that would be
 * worth someone's while.
 */
export function capabilitiesFor(
  role: string | null | undefined,
): ReadonlySet<Capability> {
  if (role === ADMIN_ROLE) return new Set(ADMIN_CAPABILITIES);
  return new Set<Capability>();
}

/** Whether `role` carries `capability`. The `hasCapability` shape LiteLLM's
 *  admin UI gates its sections with, and the one WOR-2576 cites. */
export function hasCapability(
  role: string | null | undefined,
  capability: Capability,
): boolean {
  return capabilitiesFor(role).has(capability);
}

const MUTATING_METHODS: ReadonlySet<string> = new Set([
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
]);

/*
 * The admin-only reads, by exact route shape.
 *
 * Anchored at both ends and single-segment in the id position on
 * purpose. A looser `/content$/` would classify any future route ending
 * in `content` as admin-only, which would make it vanish for read_only
 * operators who are in fact allowed to read it; a looser id pattern
 * would let `/api/requests/a/b/content` match a route that does not
 * exist. Both errors are quiet, so the pattern is strict and the list is
 * short.
 */
const ADMIN_ONLY_READS: readonly RegExp[] = [
  /^\/api\/requests\/[^/]+\/content$/,
  /^\/admin\/compression\/sessions\/[^/]+\/content$/,
];

/**
 * The capability a request needs, or `null` when it needs none.
 *
 * Method first, because that is the shape of the server's widest rule.
 * A safe method then falls through to the admin-only read list.
 */
export function capabilityForRequest(
  method: string,
  path: string,
): Capability | null {
  if (MUTATING_METHODS.has(method.toUpperCase())) return "mutate";
  const pathOnly = path.split("?")[0] ?? path;
  if (ADMIN_ONLY_READS.some((pattern) => pattern.test(pathOnly))) {
    return "inspect_content";
  }
  return null;
}

/** Bound on how much of a role string is echoed back into a message. */
const ROLE_ECHO_LIMIT = 32;

function describeRole(role: string | null | undefined): string {
  if (role === null || role === undefined || role === "") {
    return "this session carries no role";
  }
  if (role === READ_ONLY_ROLE) return "the read-only role (read_only)";
  if (role === ADMIN_ROLE) return "the admin role (admin)";
  const shown =
    role.length > ROLE_ECHO_LIMIT ? `${role.slice(0, ROLE_ECHO_LIMIT)}...` : role;
  return `"${shown}", which is not a role this console knows`;
}

/**
 * Why a call was refused, phrased for an operator reading a disabled
 * control.
 *
 * Says what the server would do rather than implying the console
 * decided, because an operator who reads this and then reaches the same
 * route with curl should not be surprised.
 */
export function refusalReason(
  capability: Capability,
  role: string | null | undefined,
): string {
  const who = describeRole(role);
  if (capability === "inspect_content") {
    return `Reading captured request content requires the admin role; this session has ${who}. The admin API refuses this read for any other role.`;
  }
  return `This action changes state, and the admin API allows that only for the admin role; this session has ${who}. A read-only operator is refused with a 403.`;
}
