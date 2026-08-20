/**
 * Filter-state-to-URL helpers (WOR-2578), following LiteLLM's pattern:
 * dashboard filter state persists in URL query params, so a filtered
 * view is a shareable link by default rather than a separate "saved
 * filter" object to manage.
 *
 * Views own their refs; these helpers translate between a flat
 * `Record<string, string>` of filter values (empty string means unset)
 * and the router's query object. Any view with server-side filters
 * (Reports, Routing decisions, Logs) can adopt them: read state with
 * `filterStateFromQuery(route.query, KEYS)` on mount, and write it
 * back with `router.replace({ query: filterStateToQuery(state) })`
 * whenever a filter changes.
 */

/** Flat filter state: key to value, empty string meaning unset. */
export type UrlFilterState = Record<string, string>;

/**
 * Build a router query object from filter state. Unset (empty)
 * dimensions are dropped so the shared link carries no noise.
 */
export function filterStateToQuery(state: UrlFilterState): Record<string, string> {
  const query: Record<string, string> = {};
  for (const [key, value] of Object.entries(state)) {
    if (value !== "") query[key] = value;
  }
  return query;
}

/**
 * Read the named keys back out of a parsed route query. The first
 * value wins when a key repeats; null and non-string values read as
 * unset; keys outside `keys` are ignored, so an unrelated query param
 * never leaks into filter state.
 */
export function filterStateFromQuery(
  query: Record<string, unknown>,
  keys: readonly string[],
): UrlFilterState {
  const state: UrlFilterState = {};
  for (const key of keys) {
    const raw = query[key];
    const value = Array.isArray(raw) ? raw[0] : raw;
    state[key] = typeof value === "string" ? value : "";
  }
  return state;
}

/**
 * Normalize a comma-separated grouping selection read out of a URL
 * against the dimensions a view supports.
 *
 * A hand-edited or truncated link can name a dimension that does not
 * exist, or name one twice, and the report API refuses both. Rather
 * than hand a shared link straight to the server and render its error,
 * keep the known dimensions, drop the rest, deduplicate, and return
 * them in `known`'s canonical order so two selections of the same set
 * build the same link. An empty result means the caller should keep
 * its own default rather than send an empty `group_by`, which the API
 * also refuses.
 */
export function groupByFromQuery(raw: string, known: readonly string[]): string[] {
  const wanted = new Set(raw.split(","));
  return known.filter((dimension) => wanted.has(dimension));
}
