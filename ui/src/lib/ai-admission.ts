/**
 * Pre-provider AI admission refusals (WOR-2595).
 *
 * `sbproxy_ai_admission_decisions_total{surface,reason,outcome}` counts
 * the requests the AI gateway refused at the inbound native-format shim
 * or the shared stored-prompt resolver, before any provider was chosen.
 * Those refusals are invisible in provider-side numbers, because no
 * provider was called: nothing lands on attempts, errors, or latency.
 *
 * The label values are bounded codes meant for a metrics store, so this
 * module maps them to the phrase an operator reads, and leaves the raw
 * code available for the view to print alongside. The two vocabularies
 * are the ones the emitter uses: `surface` is `AiSurface::label` and
 * `reason` is `ChatError::reason` plus the two stored-prompt bridge
 * codes. Anything outside them is prettified rather than dropped, so a
 * code added on the Rust side still reads as words here.
 */

import type { MetricFamily } from "./metrics";

/** The counter family this module reads. Named once. */
export const AI_ADMISSION_FAMILY = "sbproxy_ai_admission_decisions_total";

/**
 * `AiSurface::label` values, short enough for a bar label. Only the
 * three surfaces a refusal can arrive on today are spelled out; the
 * rest fall through to the generic prettifier.
 */
const SURFACE_LABELS: Readonly<Record<string, string>> = {
  messages: "Anthropic Messages",
  responses: "OpenAI Responses",
  chat_completions: "Chat completions",
  unknown: "Unclassified surface",
};

/**
 * `ChatError::reason` codes plus the stored-prompt bridge codes, in the
 * operator's terms: what the caller sent, not what the parser called
 * it. The refusal's own message is deliberately not available here (it
 * interpolates caller bytes, so neither the metric nor the decision
 * record carries it), which is why these phrases have to stand alone.
 */
const REASON_LABELS: Readonly<Record<string, string>> = {
  tools_mcp_unsupported: "MCP tool block, which would reach an MCP server past this gateway",
  previous_response_id_unsupported: "previous_response_id, which the gateway does not carry",
  conversation_unsupported: "conversation, which the gateway does not carry",
  store_unsupported: "store, which would leave the response at the provider",
  prompt_object_unresolved: "Prompt object the translator could not resolve",
  prompt_object_unrenderable: "Prompt object that failed to render",
  prompt_reference_not_found: "Stored prompt reference no prompt layer holds",
  prompt_render_failed: "Stored prompt template failed to render",
  malformed_json: "Body was not valid JSON",
  body_not_object: "Body was not a JSON object",
  role_missing: "A message carried no role",
  role_unsupported: "A message used a role the gateway does not accept",
  malformed_request: "Refused as malformed, with no narrower code recorded",
};

/** Snake case to a sentence: `audio_transcription` to `Audio transcription`. */
function prettify(code: string): string {
  const words = code.replace(/_/g, " ").trim();
  if (!words) return "Not labeled";
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** Plain name for an inbound AI surface label. */
export function admissionSurfaceLabel(surface: string): string {
  return SURFACE_LABELS[surface] ?? prettify(surface);
}

/** Plain name for a bounded refusal reason code. */
export function admissionReasonLabel(reason: string): string {
  return REASON_LABELS[reason] ?? prettify(reason);
}

/**
 * Plain name for the decision outcome. `deny` is the only value the
 * emitter writes today; the label is carried anyway so an admit-side
 * counterpart can share the family, so read whatever arrives.
 */
export function admissionOutcomeLabel(outcome: string): string {
  if (outcome === "deny") return "denied";
  if (outcome === "allow" || outcome === "admit") return "admitted";
  return prettify(outcome).toLowerCase();
}

/** One `surface / reason / outcome` series, ready to render. */
export interface AdmissionRefusalRow {
  /** Stable `v-for` key. */
  key: string;
  surface: string;
  surfaceLabel: string;
  reason: string;
  reasonLabel: string;
  outcome: string;
  outcomeLabel: string;
  count: number;
}

/** What the view needs to draw the panel, or `undefined` if unreported. */
export interface AdmissionSummary {
  /** Every decision on the family, whatever the outcome. */
  total: number;
  /** The refused slice, which is all of it today. */
  denials: number;
  /** Descending by count, then by surface and reason for a stable order. */
  rows: AdmissionRefusalRow[];
  /** Refusals per inbound surface, descending. */
  bySurface: { key: string; value: number }[];
}

/**
 * Summarize the admission counter.
 *
 * Returns `undefined` when the family is absent from the scrape, which
 * is a different fact from zero refusals: the counter is registered on
 * its first increment, so a build that has never refused a request
 * before dispatch publishes no family at all. `sumSamples(undefined)`
 * returns 0 and would draw that as a healthy signal, so the caller has
 * to be able to tell the two apart and say "not reported".
 */
export function admissionSummary(
  family: MetricFamily | undefined,
): AdmissionSummary | undefined {
  if (!family) return undefined;

  const acc = new Map<string, AdmissionRefusalRow>();
  for (const sample of family.samples) {
    const surface = sample.labels.surface ?? "";
    const reason = sample.labels.reason ?? "";
    const outcome = sample.labels.outcome ?? "";
    const key = `${surface}|${reason}|${outcome}`;
    const existing = acc.get(key);
    if (existing) {
      existing.count += sample.value;
      continue;
    }
    acc.set(key, {
      key,
      surface,
      surfaceLabel: admissionSurfaceLabel(surface),
      reason,
      reasonLabel: admissionReasonLabel(reason),
      outcome,
      outcomeLabel: admissionOutcomeLabel(outcome),
      count: sample.value,
    });
  }

  const rows = [...acc.values()].sort(
    (a, b) =>
      b.count - a.count ||
      (a.surface < b.surface ? -1 : a.surface > b.surface ? 1 : 0) ||
      (a.reason < b.reason ? -1 : a.reason > b.reason ? 1 : 0),
  );

  const bySurface = new Map<string, number>();
  let total = 0;
  let denials = 0;
  for (const row of rows) {
    total += row.count;
    if (row.outcome === "deny") {
      denials += row.count;
      bySurface.set(row.surfaceLabel, (bySurface.get(row.surfaceLabel) ?? 0) + row.count);
    }
  }

  return {
    total,
    denials,
    rows,
    bySurface: [...bySurface.entries()]
      .map(([key, value]) => ({ key, value }))
      .sort((a, b) => b.value - a.value),
  };
}
