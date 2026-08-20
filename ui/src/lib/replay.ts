// WOR-2580: replay a logged request into the playground.
//
// The request ring retains metadata only (origin, model, key, tokens,
// decisions); the request body exists solely as the redacted content
// sample WOR-2096 stores when the origin sets `capture_content: true`
// AND the governed key's policy consents with `allow_content_capture`.
// Replay therefore reconstructs what the log actually holds and says
// plainly what it does not: it never invents content, and it sends the
// redacted capture, not the original bytes. The dispatch itself goes
// through the governed `/admin/api/playground/dispatch` route, so the
// replayed request runs the full policy chain like the original did.

import type { CapturedMessage, ContentSample, RequestLog } from "../api";

/** The handoff a log row can seed: everything here rides the URL. */
export interface ReplaySeed {
  /** Request id of the logged entry; keys the content-sample lookup. */
  requestId: string;
  /** Origin hostname the request was dispatched for. */
  origin?: string;
  /** Model the log retained, when routing resolved one. */
  model?: string;
  /** Minted virtual key the original request ran as. */
  keyId?: string;
}

/** A reconstruction in progress or settled. */
export interface ReplayDraft extends ReplaySeed {
  /** Captured, redacted input messages, when the sample exists. */
  messages: CapturedMessage[] | null;
  /** Prompt seed: the last captured user message, verbatim. */
  prompt: string;
  /** Body reconstruction state. */
  content: "pending" | "captured" | "missing";
  /** The server's reason when the body could not be reconstructed. */
  contentGap?: string;
}

/**
 * Build the playground handoff query for a log row, or `null` when the
 * row is not replayable: the playground dispatches chat completions,
 * so a row needs a request id, an origin, and evidence it was an AI
 * dispatch. A resolved model or provider is that evidence, and so are
 * token counts or a guardrail decision, which a request blocked before
 * routing carries when neither resolved. A native pass-through key is
 * not a dispatchable virtual key, so only a minted key id rides along.
 */
export function replayQueryFor(request: RequestLog): Record<string, string> | null {
  if (!request.request_id || !request.origin) return null;
  const aiDispatched =
    request.model !== undefined ||
    request.provider !== undefined ||
    request.tokens_in !== undefined ||
    request.tokens_out !== undefined ||
    request.guardrail_action !== undefined;
  if (!aiDispatched) return null;
  const query: Record<string, string> = {
    replay: request.request_id,
    origin: request.origin,
  };
  if (request.model) query.model = request.model;
  if (request.api_key_id && request.key_mode === "minted") {
    query.key = request.api_key_id;
  }
  return query;
}

/** Start a reconstruction: metadata from the URL, body still pending. */
export function beginReplay(seed: ReplaySeed): ReplayDraft {
  return { ...seed, messages: null, prompt: "", content: "pending" };
}

/**
 * Settle the body half of a reconstruction. With a sample, the prompt
 * seeds from the last captured user message and the sample may fill in
 * origin or model the URL lacked (the sample records both). Without
 * one, the draft records the server's reason and reconstructs nothing:
 * an absent body stays absent.
 */
export function resolveReplayContent(
  draft: ReplayDraft,
  sample: ContentSample | null,
  error: string | null,
): ReplayDraft {
  if (!sample) {
    return {
      ...draft,
      messages: null,
      prompt: "",
      content: "missing",
      contentGap: error ?? "no content sample retained for this request",
    };
  }
  const messages = sample.input_messages.map((m) => ({
    role: m.role,
    content: m.content,
  }));
  const lastUser = [...messages].reverse().find((m) => m.role === "user");
  return {
    ...draft,
    origin: draft.origin ?? sample.origin,
    model: draft.model ?? sample.model ?? undefined,
    messages,
    prompt: lastUser?.content ?? "",
    content: "captured",
  };
}

/**
 * The messages array a dispatch should carry. A captured replay sends
 * every captured message in order, with the prompt box's current text
 * in the last user slot (appended when the capture held no user
 * message). Anything else is the plain single-prompt form.
 */
export function replayDispatchMessages(
  draft: ReplayDraft | null,
  prompt: string,
): CapturedMessage[] {
  if (!draft?.messages || draft.content !== "captured") {
    return [{ role: "user", content: prompt }];
  }
  const messages = draft.messages.map((m) => ({ role: m.role, content: m.content }));
  const lastUser = messages.map((m) => m.role).lastIndexOf("user");
  if (lastUser === -1) {
    messages.push({ role: "user", content: prompt });
  } else {
    messages[lastUser] = { role: "user", content: prompt };
  }
  return messages;
}

/**
 * What this reconstruction could not recover, stated plainly. Sampling
 * parameters are never in the log, so that gap is always present.
 */
export function replayGaps(draft: ReplayDraft): string[] {
  const gaps: string[] = [];
  if (draft.content === "pending") {
    gaps.push("Loading the captured content sample.");
  } else if (draft.content === "missing") {
    gaps.push(
      `The request body could not be reconstructed: ${draft.contentGap}. ` +
        "Only the fields the log retains are pre-filled; type a prompt to dispatch.",
    );
  } else {
    gaps.push(
      "Captured content is redacted before storage; the replay sends the redacted text, not the original.",
    );
    if (!draft.prompt) {
      gaps.push(
        "The capture holds no user message; typing a prompt appends one after the captured messages.",
      );
    }
  }
  gaps.push(
    "Sampling parameters are not retained in the request log; the replay dispatches with the playground's defaults.",
  );
  return gaps;
}

/** What the playground and key inventories currently offer. An absent
 *  list means "still loading", which produces no note. */
export interface ReplayAvailability {
  origins?: string[];
  keyIds?: string[];
  models?: string[];
}

/**
 * Notes for the parts of the log entry that no longer resolve against
 * the live server: a removed origin, a revoked or blocked key, a model
 * the endpoint no longer declares.
 */
export function replayAvailabilityNotes(
  draft: ReplayDraft,
  availability: ReplayAvailability,
): string[] {
  const notes: string[] = [];
  const { origins, keyIds, models } = availability;
  if (draft.origin && origins && !origins.includes(draft.origin)) {
    notes.push(
      `Origin ${draft.origin} is not a configured AI endpoint on this server; pick another endpoint before dispatching.`,
    );
  }
  if (draft.keyId && keyIds && !keyIds.includes(draft.keyId)) {
    notes.push(
      `The original virtual key (${draft.keyId}) is not an active key anymore; the replay dispatches as the key selected above instead.`,
    );
  }
  if (draft.model && models && models.length > 0 && !models.includes(draft.model)) {
    notes.push(
      `Model ${draft.model} is not in the endpoint's declared list; the replay still requests it as logged.`,
    );
  }
  return notes;
}
