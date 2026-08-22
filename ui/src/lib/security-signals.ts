/**
 * Edge and transport security signals read out of the `/metrics` scrape.
 *
 * Three families shipped with writers and no reader. The console curates
 * families by name, so a family nobody names is invisible however healthy
 * the exporter is, and these three are exactly the ones an operator has no
 * other way to see: the CORS refusal and the legacy signature acceptance
 * are each logged once per process and then only counted, and the
 * certificate-store gauge is set once at startup and never mentioned again.
 *
 * The derivations live here rather than in a view so the absent/zero
 * distinction can be tested directly against `parsePrometheus` output.
 * `sumSamples(undefined)` returns 0, so a family that was never registered
 * and a family sitting at zero are indistinguishable once summed. Each
 * function below therefore branches on the family itself and returns
 * `undefined` for "not reported".
 */
import {
  findFamily,
  groupByLabel,
  sumSamples,
  type MetricFamily,
} from "./metrics";

/** Responses the CORS middleware refused to decorate, by reason. */
export const CORS_REFUSALS_FAMILY = "sbproxy_cors_refusals_total";

/** RFC 9421 signatures accepted only on the pre-conformance derivation. */
export const SIGNATURE_LEGACY_DERIVATION_FAMILY =
  "sbproxy_signature_legacy_derivation_total";

/** 1 when the configured certificate store fell back to memory, 0 when it opened. */
export const CERT_STORE_DEGRADED_FAMILY = "sbproxy_cert_store_degraded";

/** A counter family reduced to a total plus its label breakdown. */
export interface CountedSignal {
  total: number;
  breakdown: { key: string; value: number }[];
}

function countedSignal(
  family: MetricFamily | undefined,
  label: string,
): CountedSignal | undefined {
  if (!family) return undefined;
  return {
    total: sumSamples(family),
    breakdown: groupByLabel(family, label).filter((b) => b.key !== "(none)"),
  };
}

/**
 * CORS refusals by reason, or `undefined` when the counter has never been
 * registered.
 *
 * The counter is created on the first refusal, so absent means no response
 * has been refused since the process started. It is not a measured zero and
 * must not be drawn as one.
 */
export function corsRefusals(
  families: MetricFamily[],
): CountedSignal | undefined {
  return countedSignal(findFamily(families, CORS_REFUSALS_FAMILY), "reason");
}

/**
 * RFC 9421 signatures that verified only against the pre-conformance
 * derivation of a request-target component, by component.
 *
 * Absent means no signer has been accepted on the old derivation since this
 * process started. It does not mean signature verification is configured and
 * clean: an origin with no signature verification at all looks identical, so
 * the copy on this signal never claims the deprecation window can close.
 */
export function legacySignatureDerivations(
  families: MetricFamily[],
): CountedSignal | undefined {
  return countedSignal(
    findFamily(families, SIGNATURE_LEGACY_DERIVATION_FAMILY),
    "component",
  );
}

/** What the certificate-store gauge says about this node. */
export type CertStoreState = "not-reported" | "opened" | "degraded";

export interface CertStoreStatus {
  state: CertStoreState;
  /** Badge text. `"not reported"` is the console's word for an absent family. */
  label: string;
  tone: "ok" | "warn" | "neutral";
  /** Every backend the gauge names, whatever its value. */
  backends: string[];
  /** Only the backends sitting at 1. */
  degradedBackends: string[];
  /** Short phrase for a status row next to the badge. */
  summary: string;
  /** The full sentence an operator can act on. */
  detail: string;
}

function backendList(names: string[]): string {
  return names.length ? names.join(", ") : "the configured backend";
}

/**
 * Read the certificate-store gauge.
 *
 * This gauge is published on the success path too, which is what makes the
 * three states distinguishable: `0` is a store that opened, `1` is a store
 * that did not, and an absent family is a node that never opened one because
 * no ACME certificate storage is configured. A gauge that only appeared when
 * something was wrong could not be told apart from a scrape that never
 * happened.
 *
 * A `1` is always a pod-local backend (`redb`, `sqlite`, `memory`). A shared
 * backend that cannot be opened refuses to start rather than degrade,
 * because an in-memory fallback inherits the single-node locking defaults
 * and hands every replica its own ACME issuance lease.
 */
export function certStoreStatus(families: MetricFamily[]): CertStoreStatus {
  const family = findFamily(families, CERT_STORE_DEGRADED_FAMILY);
  if (!family || !family.samples.length) {
    return {
      state: "not-reported",
      label: "not reported",
      tone: "neutral",
      backends: [],
      degradedBackends: [],
      summary: "No certificate store opened on this node.",
      detail:
        "This node has not opened a certificate store. The gauge is published at startup whenever ACME certificate storage is configured, so it is absent here rather than zero.",
    };
  }

  const backends = [
    ...new Set(family.samples.map((s) => s.labels.backend).filter(Boolean)),
  ].sort();
  const degradedBackends = [
    ...new Set(
      family.samples
        .filter((s) => s.value > 0)
        .map((s) => s.labels.backend)
        .filter(Boolean),
    ),
  ].sort();

  if (degradedBackends.length) {
    return {
      state: "degraded",
      label: "degraded",
      tone: "warn",
      backends,
      degradedBackends,
      summary: "Fell back to an in-memory store.",
      detail: `The configured certificate store (${backendList(degradedBackends)}) could not be opened, so this node is serving from an in-memory store. Certificates do not survive a restart and are issued again on every boot, which spends the CA rate limit for the hostname. Repair the backend behind acme.storage_path and restart the node.`,
    };
  }

  return {
    state: "opened",
    label: "ok",
    tone: "ok",
    backends,
    degradedBackends: [],
    summary: `Persisting in ${backendList(backends)}.`,
    detail: `Certificates persist in the configured store (${backendList(backends)}).`,
  };
}
