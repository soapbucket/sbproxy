<script setup lang="ts">
import type { ClusterStatusResponse } from "../api";
import { formatAgeMs } from "../lib/cluster-health";
import { formatTime } from "../lib/format";
import StatusBadge from "./StatusBadge.vue";

const props = defineProps<{ status: ClusterStatusResponse }>();

function ageAgo(ageMs: number): string {
  const age = formatAgeMs(ageMs);
  return age === "Just now" ? age : `${age} ago`;
}

function directoryLabel(): string {
  if (props.status.directory_collected_at_unix_ms === null) return "Not collected";
  return props.status.nodes.some((node) =>
    node.unhealthy_reasons.includes("directory_stale"),
  )
    ? "Stale"
    : "Fresh";
}

function directoryTone(): "ok" | "warn" | "err" | "neutral" {
  if (props.status.directory_collected_at_unix_ms === null) {
    return props.status.configured ? "warn" : "neutral";
  }
  return props.status.nodes.some((node) =>
    node.unhealthy_reasons.includes("directory_stale"),
  )
    ? "err"
    : "ok";
}

function authorityLabel(): string {
  const authority = props.status.deployment_authority;
  if (!authority.configured) return "Not configured";
  if (authority.active_revision === null) return "Awaiting signed bundle";
  return authority.read_only ? "Verified, read only" : "Publishing authority";
}

function authorityTone(): "ok" | "warn" | "info" | "neutral" {
  const authority = props.status.deployment_authority;
  if (!authority.configured) return "neutral";
  if (authority.active_revision === null) return "warn";
  return authority.read_only ? "info" : "ok";
}

function authorityDescription(): string {
  const authority = props.status.deployment_authority;
  if (!authority.configured) {
    return "No signed deployment authority is installed on this node.";
  }
  if (authority.active_revision === null) {
    return "The authority key is configured, but no active signed deployment bundle is available.";
  }
  return "Active deployment state is verified against the configured authority key.";
}
</script>

<template>
  <section class="control-plane" aria-labelledby="control-plane-heading">
    <div class="section-heading">
      <div>
        <p class="sb-eyebrow">Operating state</p>
        <h2 id="control-plane-heading">Control plane</h2>
      </div>
      <p class="section-context sb-mono">{{ status.cluster_id }}</p>
    </div>

    <div class="control-plane__grid">
      <article class="control-fact">
        <p class="control-fact__label">Cluster mode</p>
        <StatusBadge
          :label="status.mode"
          :tone="status.mode === 'distributed' ? 'info' : 'neutral'"
        />
        <p>
          {{
            status.configured
              ? "Distributed membership is configured."
              : "Running as a local, single-node cluster."
          }}
        </p>
        <dl>
          <div><dt>Local node</dt><dd class="sb-mono">{{ status.local_node_id }}</dd></div>
          <div><dt>Configured</dt><dd>{{ status.configured ? "Yes" : "No" }}</dd></div>
        </dl>
      </article>

      <article class="control-fact">
        <p class="control-fact__label">Model directory</p>
        <StatusBadge :label="directoryLabel()" :tone="directoryTone()" />
        <p>
          {{
            status.directory_age_ms === null
              ? "No fleet directory snapshot is available."
              : `Collected ${ageAgo(status.directory_age_ms)}.`
          }}
        </p>
        <dl>
          <div>
            <dt>Collected</dt>
            <dd>{{ formatTime(status.directory_collected_at_unix_ms) }}</dd>
          </div>
          <div><dt>Eligible workers</dt><dd>{{ status.summary.eligible_workers }}</dd></div>
        </dl>
      </article>

      <article class="control-fact">
        <p class="control-fact__label">Signed deployment authority</p>
        <StatusBadge :label="authorityLabel()" :tone="authorityTone()" />
        <p>{{ authorityDescription() }}</p>
        <dl>
          <div>
            <dt>Revision</dt>
            <dd class="sb-mono">{{ status.deployment_authority.active_revision ?? "None" }}</dd>
          </div>
          <div>
            <dt>Signer</dt>
            <dd class="sb-mono">{{ status.deployment_authority.signer_node_id ?? "None" }}</dd>
          </div>
          <div>
            <dt>Verifying key</dt>
            <dd class="sb-mono control-fact__long">
              {{ status.deployment_authority.verifying_key_id ?? "None" }}
            </dd>
          </div>
          <div>
            <dt>Content digest</dt>
            <dd class="sb-mono control-fact__long">
              {{ status.deployment_authority.active_content_digest ?? "None" }}
            </dd>
          </div>
        </dl>
      </article>

      <article class="control-fact">
        <p class="control-fact__label">Deployment state</p>
        <StatusBadge
          :label="status.summary.deployment_digest_mismatch ? 'Digest mismatch' : 'Digests aligned'"
          :tone="status.summary.deployment_digest_mismatch ? 'err' : 'ok'"
        />
        <p>
          {{ status.summary.ready_deployments }} of {{ status.summary.deployments }} deployments
          are target ready.
        </p>
        <dl>
          <div><dt>Rollouts active</dt><dd>{{ status.summary.rollouts_in_progress }}</dd></div>
          <div><dt>Unplaced replicas</dt><dd>{{ status.summary.unplaced_replicas }}</dd></div>
          <div><dt>Eligible replicas</dt><dd>{{ status.summary.eligible_replicas }}</dd></div>
        </dl>
      </article>
    </div>
  </section>
</template>

<style scoped>
.control-plane {
  margin-bottom: var(--sb-space-6);
}

.section-heading {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: var(--sb-space-4);
  margin-bottom: var(--sb-space-4);
}

.section-heading .sb-eyebrow {
  margin: 0 0 var(--sb-space-1);
}

.section-context {
  max-width: 50%;
  margin: 0;
  color: var(--sb-text-faint);
  font-size: 0.78rem;
  text-align: right;
}

.control-plane__grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  overflow: hidden;
  background: var(--sb-surface);
  border: 1px solid var(--sb-border);
  border-radius: var(--sb-radius);
}

.control-fact {
  min-width: 0;
  padding: var(--sb-space-5);
  border-right: 1px solid var(--sb-border);
}

.control-fact:last-child {
  border-right: 0;
}

.control-fact__label {
  margin: 0 0 var(--sb-space-3);
  color: var(--sb-text-faint);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.control-fact > p:not(.control-fact__label) {
  min-height: 3.6em;
  margin: var(--sb-space-3) 0;
  color: var(--sb-text-muted);
  font-size: 0.8rem;
}

.control-fact dl {
  display: grid;
  gap: var(--sb-space-3);
  margin: 0;
}

.control-fact dl div {
  min-width: 0;
}

.control-fact dt {
  margin-bottom: var(--sb-space-1);
  color: var(--sb-text-faint);
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.06em;
  text-transform: uppercase;
}

.control-fact dd {
  margin: 0;
  font-size: 0.82rem;
  overflow-wrap: anywhere;
}

.control-fact__long {
  word-break: break-all;
}

@media (max-width: 1040px) {
  .control-plane__grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .control-fact:nth-child(2) {
    border-right: 0;
  }

  .control-fact:nth-child(-n + 2) {
    border-bottom: 1px solid var(--sb-border);
  }
}

@media (max-width: 760px) {
  .section-heading {
    display: block;
  }

  .section-context {
    max-width: none;
    margin-top: var(--sb-space-2);
    text-align: left;
  }

  .control-plane__grid {
    grid-template-columns: 1fr;
  }

  .control-fact,
  .control-fact:nth-child(2),
  .control-fact:last-child {
    border-right: 0;
    border-bottom: 1px solid var(--sb-border);
  }

  .control-fact:last-child {
    border-bottom: 0;
  }

  .control-fact > p:not(.control-fact__label) {
    min-height: 0;
  }
}
</style>
