# OSS product truth and connected guardrails implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the OSS runtime the single product, add hardened outbound HTTP clients, and connect every documented vendor guardrail to the existing AI request path with validated configuration and local HTTP contract tests.

**Architecture:** `sbproxy-httpkit` owns bounded `reqwest` construction. `sbproxy-ai` keeps a backward-compatible wire configuration, compiles it into typed provider settings, and owns request shaping, response limits, verdict normalization, timeout, fail-mode, metrics, and safe tracing. `sbproxy-modules` resolves credentials, while `sbproxy-core` passes phase and model context through the already connected input and buffered-output guardrail path.

**Tech Stack:** Rust 2021, Tokio, reqwest 0.12, serde, serde_json, schemars, tracing, Prometheus metrics, Cargo nextest, local Tokio TCP fixtures, YAML examples

## Global Constraints

- The repository and every feature in this pull request are Apache-2.0 OSS. Do not add a current enterprise edition, enterprise repository, or enterprise URL.
- "Enterprise AI Gateway" describes supported workloads across API, MCP and agent, and AI model traffic. It is not an edition name.
- Existing external guardrail YAML remains valid, including an omitted `provider` that defaults to `generic` and the current top-level `url`, `api_key`, `auth_header`, and `auth_prefix` fields.
- New behavior is opt-in. Existing configurations retain their behavior except that malformed external verdict JSON now obeys `fail_open` instead of silently allowing.
- Do not implement or document Prompt Security until an authoritative endpoint and schema can be tested. Do not migrate Google Model Armor or the disconnected enterprise guardrail registry.
- Generic webhook, Presidio, Lakera, Aporia, Azure AI Content Safety, Amazon Bedrock Guardrails, CrowdStrike AIDR, Mistral moderation, Pangea AI Guard, and Patronus are the complete advertised adapter set for this pull request.
- Authenticated requests never follow redirects. Every response is capped at 64 KiB. `timeout_ms` must be between 1 and 30,000 inclusive and defaults to 2,000.
- External URLs accept only HTTP or HTTPS. Private, loopback, link-local, metadata, CGNAT, and documentation addresses require `allow_private_url: true`.
- Provider credentials use the existing secret resolver and never appear in errors, logs, fixtures, examples, or snapshots.
- Provider API claims and wire contracts use current official vendor documentation, not the historical private implementation.
- Use `/Users/rick/projects/soapbucket/sbproxy/target` as `CARGO_TARGET_DIR` for all Rust commands.
- Use focused tests during implementation. Run the broader affected-crate lane only once before opening the pull request.
- Public prose uses plain language and contains no em dash or en dash.

---

## File structure

Create or change these units:

```text
crates/sbproxy-httpkit/src/outbound.rs
    Hardened ordinary and token-bearing reqwest clients.
crates/sbproxy-httpkit/tests/redirect_policy.rs
    Cross-host redirect and bounded-redirect behavior.

crates/sbproxy-ai/src/external_guardrail/mod.rs
    Backward-compatible wire config, typed compile step, bounded dispatcher,
    normalized verdict, fail-mode, and phase runner.
crates/sbproxy-ai/src/external_guardrail/generic.rs
    Generic webhook and Presidio request/response contracts.
crates/sbproxy-ai/src/external_guardrail/lakera.rs
crates/sbproxy-ai/src/external_guardrail/aporia.rs
crates/sbproxy-ai/src/external_guardrail/azure.rs
crates/sbproxy-ai/src/external_guardrail/bedrock.rs
crates/sbproxy-ai/src/external_guardrail/crowdstrike.rs
crates/sbproxy-ai/src/external_guardrail/mistral.rs
crates/sbproxy-ai/src/external_guardrail/pangea.rs
crates/sbproxy-ai/src/external_guardrail/patronus.rs
    Provider request shaping and strict verdict parsing only.
crates/sbproxy-ai/tests/external_guardrail_contract.rs
    Local HTTP server that proves the real request path for every adapter.
crates/sbproxy-ai/src/bin/generate-ai-external-guardrail-schema.rs
schemas/ai-external-guardrail.schema.json
    Generated field-level contract for external guardrail configuration.

crates/sbproxy-modules/src/action/aiproxy.rs
    Secret-reference resolution for guardrail credentials.
crates/sbproxy-core/src/server/ai_dispatch.rs
    Model and phase context at the existing input and output call sites.

crates/sbproxy-core/src/hooks.rs
crates/sbproxy-core/src/hook_registry.rs
crates/sbproxy-core/src/server/lifecycle.rs
crates/sbproxy-core/src/pipeline.rs
crates/sbproxy-core/src/config_subscriber.rs
crates/sbproxy-core/tests/hooks.rs
crates/sbproxy-core/tests/hook_registry.rs
    Rename the generic lifecycle hook and remove edition wording.

examples/ai-external-guardrails/sb.yml
examples/ai-external-guardrails/README.md
examples/ai-external-guardrails/smoke.json
examples/ai-external-guardrails/docker-compose.yml
examples/ai-external-guardrails/fixture.py
docs/guardrails.md
    Tested configuration and an operator walkthrough.
```

### Task 1: Rename the lifecycle hook and remove the current edition split

**Files:**
- Modify: `crates/sbproxy-core/src/hooks.rs`
- Modify: `crates/sbproxy-core/src/hook_registry.rs`
- Modify: `crates/sbproxy-core/src/server/lifecycle.rs`
- Modify: `crates/sbproxy-core/src/pipeline.rs`
- Modify: `crates/sbproxy-core/src/config_subscriber.rs`
- Modify: `crates/sbproxy-core/tests/hooks.rs`
- Modify: `crates/sbproxy-core/tests/hook_registry.rs`
- Modify: `crates/sbproxy-config/src/compiler.rs`
- Modify: `crates/sbproxy-config/src/snapshot.rs`
- Modify: `crates/sbproxy-mesh/src/federation.rs`
- Modify: `crates/sbproxy-mesh/src/node_handle.rs`
- Modify: `crates/sbproxy-mesh/src/persistence.rs`
- Modify: `crates/sbproxy-modules/src/transform/mod.rs`
- Modify: `crates/sbproxy-core/src/policy_bus.rs`
- Modify: `crates/sbproxy-openapi/src/lib.rs`
- Delete: `docs/enterprise.md`
- Modify: `README.md`
- Modify: `docs/README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/402-challenge.md`
- Modify: `docs/ai-crawl-control.md`
- Modify: `docs/cache-reserve.md`
- Modify: `docs/exposed-credentials.md`
- Modify: `docs/features.md`
- Modify: `docs/faq.md`
- Modify: `docs/scripting.md`
- Modify: `BENCHMARK.md`
- Modify: `MIGRATION.md`
- Modify: `SECURITY.md`
- Modify: `SUPPLY-CHAIN.md`
- Modify: `AGENTS.md`
- Modify: `CLAUDE.md`
- Modify: `bench-synthetic/Cargo.toml`
- Modify: `scripts/docs-ci.sh`
- Modify: `scripts/check-spec-citations.sh`
- Delete: `scripts/check-crate-graph.sh`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: Existing `register_startup_hook!` inventory registration and `Hooks.startup`.
- Produces: `pub trait PipelineLifecycleHook`, `Hooks.startup: Option<Arc<dyn PipelineLifecycleHook>>`, and `DegradedSubsystem::PipelineLifecycleHook` with stable string `pipeline_lifecycle_hook`.

- [ ] **Step 1: Rename the tests first**

Update the object-safety and registry tests to use this exact public contract:

```rust
use sbproxy_core::hooks::PipelineLifecycleHook;

assert_object_safe::<dyn PipelineLifecycleHook>();

#[async_trait::async_trait]
impl PipelineLifecycleHook for DummyHook {
    async fn on_startup(
        &self,
        _pipeline: &mut CompiledPipeline,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn on_reload(
        &self,
        _pipeline: &mut CompiledPipeline,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}
```

Change lifecycle assertions from `EnterpriseHook` and `enterprise_hook` to
`PipelineLifecycleHook` and `pipeline_lifecycle_hook`.

- [ ] **Step 2: Run the renamed tests and verify they fail**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core \
  -E 'test(hooks) | test(hook_registry) | test(lifecycle)'
```

Expected: compile failure because `PipelineLifecycleHook` and the renamed
degraded subsystem do not exist.

- [ ] **Step 3: Rename the public hook without a compatibility alias**

Use these exact names:

```rust
#[async_trait::async_trait]
pub trait PipelineLifecycleHook: Send + Sync {
    async fn on_startup(
        &self,
        pipeline: &mut CompiledPipeline,
    ) -> anyhow::Result<()>;

    async fn on_reload(
        &self,
        pipeline: &mut CompiledPipeline,
    ) -> anyhow::Result<()>;
}

#[derive(Default)]
pub struct Hooks {
    pub startup: Option<Arc<dyn PipelineLifecycleHook>>,
}
```

Keep the macro name `register_startup_hook!`. Change its factory type and
collector return type to `Arc<dyn PipelineLifecycleHook>`. Rename the degraded
subsystem variant and its stable string. Update comments in the listed config,
mesh, module, pipeline, and subscriber files so the hook is described as a
normal pipeline lifecycle extension.

- [ ] **Step 4: Remove current product-split machinery and copy**

Delete `docs/enterprise.md` and the enterprise crate-graph script. Remove the
associated CI job and sibling-repository branches from the two documentation
scripts. Rewrite current-facing root copy so it states:

```text
SBproxy is an open source Enterprise AI Gateway for API, MCP and agent, and AI
model traffic. Every feature in this repository ships under Apache-2.0.
```

Do not promise RAG, distributed semantic cache, or settlement until their later
pull requests merge. Point necessary Go migration history to
`https://github.com/soapbucket/sbproxy-go`. Leave factual historical changelog
entries intact.

- [ ] **Step 5: Verify the rename and stale-reference boundary**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core \
  -E 'test(hooks) | test(hook_registry) | test(lifecycle)'
rg -n 'EnterpriseStartupHook|EnterpriseHook|enterprise_hook|enterprise-only|sbproxy-rust|sbproxy\.dev/enterprise|sbproxy-enterprise' \
  README.md BENCHMARK.md MIGRATION.md SECURITY.md SUPPLY-CHAIN.md AGENTS.md CLAUDE.md \
  bench-synthetic docs scripts crates \
  --glob '!CHANGELOG.md' \
  --glob '!docs/llms*.txt' \
  --glob '!docs/superpowers/**'
```

Expected: tests pass. The search has no current product, code, or script hits.
Any preserved historical result must point to `sbproxy-go`.

- [ ] **Step 6: Commit the product-truth boundary**

```bash
git add .github/workflows/ci.yml README.md BENCHMARK.md MIGRATION.md SECURITY.md \
  SUPPLY-CHAIN.md AGENTS.md CLAUDE.md bench-synthetic/Cargo.toml docs crates scripts
git commit -m "refactor: make lifecycle hooks product neutral"
```

### Task 2: Add hardened outbound HTTP clients

**Files:**
- Modify: `crates/sbproxy-httpkit/Cargo.toml`
- Modify: `crates/sbproxy-httpkit/src/lib.rs`
- Create: `crates/sbproxy-httpkit/src/outbound.rs`
- Create: `crates/sbproxy-httpkit/tests/redirect_policy.rs`

**Interfaces:**
- Consumes: Workspace `reqwest = 0.12`.
- Produces:

```rust
pub fn default_outbound() -> reqwest::Client;
pub fn token_bearing_outbound() -> reqwest::Client;
pub struct OutboundClientBuilder;
```

with builder methods `new`, `connect_timeout`, `request_timeout`,
`pool_idle_timeout`, `max_idle_per_host`, `no_redirects`,
`limited_redirects`, `user_agent`, `build`, and `into_inner`.

- [ ] **Step 1: Write redirect-policy tests**

Create two loopback listeners. The first returns a `302 Location` for the
second. Assert:

```rust
let response = token_bearing_outbound()
    .get(first_url)
    .header("Authorization", "Bearer fixture-secret")
    .send()
    .await?;

assert_eq!(response.status(), reqwest::StatusCode::FOUND);
assert!(!second_was_hit.load(Ordering::SeqCst));
```

Add a second test that uses `default_outbound()` without credentials and
asserts one redirect succeeds, while a three-hop chain returns an error after
the configured limit of two.

- [ ] **Step 2: Run the HTTP-kit tests and verify they fail**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-httpkit
```

Expected: compile failure because the outbound constructors are absent.

- [ ] **Step 3: Implement the bounded builder**

Add `reqwest.workspace = true` and `tokio.workspace = true` as a dev
dependency. Implement these exact defaults:

```rust
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
pub const DEFAULT_MAX_IDLE_PER_HOST: usize = 64;
pub const DEFAULT_REDIRECT_LIMIT: usize = 2;
pub const USER_AGENT: &str = concat!("sbproxy/", env!("CARGO_PKG_VERSION"));
```

`default_outbound()` uses `Policy::limited(2)`.
`token_bearing_outbound()` uses `Policy::none()`. Both set all four timeout and
pool values plus the user agent. Preserve TLS certificate verification. Do not
add an accept-invalid-certificate switch.

- [ ] **Step 4: Run the HTTP-kit tests**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-httpkit
```

Expected: all buffer-pool and outbound-client tests pass.

- [ ] **Step 5: Commit the shared client**

```bash
git add crates/sbproxy-httpkit
git commit -m "feat(httpkit): add bounded outbound clients"
```

### Task 3: Compile backward-compatible configuration into a strict provider contract

**Files:**
- Modify: `crates/sbproxy-ai/Cargo.toml`
- Delete: `crates/sbproxy-ai/src/external_guardrail.rs`
- Create: `crates/sbproxy-ai/src/external_guardrail/mod.rs`
- Create: `crates/sbproxy-ai/src/external_guardrail/generic.rs`
- Modify: `crates/sbproxy-ai/src/guardrails/mod.rs`
- Modify: `crates/sbproxy-ai/src/handler.rs`
- Modify: `crates/sbproxy-ai/src/ai_metrics.rs`
- Modify: `crates/sbproxy-observe/src/metric_registry.rs`
- Create: `crates/sbproxy-ai/tests/external_guardrail_contract.rs`

**Interfaces:**
- Consumes: `sbproxy_httpkit::token_bearing_outbound`,
  `sbproxy_security::ssrf::validate_url`, `GuardrailsConfig.external`.
- Produces:

```rust
pub enum GuardrailPhase { Input, Output }

pub struct ExternalGuardrailRequest<'a> {
    pub content: &'a str,
    pub model: &'a str,
    pub phase: GuardrailPhase,
}

pub struct GuardrailVerdict {
    pub allowed: bool,
    pub reason: Option<String>,
    pub categories: Vec<String>,
    pub scores: BTreeMap<String, f64>,
}

pub async fn check_external_guardrail(
    config: &ExternalGuardrailConfig,
    request: ExternalGuardrailRequest<'_>,
) -> GuardrailVerdict;
```

- [ ] **Step 1: Write config and malformed-verdict tests**

Preserve this existing document:

```yaml
name: custom
url: https://guard.example.test/check
mode: pre_call
default_on: true
api_key: secret://guard-key
```

Add tests named:

```text
legacy_generic_config_defaults_provider
timeout_must_be_between_one_and_thirty_seconds
private_url_requires_explicit_opt_in
provider_required_fields_fail_during_load
generic_response_without_verdict_is_an_error
oversized_response_obeys_fail_mode
logging_only_records_but_never_blocks
```

The malformed response fixture is `{"analysis":{"risk":"unknown"}}`. Assert
fail-open allows it and fail-closed blocks it.

- [ ] **Step 2: Run the focused tests and verify the new assertions fail**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-ai external_guardrail
```

Expected: failures for permissive malformed JSON, missing validation, and the
new request/verdict types.

- [ ] **Step 3: Add the wire configuration and typed compile result**

Add `sbproxy-httpkit.workspace = true` to `sbproxy-ai`. Keep its existing
direct `reqwest` dependency because unrelated provider clients still use it.

Keep `ExternalGuardrailConfig` as the deserialized public wire shape. It owns
the existing common fields and these provider fields:

```rust
pub struct ExternalGuardrailConfig {
    pub name: String,
    pub url: Option<String>,
    pub mode: GuardrailMode,
    pub default_on: bool,
    pub fail_open: bool,
    pub timeout_ms: u64,
    pub provider: GuardrailProvider,
    pub api_key: Option<String>,
    pub auth_header: Option<String>,
    pub auth_prefix: Option<String>,
    pub allow_private_url: bool,
    pub language: Option<String>,
    pub project_id: Option<String>,
    pub application_id: Option<String>,
    pub region: Option<String>,
    pub guardrail_id: Option<String>,
    pub guardrail_version: Option<String>,
    pub severity_threshold: Option<u8>,
    pub model: Option<String>,
    pub score_threshold: Option<f64>,
    pub input_recipe: Option<String>,
    pub output_recipe: Option<String>,
    pub evaluator: Option<String>,
    pub criteria: Option<String>,
    #[serde(skip)]
    #[schemars(skip)]
    client: std::sync::OnceLock<reqwest::Client>,
}
```

Compile it during validation into provider-specific structs held by:

```rust
pub enum CompiledGuardrailProvider {
    Generic(GenericConfig),
    Presidio(PresidioConfig),
    Lakera(LakeraConfig),
    Aporia(AporiaConfig),
    AzureContentSafety(AzureConfig),
    Bedrock(BedrockConfig),
    CrowdStrike(CrowdStrikeConfig),
    Mistral(MistralConfig),
    Pangea(PangeaConfig),
    Patronus(PatronusConfig),
}
```

`GuardrailProvider` uses `#[serde(rename_all = "snake_case")]`, defaults to
`Generic`, and contains exactly the ten variants in
`CompiledGuardrailProvider`. Every optional wire field uses `#[serde(default)]`
so a legacy generic document can omit both `provider` and `url` only when a
provider-specific default URL exists. Generic and Presidio still require
`url`.

`ExternalGuardrailConfig::validate()` checks name, timeout, thresholds,
required fields, provider URL, and unresolved `${NAME}` references. A private
test URL is accepted only with `allow_private_url: true`. Add
`credential_reference_mut() -> Option<&mut String>` for the resolver.

For a public endpoint, `client()` calls
`sbproxy_security::validate_url_resolved`, builds a token-bearing client with
`reqwest::ClientBuilder::resolve_to_addrs`, and stores it in `client`. This
pins the validated socket addresses to the dial and closes the DNS-rebinding
gap documented by `sbproxy-security`. An explicit private endpoint uses the
same no-redirect client without the public-address check. Client construction
happens once per deserialized guardrail, so connections remain pooled.

- [ ] **Step 4: Implement one bounded dispatcher**

Use a process-wide token-bearing client. Apply the configured timeout to each
request. Read the response in chunks and stop before allocating more than
`64 * 1024` bytes:

```rust
const MAX_GUARDRAIL_RESPONSE_BYTES: usize = 64 * 1024;

while let Some(chunk) = response.chunk().await? {
    if body.len().saturating_add(chunk.len()) > MAX_GUARDRAIL_RESPONSE_BYTES {
        return Err(GuardrailCallError::ResponseTooLarge);
    }
    body.extend_from_slice(&chunk);
}
```

Return an internal `Result<GuardrailVerdict, GuardrailCallError>`, then apply
`fail_open` once in `check_external_guardrail`. Never let provider parsers
invent an allow verdict for unknown JSON.

- [ ] **Step 5: Add closed-label metrics and safe tracing**

Record provider, phase, and outcome only:

```rust
record_external_guardrail_verdict(provider.as_str(), phase.as_str(), outcome);
```

The allowed outcome labels are `allow`, `block`, `fail_open`, and
`fail_closed`. Add
`sbproxy_ai_external_guardrail_verdicts_total{provider,phase,outcome}` to the
metric registry. Trace name, provider, phase, latency, categories, and outcome.
Do not trace content, request bodies, response bodies, URLs containing query
values, or credentials.

- [ ] **Step 6: Validate external entries while loading the AI handler**

After `validate_pipeline_config`, call `external.validate()` for every entry
and prefix errors with the configured name, for example:

```text
ai external guardrail 'customer-policy': missing api_key
```

Keep `logging_only` nonblocking. Keep `default_on` behavior unchanged.

- [ ] **Step 7: Run the strict core tests**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-ai external_guardrail
```

Expected: the backward-compatibility, validation, response-cap, malformed
response, fail-mode, metric-label, and generic/Presidio tests pass.

- [ ] **Step 8: Commit the strict provider foundation**

```bash
git add crates/sbproxy-ai crates/sbproxy-observe
git commit -m "feat(ai): harden external guardrail contracts"
```

### Task 4: Connect current Lakera and Aporia contracts

**Files:**
- Create: `crates/sbproxy-ai/src/external_guardrail/lakera.rs`
- Create: `crates/sbproxy-ai/src/external_guardrail/aporia.rs`
- Modify: `crates/sbproxy-ai/src/external_guardrail/mod.rs`
- Modify: `crates/sbproxy-ai/tests/external_guardrail_contract.rs`

**Interfaces:**
- Consumes: `CompiledGuardrailProvider`, `ExternalGuardrailRequest`, and the
  bounded dispatcher from Task 3.
- Produces:

```rust
fn lakera_request(config: &LakeraConfig, request: ExternalGuardrailRequest<'_>) -> Value;
fn parse_lakera(body: &Value) -> Result<GuardrailVerdict, GuardrailCallError>;
fn aporia_request(config: &AporiaConfig, request: ExternalGuardrailRequest<'_>) -> Value;
fn parse_aporia(body: &Value) -> Result<GuardrailVerdict, GuardrailCallError>;
```

- [ ] **Step 1: Add failing wire-contract tests**

For Lakera assert:

```text
POST /v2/guard
Authorization: Bearer fixture-key
{"messages":[{"role":"user","content":"fixture prompt"}],"breakdown":true}
```

Include `project_id` when configured. Parse top-level `flagged` and collect
detected `breakdown[].detector_type` values.

For Aporia assert:

```text
POST /fixture-project/validate
X-APORIA-API-KEY: fixture-key
{"messages":[{"role":"user","content":"fixture prompt"}],
 "validation_target":"prompt","explain":true}
```

For output phase, use `validation_target: "response"` and include `response`.
The tests must cover allow, block, malformed JSON, non-2xx, delay timeout, and
both fail modes through `check_external_guardrail`.

- [ ] **Step 2: Run the two provider tests and verify they fail**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-ai \
  -E 'test(lakera_) | test(aporia_)'
```

Expected: request or parser implementation missing.

- [ ] **Step 3: Implement the official contracts**

Use Lakera `/v2/guard` from <https://docs.lakera.ai/docs/api/guard>.
Use Aporia `https://gr-prd.aporia.com/<PROJECT_ID>/validate` from
<https://gr-docs.aporia.com/fundamentals/integration/rest-api>.
Provider modules return only strict normalized verdicts. They do not own
timeouts, redirects, response caps, or fail-mode decisions.

- [ ] **Step 4: Run and commit**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-ai \
  -E 'test(lakera_) | test(aporia_)'
```

Expected: all Lakera and Aporia contract cases pass.

```bash
git add crates/sbproxy-ai
git commit -m "feat(ai): connect Lakera and Aporia guardrails"
```

### Task 5: Add Azure Content Safety and Bedrock Guardrails

**Files:**
- Create: `crates/sbproxy-ai/src/external_guardrail/azure.rs`
- Create: `crates/sbproxy-ai/src/external_guardrail/bedrock.rs`
- Modify: `crates/sbproxy-ai/src/external_guardrail/mod.rs`
- Modify: `crates/sbproxy-ai/tests/external_guardrail_contract.rs`

**Interfaces:**
- Consumes: Task 3 provider dispatcher.
- Produces strict Azure severity and Bedrock action parsers.

- [ ] **Step 1: Add failing Azure and Bedrock contract tests**

Azure request:

```text
POST /contentsafety/text:analyze?api-version=2024-09-01
Ocp-Apim-Subscription-Key: fixture-key
{"text":"fixture prompt","outputType":"EightSeverityLevels"}
```

Assert a `categoriesAnalysis` entry at or above `severity_threshold` blocks,
and that a blocklist hit blocks. Validate threshold `0..=7`, default `4`.

Bedrock request:

```text
POST /guardrail/fixture-guardrail/version/1/apply
Authorization: Bearer fixture-key
{"source":"INPUT","content":[{"text":{"text":"fixture prompt"}}]}
```

Output phase sends `source: "OUTPUT"`. Assert `action: "GUARDRAIL_INTERVENED"`
blocks and `action: "NONE"` allows. Missing or unknown action is malformed.

- [ ] **Step 2: Run the provider tests and verify they fail**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-ai \
  -E 'test(azure_) | test(bedrock_guardrail_)'
```

Expected: provider modules absent.

- [ ] **Step 3: Implement current official request shapes**

Use Azure API version `2024-09-01` and integer severities documented at
<https://learn.microsoft.com/en-us/azure/ai-services/content-safety/quickstart-text>.
Use Bedrock `ApplyGuardrail` documented at
<https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-use-independent-api.html>.
Derive the Bedrock endpoint as
`https://bedrock-runtime.<region>.amazonaws.com` unless `url` overrides it for
testing.

- [ ] **Step 4: Run and commit**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-ai \
  -E 'test(azure_) | test(bedrock_guardrail_)'
git add crates/sbproxy-ai
git commit -m "feat(ai): add Azure and Bedrock guardrails"
```

Expected: every Azure and Bedrock allow, block, auth, phase, malformed,
timeout, and fail-mode case passes.

### Task 6: Add CrowdStrike AIDR and Pangea AI Guard

**Files:**
- Create: `crates/sbproxy-ai/src/external_guardrail/crowdstrike.rs`
- Create: `crates/sbproxy-ai/src/external_guardrail/pangea.rs`
- Modify: `crates/sbproxy-ai/src/external_guardrail/mod.rs`
- Modify: `crates/sbproxy-ai/tests/external_guardrail_contract.rs`

**Interfaces:**
- Consumes: Task 3 provider dispatcher.
- Produces strict `result.blocked` parsers with detector categories.

- [ ] **Step 1: Add failing CrowdStrike and Pangea contract tests**

CrowdStrike request:

```text
POST /aidr/aiguard/v1/guard_chat_completions
Authorization: Bearer fixture-key
{"guard_input":{"messages":[{"role":"user","content":"fixture prompt"}]}}
```

Include configured application metadata only under the vendor-documented
field. Assert `result.blocked` controls the verdict and detected result
categories are normalized.

Pangea request:

```text
POST /v1/text/guard
Authorization: Bearer fixture-key
{"text":"fixture prompt","recipe":"pangea_prompt_guard","debug":true}
```

Output phase selects `output_recipe`. Assert `result.blocked` controls the
verdict and `result.detectors` yields categories and analyzer confidence
scores.

- [ ] **Step 2: Run the provider tests and verify they fail**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-ai \
  -E 'test(crowdstrike_) | test(pangea_)'
```

Expected: provider modules absent.

- [ ] **Step 3: Implement current official request shapes**

Use CrowdStrike AIDR
`/aidr/aiguard/v1/guard_chat_completions` from
<https://aidr-docs.crowdstrike.com/docs/api/aidr>.
Use Pangea `/v1/text/guard` from
<https://pangea.cloud/docs/ai-guard/apis>.
Do not copy the historical `/ml-content-safety/v1/scan` or
`/v1beta/text/guard` contracts.

- [ ] **Step 4: Run and commit**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-ai \
  -E 'test(crowdstrike_) | test(pangea_)'
git add crates/sbproxy-ai
git commit -m "feat(ai): add CrowdStrike and Pangea guardrails"
```

Expected: every contract case passes.

### Task 7: Add Mistral moderation and Patronus evaluation

**Files:**
- Create: `crates/sbproxy-ai/src/external_guardrail/mistral.rs`
- Create: `crates/sbproxy-ai/src/external_guardrail/patronus.rs`
- Modify: `crates/sbproxy-ai/src/external_guardrail/mod.rs`
- Modify: `crates/sbproxy-ai/tests/external_guardrail_contract.rs`

**Interfaces:**
- Consumes: Task 3 provider dispatcher.
- Produces category-boolean or score-threshold Mistral verdicts and Patronus
  pass/fail verdicts.

- [ ] **Step 1: Add failing Mistral and Patronus contract tests**

Mistral request:

```text
POST /v1/moderations
Authorization: Bearer fixture-key
{"model":"mistral-moderation-2603","inputs":["fixture prompt"]}
```

Block when any `results[0].categories` value is true. If `score_threshold` is
configured, also block when any `category_scores` value meets or exceeds it.
Reject absent, empty, or mismatched result maps.

Patronus request for input:

```text
POST /v1/evaluate
X-API-KEY: fixture-key
{"evaluators":[{"evaluator":"prompt-injection"}],
 "evaluated_model_input":"fixture prompt"}
```

Output phase sends `evaluated_model_output`. Include `criteria` in the
evaluator object when configured. Block when any returned evaluation result
has `pass: false`; reject an empty result set.

- [ ] **Step 2: Run the provider tests and verify they fail**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-ai \
  -E 'test(mistral_) | test(patronus_)'
```

Expected: provider modules absent.

- [ ] **Step 3: Implement current official request shapes**

Use Mistral classifiers from
<https://docs.mistral.ai/api/endpoint/classifiers> and Patronus evaluation
from <https://docs.patronus.ai/docs/api_ref/evaluations/evaluate_v1_evaluate_post>.
Keep `mistral-moderation-2603` as the default model. Do not parse a top-level
Mistral `flagged` field because the current API does not return one.

- [ ] **Step 4: Run and commit**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-ai \
  -E 'test(mistral_) | test(patronus_)'
git add crates/sbproxy-ai
git commit -m "feat(ai): add Mistral and Patronus guardrails"
```

Expected: every contract case passes.

### Task 8: Resolve secrets and pass model context through the live proxy path

**Files:**
- Modify: `crates/sbproxy-modules/src/action/aiproxy.rs`
- Modify: `crates/sbproxy-core/src/server/ai_dispatch.rs`
- Modify: `crates/sbproxy-core/tests/ai_proxy.rs`
- Modify: `crates/sbproxy-ai/tests/external_guardrail_contract.rs`

**Interfaces:**
- Consumes: `credential_reference_mut`, `ExternalGuardrailRequest`.
- Produces:

```rust
pub async fn run_input_external_guardrails(
    configs: &[ExternalGuardrailConfig],
    content: &str,
    model: &str,
) -> Option<(String, String)>;

pub async fn run_output_external_guardrails(
    configs: &[ExternalGuardrailConfig],
    content: &str,
    model: &str,
) -> Option<(String, String)>;
```

- [ ] **Step 1: Add failing secret and proxy-path tests**

Install the test process resolver with `secret://fixture-guardrail` and assert
the constructed `AiProxyAction` contains the resolved value, while errors name
the guardrail but not the reference value.

Add one proxy test whose local guardrail server captures:

```json
{"model":"requested-model","phase":"input"}
```

through a generic webhook, blocks the request, and proves the upstream model
server was not called. Add one buffered output test that sees the selected
model and prevents a violating 200 response from being cached or sent.

- [ ] **Step 2: Run the focused tests and verify they fail**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-modules aiproxy
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core external_guardrail
```

Expected: unresolved external credential and missing model/phase assertions.

- [ ] **Step 3: Resolve guardrail credentials**

After provider key resolution, iterate through
`config.guardrails.external`. Resolve only the mutable value returned by
`credential_reference_mut()`. Wrap resolver errors as:

```text
resolving credential for external guardrail 'customer-policy': secret not found
```

Use the actual configured guardrail name and the resolver's safe error text.
Do not include the reference or resolved secret in that error.

- [ ] **Step 4: Pass model and phase through existing call sites**

At input, pass the model requested in the canonicalized body, defaulting to an
empty string. At buffered output, pass `ctx.ai_model` when available. Build
`ExternalGuardrailRequest` inside the shared runner so every provider receives
the same phase contract. The generic webhook body is:

```json
{"input":"fixture prompt","model":"requested-model","phase":"input"}
```

- [ ] **Step 5: Run and commit**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-modules aiproxy
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core external_guardrail
git add crates/sbproxy-modules crates/sbproxy-core crates/sbproxy-ai
git commit -m "feat(ai): wire vendor guardrails through the proxy"
```

Expected: secret-resolution and real proxy-path tests pass.

### Task 9: Generate the schema and add one tested operator example

**Files:**
- Create: `crates/sbproxy-ai/src/bin/generate-ai-external-guardrail-schema.rs`
- Create: `schemas/ai-external-guardrail.schema.json`
- Modify: `scripts/check-config-schema.sh`
- Create: `examples/ai-external-guardrails/sb.yml`
- Create: `examples/ai-external-guardrails/README.md`
- Create: `examples/ai-external-guardrails/smoke.json`
- Create: `examples/ai-external-guardrails/docker-compose.yml`
- Create: `examples/ai-external-guardrails/fixture.py`
- Modify: `docs/guardrails.md`
- Modify: `docs/README.md`
- Modify: `docs/llms.txt`
- Modify: `docs/llms-full.txt`

**Interfaces:**
- Consumes: The final `ExternalGuardrailConfig` and every adapter contract.
- Produces: A checked-in JSON Schema plus one credential-free generic-webhook
  walkthrough that can run against a deterministic local fixture.

- [ ] **Step 1: Add the schema generator and stale-schema check**

Generate `schema_for!(ExternalGuardrailConfig)` with title
`SBproxy AI external guardrail configuration`. Add this mapping:

```bash
"schemas/ai-external-guardrail.schema.json|-p sbproxy-ai --bin generate-ai-external-guardrail-schema"
```

Run:

```bash
bash scripts/check-config-schema.sh
```

Expected before generation: failure showing the new schema is missing or
stale.

- [ ] **Step 2: Create a deterministic generic-webhook example**

The example must contain:

```yaml
guardrails:
  external:
    - name: local-policy
      provider: generic
      url: http://127.0.0.1:18081/check
      allow_private_url: true
      mode: pre_call
      default_on: true
      fail_open: false
      timeout_ms: 500
```

`fixture.py` starts two bounded `ThreadingHTTPServer` instances. Port 18080
returns a deterministic OpenAI-compatible model response. Port 18081 returns
`{"allowed": false, "reason": "fixture policy"}` when the input contains
`blocked`, otherwise `{"allowed": true}`. It prints method, path, model, phase,
and verdict only.

`docker-compose.yml` starts that fixture and the locally built SBproxy image.
Its README explains every field, sends one allowed and one blocked prompt,
shows expected status and safe log fields, then gives cleanup commands.
`smoke.json` asserts a 200 response for `allowed prompt` and a 400
`guardrail_violation` for `blocked prompt`. Hosted provider fragments use
`${NAME}` or `secret://name`, never live keys.

- [ ] **Step 3: Rewrite the guardrail reference around the real pipeline**

Document built-in versus external checks, input/output/logging modes,
`default_on`, timeout and failure policy, private URL opt-in, secret
references, response cap, generic webhook response contract, provider field
tables, and troubleshooting. State clearly that Prompt Security and Model
Armor are not named adapters. Link provider claims to the official references
used in Tasks 4 through 7.

- [ ] **Step 4: Generate and validate**

Run:

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo run --locked -p sbproxy-ai --bin generate-ai-external-guardrail-schema \
  > schemas/ai-external-guardrail.schema.json
bash scripts/check-config-schema.sh
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-config --test validate_examples
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core --test construct_examples
bash scripts/regen-llms-full.sh
bash scripts/docs-ci.sh
```

Expected: schema is current, all example configs compile, examples construct,
generated indexes are current, and docs checks pass.

- [ ] **Step 5: Commit the reference and example**

```bash
git add crates/sbproxy-ai/src/bin schemas scripts examples/ai-external-guardrails \
  docs/guardrails.md docs/README.md docs/llms.txt docs/llms-full.txt
git commit -m "docs: add connected guardrail walkthrough"
```

### Task 10: Run the selective pull request gate

**Files:**
- Modify only files required by failures caused by this pull request.

**Interfaces:**
- Consumes: Tasks 1 through 9.
- Produces: A formatted, linted, focused-test-clean branch ready for review.

- [ ] **Step 1: Format and check the diff**

```bash
cargo fmt --all -- --check
git diff --check
```

Expected: both commands exit zero.

- [ ] **Step 2: Run targeted Clippy**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo clippy --locked -p sbproxy-httpkit -p sbproxy-ai \
  -p sbproxy-modules -p sbproxy-core --all-targets -- -D warnings
```

Expected: exit zero with no warnings.

- [ ] **Step 3: Run affected tests once**

```bash
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-httpkit
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-ai external_guardrail
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-modules aiproxy
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core \
  -E 'test(external_guardrail) | test(hooks) | test(hook_registry) | test(lifecycle)'
bash scripts/check-config-schema.sh
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-config --test validate_examples
CARGO_TARGET_DIR=/Users/rick/projects/soapbucket/sbproxy/target \
  cargo nextest run --locked -p sbproxy-core --test construct_examples
bash scripts/docs-ci.sh
```

Expected: every command exits zero. Do not run the whole workspace test suite
unless CI or a focused failure shows the change crosses a wider boundary.

- [ ] **Step 4: Scan the final diff for product and credential regressions**

```bash
rg -n 'EnterpriseStartupHook|EnterpriseHook|enterprise_hook|enterprise-only|sbproxy-rust|sbproxy\.dev/enterprise|sbproxy-enterprise' \
  README.md BENCHMARK.md MIGRATION.md SECURITY.md SUPPLY-CHAIN.md AGENTS.md CLAUDE.md \
  bench-synthetic docs scripts crates \
  --glob '!CHANGELOG.md' \
  --glob '!docs/superpowers/**'
rg -n '(sk-|api[_-]?key: +[^$<{]|Bearer +[A-Za-z0-9_-]{16,})' \
  examples/ai-external-guardrails docs/guardrails.md
```

Expected: no current product-split hit and no credential-shaped example value.

- [ ] **Step 5: Commit any gate-only fixes**

If the gate required changes:

```bash
git add crates/sbproxy-ai/src/external_guardrail/mod.rs
git commit -m "fix: close guardrail review gaps"
```

Replace the sample path with the exact files changed by the gate. If no
changes were needed, do not create an empty commit.
