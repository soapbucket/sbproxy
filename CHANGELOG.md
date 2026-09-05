# Changelog

All notable changes to SBproxy v1.x. Versions before v1.0 shipped as the
Go implementation and now live in the archived
[`soapbucket/sbproxy-go`](https://github.com/soapbucket/sbproxy-go)
repository.

## [Unreleased]

Entries for the next version cut are not written here. Each one is a
separate file under [`docs/.changes/`](docs/.changes/), so two branches
landing the same night produce two files instead of one conflict.

Render what the next release will say with
`python3 scripts/changelog-fragments.py --preview`.

## [1.14.0] - 2026-09-05

### Breaking

- **Two outbound paths that ignored their `egress:` allowlist now honor
  it.** No key changed and the same file still compiles; what changed is
  that the value you already wrote is enforced where it previously was
  not.

  If `egress.usage_sinks` is set to `mode: deny_by_default` and you run
  an `events:` webhook sink, add your collector's host to
  `egress.usage_sinks.hosts` before upgrading. `ports` defaults to `[80,
  443]`, so a collector on another port needs an explicit `ports:`, and
  one that resolves onto a private address needs `allow_private: true`.
  Until you do, every batch is refused: a `warn` on the `events` target,
  one
  `sbproxy_events_dropped_total{sink="webhook",reason="egress_denied"}`
  per event, and a `denied` row in `GET /api/egress`.

  If `egress.token_exchange` is set to `mode: deny_by_default` and an
  MCP server uses `run_as_user_auth` with the token-exchange mode, add
  that token endpoint's host to `egress.token_exchange.hosts`. A
  per-server `egress:` block does not cover it. Until you do, the tool
  call fails with `token exchange egress denied`.

  Read the current hosts off `GET /api/egress` on the running proxy: the
  `webhook` and `token_exchange` rows name exactly what has to be
  listed. See
  [config-stability.md](../config-stability.md#upgrade-affecting-behavior-changes).

- **An unreadable MCP `tool_quotas[].rate.per` is refused at config
  load.** A `per:` value outside `ms / s / m / h / d` was never
  validated anywhere: `per: 1hour` compiled clean, `sbproxy validate`
  accepted it, and the request path then read the parse failure as "this
  tool has no quota" and let every `tools/call` through with no log line
  and no counter, so the dashboard showed the quota configured and zero
  rejections. The `mcp` action now refuses the config naming the policy,
  the tool, and the string, so a config carrying a typo stops loading
  rather than loading a quota nothing enforces; the request-path branch
  survives as a backstop and denies instead of allowing. Grep your
  configs for `per:` under `tool_quotas` before upgrading, starting with
  any quota that has never rejected anything. See
  [docs/config-stability.md](docs/config-stability.md) and
  [docs/mcp.md](docs/mcp.md).

- **A relative `model_host.cache.directory` is refused at config load.**
  The engine subprocess that reads the weight cache is launched with its
  own working directory and requires an absolute snapshot path, so a
  relative value was accepted by `validate` and `models pull`, survived
  a complete multi-gigabyte download, and then failed at engine launch
  with `artifact_not_ready: verified snapshot path must be absolute`,
  naming a field the operator never wrote.
  `proxy.model_host.cache.directory`, the compatibility
  `serve.cache_dir`, and the `--cache-dir` flag now each refuse a
  relative path by name before anything is downloaded. Point the key at
  an absolute path, or interpolate a variable with an absolute `:-`
  default, such as `${SB_MODEL_CACHE_DIR:-/var/lib/sbproxy/models}`,
  when the location differs per host. `catalog_file` is unchanged and
  still resolves relative paths against the config directory.

- The S3 Cache Reserve backend refuses to read an object written before
  this release. Its envelope now binds the ciphertext to a versioned
  canonical AAD covering bucket, prefix, logical key, object key, and
  stored metadata, so a moved or renamed object cannot be decrypted in
  its new place. Objects carrying the previous AAD fail closed with an
  explicit rewrite-required error rather than being silently accepted;
  drop the prefix and let it refill.

- **A mesh node that exits cleanly now announces `Left` to a fan-out of
  live peers.** That is a wire break: every node in the cluster must
  understand the new membership state, so rolling this out means
  upgrading the whole cluster together. A peer that received the
  announcement is evicted under
  `mesh_peer_evicted_total{reason="graceful_leave"}` instead of waiting
  out the suspect window and `dead_timeout`. `dead_peer_gc_secs` still
  GCs the routing membership after that, and the admin roster keeps its
  bounded tombstone.

- **Go compatibility is deprecated: a flat schema-v1 `sb.yml` is now
  refused instead of booting an empty proxy.** The archived Go `v0.1.x`
  line wrote one origin's behavior at the top level of the file. This
  binary reads origin behavior only from `origins.<hostname>:` and never
  translated the flat shape into it, so such a file used to compile:
  each top-level key was dropped with a single warning, the proxy booted
  with no origin at all and answered 404 for the hostname the file
  declared, and `sbproxy validate` reported the same file as valid. An
  operator who believed they had authentication and IP allow-listing
  deployed with neither. `serve`, `validate`, and hot reload now fail
  when a top-level key carries origin behavior (`hostname`, `action`,
  `authentication`, `policies`, `forward_rules`, `cors`,
  `request_modifiers`, `response_modifiers`, `session`, `variables`,
  `allowed_methods`, `force_ssl`, `ai_proxy`), with a message naming the
  keys it would have dropped and pointing at
  [`soapbucket/sbproxy-go`](https://github.com/soapbucket/sbproxy-go)
  for anyone who would rather keep running the Go binary, which is
  maintenance only. Descriptive top-level leftovers (`config_version`,
  `id`, `workspace_id`, `version`, `environment`, `tags`, `debug`) are
  unaffected and still only warn, so a modern config carrying one keeps
  booting. There is no translation shim and there will not be one; the
  rewrite is one nesting level and is shown side by side in
  [MIGRATION.md](MIGRATION.md).

### Security

- **`hmac_auth` now binds a signature to the body it covers.** A
  signature covering `content-digest` was checked against the empty body
  the authentication phase can offer, not against the bytes the client
  sent. The check was inverted rather than weak: a client sending the
  true digest of its body was refused, while one declaring the
  empty-body digest
  `sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:` was admitted
  and could then send any body at all. Because covering `content-digest`
  could not work, deployments signed `("@method" "@target-uri")` and
  nothing else, so a request captured off the wire replayed with an
  attacker-chosen body until its `created` timestamp left the
  `clock_skew_seconds` window. An attacker could not forge a signature,
  change the method or the route, or extend the window; they substituted
  the body of a request someone else signed.

  Verification now defers the digest half to the request body filter and
  completes it against the complete pre-transform body, the same
  two-step contract `bot_auth` uses, answering `401` on a mismatch.
  Covering `content-digest` works, so `required_components` can require
  it and mean it. Two consequences worth knowing before you upgrade: a
  body-covering signature now caps the request at the 8 MiB request-body
  buffer and a larger body answers `413`, and the `401` body for a
  mismatch changed from `bot_auth: content-digest body mismatch` to
  `signature: content-digest body mismatch`, since either provider can
  raise it. See the `hmac_auth` section of
  [docs/configuration.md](docs/configuration.md).

- **`ldap_auth` bounds what it dials.** Authentication runs before an
  origin's `policies:`, so no `rate_limit` or `ddos` policy could cap
  the directory bind: anyone able to send an `Authorization: Basic`
  header drove one bind per request, which made the gateway a 1:1
  amplifier pointed at the directory and offered account lockout for any
  guessable username. Three bounds now run before the dial, none of
  which caches a success: a 30 second refused-credential cache keyed on
  a salted SHA-256 of the exact username and password, a per-username
  failed-bind budget of 5 per 60 seconds that then throttles to one bind
  per 12 seconds, and a cap of 32 binds in flight. The budget throttles
  rather than blocks on purpose, so nobody can spend a username's budget
  with wrong guesses and lock its owner out; a throttled request answers
  `503`, not `401`, because the directory was never consulted. An
  attacker cycling *distinct* usernames is still bounded only by what
  runs in front of the origin.

- **Refused LDAP binds and refused JWE algorithms are visible in release
  builds.** Both logged at `debug`, which the release profile's
  `release_max_level_info` compiles out, so the shipped binary recorded
  nothing for a refused credential while the documentation promised the
  log named the offending algorithm. Raised to `info`. A failed
  `content-digest` body binding now logs at `warn` at all three refusal
  sites; it previously logged at `debug` in one and nowhere in the other
  two. No credential is logged at any of them.

- A `policy: rego` or `ai_routing_policy` base-data document that lands
  on any rule the module defines is now refused at config load, not just
  one that lands on the rule the query names. Rego resolves base data
  over a rule at the same path, so a table that collided with a helper
  several references from the query turned that helper into a constant:
  the query kept evaluating, the decision kept looking computed, and a
  `deny` rule that stopped running failed open with nothing in the logs
  to say so. The refusal names the data path, the rule it landed on, and
  the reference chain from the query to that rule: ``base data defines
  `data.sbproxy.trusted`, and the module defines a rule at that path, so
  Rego resolves the base document there and the rule never evaluates.
  The query `data.sbproxy.allow` reaches it: data.sbproxy.allow ->
  data.sbproxy.trusted.`` A JSON `null` at a rule path and a scalar
  above one refuse for the same reason, and a query that reads a parent
  path (`data.sbproxy.denies` over a `denies[k]` rule) now resolves to
  the rules beneath it, so the chain is printed instead of the collision
  being reported as latent. A partial rule whose keys are computed
  (`limits[k] := ...`) is comparable only down to the fixed part of its
  path, so any key already sitting under that path refuses, including
  keys the rule would never have produced; an empty object there still
  loads, and the message for this shape says the base keys win rather
  than claiming the rule never evaluates. Every base-data refusal now
  counts on
  `sbproxy_script_compile_total{engine="rego",result="semantic_error"}`,
  the same family the parse and analysis outcomes use. This is
  upgrade-affecting: a config that compiled before can refuse now, and
  the fix is to move the table off the rule path. Sibling keys inside
  the package and top-level keys are unaffected.

- **A query parameter can no longer overwrite a gRPC transcode path
  binding.** `GET /v1/echo/allowed?message=forbidden` bound `message`
  from the path and then let the query replace it, so the value the
  route matched on and the header-phase policies read was not the value
  the gRPC upstream received. A query key addressing a bound field path,
  or a parent or a child of one, is now dropped. Two caps come with it:
  at most 256 query parameters per request, and at most 32 dotted
  segments in a parameter name, which bounds a recursion that a
  self-referential message type could otherwise drive into the worker
  stack. A client that was correcting a path segment from the query has
  to send the corrected value in the path instead.

- **A saturated metric label warns once, and never logs the demoted
  value.** When a label reached its cardinality budget, every subsequent
  unseen value emitted a `WARN` line carrying that value, and the
  accepted-value set never shrinks, so the flood was permanent.
  `project`, `feature`, `team`, `environment`, and `agent_type` arrive
  on `SB-Attr-*` request headers with nothing upstream bounding them, so
  one client sending a distinct value per request could drive one log
  line per request, each carrying a string it chose. The proxy now
  announces a label's saturation once per label per process and names
  only the label. The saturation itself stays scrapeable for as long as
  it lasts on `sbproxy_label_cardinality_unique_values{label}` against
  `sbproxy_label_cardinality_budget{label}`, which are recomputed at
  scrape from the limiter's own accepted-value map and so cover every
  proxy-wide label; `sbproxy_label_cardinality_overflow_total{metric,
  label}` counts each individual demotion, but only for the labels
  routed through the per-label-budget path, so alert on the gauge ratio
  rather than on that counter. The announcement is also emitted after
  the limiter's lock is released rather than while holding it. What this
  does not distinguish: a tenant-scoped saturation is announced under
  its label name alone, so the first tenant to fill a label mutes the
  line for the rest;
  `sbproxy_label_cardinality_overflow_per_tenant_total{metric, label,
  tenant_id}` carries the tenant dimension.

- **Every configurable built-in auth provider now refuses a
  configuration key it does not recognize.** Until this release an
  unrecognized key inside an `authentication:` block was dropped
  silently and the setting it was meant to be took its default, and
  every optional switch on an auth provider defaults to the permissive
  value. `require_dp0p: true` on a `bearer` block, with a zero for the
  `o`, compiled, booted, and served every request with DPoP
  proof-of-possession off while the config read as though it were on.
  The same held for `require_mtls_bound` on `jwt`, `tls_verify` on
  `ldap_auth`, `require_agent_binding` on `cap`, `nonce_policy` on
  `bot_auth`, and `clock_skew_seconds` on `hmac_auth`.

  This is upgrade-affecting: a configuration that carried a stray key
  inside an `authentication:` block used to boot and now fails to
  compile, at `serve`, `validate`, and hot reload alike, with an error
  naming the key and the ones the provider accepts (``unknown field
  `require_dp0p`, expected `tokens` or `require_dpop` ``). Run `sbproxy
  validate <path>` before rolling. Any key it names is one the proxy was
  already ignoring, so correcting the spelling gives you the control the
  file claimed and deleting the line gives you the behavior you were
  already running. A rejected hot reload leaves the last-good
  configuration serving.

  `noop` has no configuration to check and is unchanged, and the
  per-credential entries under `api_keys:`, `tokens:`, `users:`, and
  `hmac_auth`'s `keys:` stay permissive because they fold free-form
  attribution metadata into the same mapping as the secret.
  `proxy.extensions.agent_detect` also refuses unknown keys now, and a
  malformed block that sets `enabled: true` is a hard compile error
  rather than a warning that left the scorer off; an absent block still
  means detection off with nothing logged.

- **A validate-only bundle load no longer un-redacts the serving
  config's secrets.** `Candidate::finish` installed the process-wide
  structured-log field-key denylist at candidate-construction time, so
  every load that is not an adoption reprogrammed the redactor for the
  generation still serving: a `/config/publish` dry run carrying no
  `extensions:` block, a doctor run, or any
  `CompiledPipeline::from_config` (which loads an empty registry)
  replaced the live list with its own, and from that moment the serving
  config emitted its bundles' `secret_vars` in cleartext in every
  structured log line. The registry now carries its names and the single
  pipeline publisher installs them, so the denylist moves only when the
  pipeline that owns it does.

- **A shared certificate-store backend that cannot be opened now refuses
  to start instead of silently disabling the fleet-wide ACME issuance
  lock.** Every failure path in the certificate-store open (`redb` and
  `sqlite` directory creation, `redb`, `sqlite`, `file`, and
  object-store opens, and a rejected Redis DSN) logged one `warn`
  reading "certs will NOT persist (in-memory fallback)" and handed back
  a `MemoryKVStore`. Persistence was the smaller half of what that cost:
  `MemoryKVStore` overrides neither `try_lock` nor `renew_lock`, so it
  inherits the single-node trait defaults, both an unconditional
  `Ok(true)`. Every replica therefore won its own issuance lease and its
  own fencing generation, opened its own ACME order for the same
  hostname, and published its HTTP-01 token to a store no peer could
  read, so roughly two thirds of the CA's validation fetches landed on a
  replica that had never seen the token and the account burned through
  Let's Encrypt's limit of five duplicate certificates per hostname set
  per week. Nothing in `/metrics` told that apart from a CA outage, and
  the operator's multi-replica guard could not catch it either, because
  the configured backend was a shared one and it was the open that
  failed. A failure on `file`, `redis`, `s3`, `gcs`, or `azure` is now a
  startup error naming the backend, with no part of `storage_path` in
  the message since a DSN or bucket URL can carry credentials. A
  pod-local backend (`redb`, `sqlite`, `memory`) still degrades, because
  a single node has no peer to be excluded from, but loudly: the log is
  at `error` and the new `sbproxy_cert_store_degraded{backend}` gauge
  goes to 1, and reads 0 when the configured backend opened. See the
  certificate-store-backends section of
  [docs/configuration.md](docs/configuration.md) and the upgrade note in
  [docs/config-stability.md](docs/config-stability.md).

- **The classifier sidecar bounds every inference it runs.** `Classify`
  and `Embed` accepted caller-supplied text and handed it straight to
  `spawn_blocking` with no size check, no batch-size check, no admission
  permit, and no deadline. Only `Compress` was bounded. An unbounded
  `spawn_blocking` is a thread-pool exhaustion primitive: the blocking
  pool has a fixed ceiling and every task queued past it stalls every
  other blocking caller in the process, so a single caller could park
  the sidecar with either a stream of large requests or one batch of a
  million texts.

  All three RPCs now check the encoded request size before the model is
  resolved, take a running permit from their own semaphores, and run
  under a deadline that starts when the request arrives, so it covers
  the wait for a running slot as well as the inference. A refused
  request answers `RESOURCE_EXHAUSTED`, a request past the deadline
  answers `DEADLINE_EXCEEDED`, and a panic inside inference is contained
  by the runtime and answers `INTERNAL` without echoing the panic
  payload, which is derived from the caller's own text. Every refusal
  increments a per-reason counter and logs the first of each reason plus
  every hundredth after that, so a refusal storm cannot become a log
  flood.

  **This is upgrade-affecting: a sidecar that answered every concurrent
  `Classify` and `Embed` its hardware could run will now shed load above
  its ceiling, and you widen that ceiling with
  `--inference-max-concurrent` and `--inference-max-queued`.** The
  ceiling is not a fixed number. Concurrency defaults to the host's
  available parallelism, held between 4 and 64, and queue depth to eight
  slots per running slot, so the sidecar tracks what the machine can
  actually do instead of a literal chosen on somebody else's box. On the
  proxy side a shed request is a failed call: the `prompt_injection_v2`
  sidecar detector gives up after 250 ms and takes its `failure_posture`
  path, the same as for a sidecar that is down, so size the flags for
  peak concurrent inferences and not for average load.

  The other defaults apply whether or not you configure anything:
  `Classify` and `Embed` cap one request at 1 MiB encoded, an `Embed`
  batch at 64 texts, and any request at 30 seconds end to end. Widen
  them with `--inference-max-request-bytes`, `--inference-max-items`,
  and `--inference-timeout-ms`. When the proxy supervises the sidecar
  itself, `SupervisorConfig` now carries all five as optional overrides
  and passes each one it is given to the child. See
  [docs/classifier-sidecar.md](docs/classifier-sidecar.md) for the full
  table and the status each bound returns.

- **The MCP concealed-text detector now flags variation selectors.**
  `U+FE00` to `U+FE0F` and `U+E0100` to `U+E01EF` are 256 invisible,
  non-control code points wide enough to carry a byte each, and they are
  the channel current tool-metadata smuggling work uses. A federated
  tool description carrying a payload encoded in them produced no
  finding, no change record, and `strip_concealed` handed the smuggled
  bytes back unchanged. They are reported now under a new
  `variation_selector` class on
  `sbproxy_mcp_concealed_text_findings_total{class}`, alongside newly
  covered invisible format characters (`U+00AD`, `U+180E`,
  `U+2061`-`U+2064`, `U+FFF9`-`U+FFFB`) under `zero_width`. This class
  has expected false positives: `U+FE0F` is the emoji presentation
  selector and `U+E0100` onward is the Ideographic Variation Sequence
  range legitimate Japanese and Chinese text uses, so a description
  ending in an emoji or written in CJK is reported. That is deliberate,
  because the code point a script needs and the code point a payload
  rides on are the same code point, and the separate class label is what
  lets an operator baseline the noise and tell the findings apart. See
  [docs/mcp.md](docs/mcp.md).

- **Two linked crates claiming the same auth plugin name are refused
  instead of resolved by link order.** `build_auth_plugin` took the
  first registration that matched, so a binary linking two crates that
  both register `saml` authenticated origins with whichever one the
  linker happened to emit first, and no config, log line, or admin
  surface said which. It now behaves like the policy, transform, and
  action channels it sits beside: the config compiler fails the load
  with `duplicate auth plugin registration: <name>`, naming how many
  claims there are, and no factory runs. Which crates they came from is
  a question for the binary's dependency graph, since a registration
  carries a name and a function pointer and nothing else. This is
  reachable only in a fork or an embedding that links its own auth
  providers; the shipped binary registers none.

- **Durable sinks now create their files owner-only (`0o600`).** The
  signed usage ledger, the settlement database and its `-wal` and `-shm`
  sidecars, the request event file, the session ledger, and the JSONL
  usage feed were all opened with a bare `OpenOptions`, which asks for
  `0o666` and lets the umask decide. Under the near-universal default of
  `0o022` every one of them landed on disk as `0o644`, readable by every
  account on the host: per-tenant token counts and the amounts they
  price, payer identifiers, and the route, identity, and decision for
  every call the proxy served. Directories this process creates for its
  own state, currently the parent of `payments.state_path`, are now
  `0o700` for the same reason; a `0o600` file inside a world-traversable
  directory still discloses its name, its size, and its existence. Read
  this before you upgrade if anything outside the proxy reads those
  files. A log shipper, a backup job, or a metrics scraper running as a
  different user loses access the first time the sink opens its file,
  because a file that already exists at a looser mode is tightened
  rather than inherited. Run those readers as the proxy user, add them
  to a setup that grants access explicitly, or point the sink at a fifo
  or `/dev/stdout`, which are left exactly as the operator configured
  them. A directory that already exists keeps the mode it has, so a
  shared parent such as `/var/log` is never narrowed.

- The `events:` webhook sink no longer follows redirects. Its dial is
  pinned to the addresses the SSRF guard resolved, the collector is
  authorized against `egress.usage_sinks` when that block is armed, a
  `3xx` `Location` at another origin is refused rather than handed the
  signed event batch, and the five-second timeout now covers the whole
  chain rather than restarting on every hop. A refused batch counts
  under
  `sbproxy_events_dropped_total{sink="webhook",reason="egress_denied"}`
  and shows as a `denied` row in `GET /api/egress`.

- **The `html` transform's `rewrite_attributes` now reads a tag's
  attribute list instead of pattern-matching the tag text.** It found
  the attribute with a regex over the whole opening tag, and that got
  two cases wrong. A tag carrying the attribute unquoted, which HTML
  minifiers emit routinely (`<a target=_self>`), did not match, so the
  transform appended a second copy; an HTML parser keeps the first of a
  duplicated attribute, so the rewrite silently did nothing to exactly
  the tags it reported stamping. Worse, the same characters inside
  another attribute's *value* did match: upstream content of the shape
  `<a title="pick target='b' onmouseover=x">` came back as `<a
  title="pick target="_blank" onmouseover=x">`, closing the title early
  and promoting the rest of an upstream-controlled string to real
  attributes, event handlers included.

  Both are fixed by walking the tag's attributes and only ever rewriting
  something parsed as a value. If you configure `rewrite_attributes`
  against an upstream that reflects user content into attribute values,
  this closes an injection path that needed no cooperation from the
  operator's config beyond having the transform enabled. Two visible
  changes to expect: a tag whose value was unquoted now comes back
  quoted and rewritten rather than duplicated, and text inside another
  attribute's value is left exactly as the upstream sent it.

- **Redis-backed idempotency entries are namespaced per origin.**
  `idempotency.backend: redis` wraps the one cluster-wide
  `proxy.l2_store`, and its storage key was
  `sbproxy:idem::<Idempotency-Key>`: the workspace segment it was
  supposed to be scoped by is a field nothing in the tree ever assigns,
  so every origin on every node shared one flat keyspace. A client
  posting `Idempotency-Key: order-1234` to one origin could be served
  another origin's cached response verbatim, or park a permanent 409 on
  a key it did not own, for the full 24h TTL. Keys now carry the owning
  origin's `tenant_id` and origin id, and every segment is
  length-delimited so a colon inside an operator-supplied id or a
  caller-supplied key cannot straddle a separator. The `memory` backend
  was never affected, which is why no test saw this. Entries written
  under the old key are not readable under the new one, so plan the
  upgrade the way [docs/config-stability.md](docs/config-stability.md)
  describes: a retry that spans the restart re-executes upstream once.
  The three idempotency metrics also stop labeling everything
  `backend="default"`: the label is now `memory` or `kv`, so a broken
  shared store is distinguishable from a cold local cache, and a
  store-side read or write failure counts a new `result="error"`
  alongside the miss the read degrades into, so an unreachable store
  reads as a fault rather than as cold traffic.

- **A keystore cache invalidation that does not propagate is now
  reported instead of dropped.** `CacheTier::invalidate` and
  `TtlCache::invalidate` returned `()`, folding a failed revocation into
  the same best-effort bucket as a failed lookup. A failed lookup is a
  cache miss the store covers for; a failed revocation is a credential
  every other replica keeps accepting for a full cache TTL while the
  admin console reports it revoked, with nothing in the logs, metrics,
  or events saying so. Both now return `Result`. A key mutation whose
  invalidation did not reach the shared tier still returns 2xx, because
  the store write did land, but the body carries a `cache_propagation`
  object naming the failure and its effect. `POST
  /admin/cache/key-policy/evict` returns 502 instead, because
  propagating is the whole operation there. Both paths log a warning and
  increment the new
  `sbproxy_key_cache_invalidation_failures_total{scope}` counter, so a
  revoke that did not land is alertable.

- **`allow_patterns: false` now also disables `string.gsub`.** The Lua
  sandbox gate stubbed `string.find`, `string.match`, and
  `string.gmatch` and left `string.gsub` live, so the knob whose stated
  purpose is containing catastrophic backtracking left the same C-level
  matcher reachable. `max_execution_ms` cannot help there either: the
  matcher runs inside Luau's C string library, where the interrupt the
  timer relies on never fires, so one request pinned a worker thread
  indefinitely. All four pattern functions are stubbed now, which is the
  complete pattern-taking surface of the `string` table. See
  [docs/scripting.md](docs/scripting.md) and
  [docs/config-stability.md](docs/config-stability.md).

- The MCP run-as-user token cache mixes tenant, scope, and client
  credential reference into its key, so two federated servers that
  differ only in `scope`, or one inbound token arriving at two tenants'
  origins, no longer share a cached credential. The cache is bounded at
  4096 entries with LRU eviction, drops expired entries rather than
  stepping over them, and zeroizes evicted bearer values.

- The MCP run-as-user token exchange keeps the pin set its egress
  authorization resolved and dials only those addresses, so a DNS answer
  that changes between the check and the connect no longer moves the
  request. A cross-origin redirect is refused instead of replaying the
  form body carrying the caller subject token, the token response is
  read under a 64 KiB ceiling, and the exchange is now armed by the
  top-level `egress.token_exchange` block, which the only production
  call site previously bypassed.

- **The MCP tool-quota counter map is bounded per tenant and per
  process.** The sliding-window store was keyed on the caller-presented
  principal id and never evicted, so every distinct `sub` that called a
  quota'd tool once left a permanent entry and an attacker able to mint
  subs drove the footprint deliberately. Aged-out windows are reclaimed
  now, and two ceilings bound what is left: 10,000 live windows per
  tenant and 100,000 across the process. A principal the store cannot
  track is refused rather than admitted unmetered, and the per-tenant
  ceiling is what keeps one tenant's flood from refusing every other
  tenant's next unseen caller. Because that refusal looks identical to a
  real quota rejection on the wire, it has its own counter,
  `sbproxy_mcp_tool_quota_registry_saturated_total`; alert on it. See
  [docs/mcp.md](docs/mcp.md).

- **Mesh node-to-node RPC has network deadlines and inbound connection
  admission.** The cross-node cache transport had neither. A peer could
  open a socket on the mesh transport port and then stop reading, or
  accept a connection and never answer, and the task serving it waited
  forever; enough such peers occupied every task there was, and nothing
  on the calling side bounded a routed cache read either. Both halves
  are now bounded. Outbound: connect 3s, peer mTLS 5s, request write
  10s, response 10s (60s for the scanning operations: prefix purge,
  digest, snapshot), all clamped by one overall per-request budget of
  15s (90s for a scan) fixed before the per-peer lock is taken, so the
  phases cannot add up past it. Inbound: at most 1024 connections and 64
  concurrent TLS handshakes, a 10s deadline covering the handshake and
  the wait for a handshake slot, a five-minute idle reaper, a 30s
  deadline on delivering a frame body once its length has been
  announced, and a 30s deadline on draining a response. Refused and
  reaped connections count on the new
  `mesh_transport_inbound_rejected_total{reason}`, and client-side
  deadlines land on `mesh_transport_rpc_errors_total` under five new
  `timeout_` kinds. Alert on `reason!="idle_timeout"`: a link nobody
  uses for a whole idle window is reclaimed as a matter of course on a
  quiet cluster, so that one value moves on a healthy fleet and logs at
  `debug` rather than `warn`. Neither set is configurable: each default
  is sized against mesh behavior at its constant, and see the mesh
  transport limits table in
  [docs/key-management.md](docs/key-management.md).

  Upgrade-affecting on one axis. A node running an older build that
  holds a mesh transport connection idle for more than the five-minute
  inbound idle window now has it closed by the upgraded peer and loses
  that one RPC to the reconnect. Nodes on this build reach the reaper
  too on a link nobody uses, but they re-check their own 60-second
  recycle mark before every request, so their next call after such a gap
  dials fresh instead of writing into a closed socket and costs a
  handshake rather than an RPC. The exposure is the mixed-version window
  during a rolling restart.

- **Two operator replicas can no longer both win the leader Lease, and a
  deposed leader is fenced before a successor may act.** Takeover of an
  expired `sbproxy-operator-leader` Lease was a plain merge PATCH with
  no `resourceVersion` in the body, so the holder check that preceded it
  constrained nothing at the apiserver: two standbys reading the same
  stale Lease within a few milliseconds both wrote themselves in, both
  reported acquired, and both began reconciling the same `SBProxy` set.
  Creation now uses POST and takeover uses a
  `resourceVersion`-conditional replace, so exactly one candidate wins
  and the loser gets a 409 and keeps polling. Separately, the renew loop
  stepped down on the first transient apiserver error, turning a single
  500 during an apiserver rollout into a pod restart and 15s of no
  reconciliation; renewals are now retried until an absolute safety
  deadline of 10s measured from the start of the last successful
  renewal. That deadline is enforced from inside the wait rather than
  checked after it, so an apiserver that hangs instead of erroring still
  fences at 10s rather than at the old 15s, which was exactly the lease
  duration and therefore the instant a standby's takeover became legal
  rather than any time before it. Losing leadership now closes a write
  gate that the reconcile path checks before every status patch, every
  server-side apply, and every `/admin/reload` fan-out, because aborting
  the controller task only takes effect at its next await point and does
  not recall a request already dispatched. A refused pass is counted as
  `sbproxy_operator_reconcile_total{result="fenced"}`. See the
  leader-election section of [docs/kubernetes.md](docs/kubernetes.md).

- Operator URLs no longer reach log lines or error strings in full.
  Redis and object-store DSNs, alert and callback webhook targets, JWKS
  endpoints, usage sink collectors, and WAF feed URLs are now rendered
  with only their scheme, host, and port (plus a Redis DSN's database index), so
  an inline password or a webhook secret in the path cannot land in the
  process log. `reqwest` failures are summarized by failure class
  instead of interpolated directly, since that error's own `Display`
  prints the whole request URL, and the same stripped error is what gets
  wrapped rather than only what gets logged. A new ratchet,
  `scripts/check-log-url-ratchet.sh`, refuses new sites of either shape;
  its header states what its detector can and cannot see.

- **Proxy-Wasm `proxy_log` is bounded, sanitized, and level-clamped.** A
  guest capped one message at 4 KiB and nothing else, so a filter
  looping `proxy_log` inside `proxy_on_http_request_headers` turned a
  single request into thousands of records at whatever level it chose,
  including `error`. The message bytes were also emitted verbatim, so a
  payload containing a newline forged a whole log line no part of the
  proxy wrote. Guest output is now capped at 1 MiB per callback (dropped
  past the cap, with one `warn` saying so and no backpressure signal to
  the guest), split one record per line with control characters escaped,
  and emitted at a host-chosen level: trace and debug at `debug`, info
  at `info`, and warn, error, and critical all at `warn`. The guest's
  requested level stays on the record as `log_level`. A guest can no
  longer mint an `error` line in its host's log. See
  [docs/extension-bundles.md](docs/extension-bundles.md).

- **Response cache keys no longer let one request seed another's entry,
  and no longer let one caller read another's.** Key fields were joined
  with a raw `:` and nothing escaped the fields themselves, so a colon
  in a path or a query moved the boundary: `GET /victim:foo?bar` and
  `GET /victim?foo:bar` rendered one key, and the `POST` invalidation
  prefix for `/victim` was a string prefix of every `/victim:foo` key,
  purging paths the caller never named. Fields are now percent-escaped
  and the key carries a `v2:` version tag. Separately, nothing about the
  caller was in the key at all, so an origin running `authentication`
  and `response_cache` together stored the first caller's `GET /me` and
  replayed it to every later caller as a hit; the key now carries a
  digest of the resolved principal, the `Authorization` and
  `Proxy-Authorization` headers, and the `Cookie` header, plus the
  origin's tenant and the set of content codings the caller accepts. A
  request that presents no credential keys exactly as it did.

  Upgrade-affecting, in two ways. Every entry written by an earlier
  build is unreadable to this one and ages out on its TTL, so expect one
  cold cache per origin, and on a shared Redis or file store expect the
  old entries to hold space until they expire. And on an origin whose
  callers authenticate or carry cookies, one shared entry becomes one
  entry per caller, so the hit rate falls toward the per-caller repeat
  rate. That is the fix rather than a side effect, and
  [docs/configuration.md](docs/configuration.md#who-a-cached-entry-belongs-to)
  covers what to do when the content really is public. Hand-written
  `POST /admin/cache/purge` prefixes have to be rewritten in the new
  format.

  Two more ways a stored entry could be read by a request that should
  have missed, both on the write side. A response carrying a `Vary:` the
  key does not cover is no longer stored at all: the upstream names the
  request headers that change its answer, nothing read that header, and
  an origin answering `Vary: Accept-Language` had one variant stored and
  served to every language. `Accept-Encoding`, `Authorization`,
  `Proxy-Authorization`, `Cookie`, and `Host` are covered by the proxy;
  anything else has to be in `response_cache.vary`, and `Vary: *` is
  never storable. The symptom of getting this wrong is a hit rate stuck
  at zero, and a `debug` line names the header to add. And an entry no
  longer stores a `Content-Encoding` the proxy itself applied:
  compression runs after the entry is written and a hit never replays
  it, so every hit on a compressed origin was shipping identity bytes
  labeled `gzip`, which no client could decode.

- **Reverse-DNS agent verification no longer lets a client spend the
  request path.** Resolver step 2 of the agent-class chain queries a
  zone the client being identified controls, and it used to follow that
  zone wherever it led: one forward lookup per PTR name with no cap, on
  the host resolver's default 5s-by-2-attempts timeout, on a fresh OS
  thread wrapping a fresh multi-thread Tokio runtime per query, and with
  the resulting DNS-error verdict deliberately not cached. A client
  whose IP has no PTR record (most of them) therefore paid the whole
  thing again on every request, and a client that answered its own
  reverse zone with fifty black-holed names could pin a proxy worker
  thread for minutes per request. Every part of that is now bounded: at
  most four PTR names are forward-confirmed, each query is capped at two
  seconds, the forward-confirm loop stops issuing new lookups once two
  seconds of it have elapsed (so a whole verification costs at most
  about six seconds), at most 32 queries are in flight process-wide, all
  queries share one background runtime and one `hickory-resolver`
  instance (so repeats hit its response cache), DNS failures are cached
  for 30 seconds, and a request that needs a lookup runs it on the
  blocking pool instead of an async worker. A check that stops at a
  bound reports a DNS-error verdict, not a not-matched one, so it falls
  through to User-Agent matching rather than caching a negative for five
  minutes. See the `agent_classes` section of
  [docs/configuration.md](docs/configuration.md) and the upgrade note in
  [docs/config-stability.md](docs/config-stability.md).

- **Service tier is the operator's choice, not the caller's.** A caller
  POSTing `{"service_tier": "priority"}` to `/v1/chat/completions`
  reached OpenAI-shaped upstreams verbatim, because that surface never
  round-trips through the canonical hub request. Raising the tier raises
  the bill and the operator pays it, so the field is now removed from
  every request on the way through and replaced by the destination's own
  tier. A new `service_tier:` key on a `providers[]` entry takes `flex`,
  `standard`, or `priority`, translated to the vendor's wire spelling by
  the provider catalog (OpenAI's `standard` is its `default`). Unset
  sends no tier field at all and the vendor serves on its own default.
  To run two tiers of one vendor, declare two entries with the same
  `provider_type` and different tiers; the router treats them as two
  candidates with independent weights, health, and observed latency. A
  tier the catalog does not record for that vendor is refused at config
  load, naming the tier and the vendor, rather than booting and serving
  on a tier nobody chose. The Anthropic native-bypass path, which
  rebuilds the request from the inbound bytes, carries the operator's
  tier too. `sbproxy_ai_service_tier_decisions_total{disposition}`
  counts the replacements, the strips, and the plain applications, so a
  caller losing the tier they asked for is visible rather than silent.
  See the service tier section of
  [docs/ai-gateway.md](docs/ai-gateway.md) and the declared service
  tiers table in [docs/providers.md](docs/providers.md).

- **RFC 9421 verification refuses a stale `created`, and `@target-uri`
  is the absolute URI the spec defines.** The freshness check enforced
  only the future half of the window: there was no lower bound on
  `created` at all. Since `nonce` is optional in the Web Bot Auth
  profile, `required_components` can require a component but never a
  parameter, and nothing in the tree wires `bot_auth`'s nonce store, a
  captured `Signature-Input` / `Signature` pair with no `expires`
  verified forever, which made the two headers an unexpiring bearer
  token for whatever identity the `keyid` carried. `clock_skew_seconds`
  is now the symmetric window both docs already described it as, and
  `hmac_auth`'s hand-rolled copy of the stale check is gone so one
  function owns it. Separately, `@target-uri` emitted the origin-form
  request target where RFC 9421 §2.2.2 defines the full absolute URI,
  and `@request-target` emitted draft-cavage's `METHOD /path` where
  §2.2.5 is the bare target, so no conformant peer could interoperate in
  either direction. Both derive correctly now, the proxy stamps the
  listener's scheme and the `Host` authority onto an origin-form request
  line so the reconstruction matches what a conformant signer signed,
  and inbound verification accepts the old derivation for a deprecation
  window, counting every acceptance on a new
  `sbproxy_signature_legacy_derivation_total{component}` and logging it
  once per process with the verifier's key id. Watch that counter go to
  zero before the window closes. See the upgrade notes in
  [docs/config-stability.md](docs/config-stability.md).

- **Terminal actions now bound the request body they read, and run the
  body policies they were skipping.** An action that answers inside the
  request phase returns before Pingora ever calls `request_body_filter`,
  so the streaming `max_body_size` check that guards a proxied request
  never ran behind one. Three drains had no cap of their own: the AI
  gateway's POST path, its PUT/PATCH path, and the linked Rust action
  plugin arm. Each read the whole downstream body into a growing buffer
  first and asked questions afterwards, so one client could size a
  worker's allocation by choosing what to send. A `request_limit` policy
  did not help: it rejects an honest `Content-Length` and otherwise only
  records the cap for the streaming check, which these paths never
  reach.

  All three now read through one bounded reader. An oversize declared
  `Content-Length` is refused before the first read, a chunked upload
  that declares nothing is refused on the chunk that crosses the cap,
  and both answer `413` ahead of provider dispatch, guardrails, and
  idempotency capture, so no upstream is contacted and no cache or
  idempotency record is written. The cap is `ai_proxy.max_body_size` on
  the AI paths and `request_limit.max_body_size` on the action path;
  where neither is set it is 64 MiB rather than unlimited, because a
  bound that exists only once somebody configures it is not a bound. `0`
  reads as unset and anything above 1 GiB is clamped. The reader also
  keeps `bytes_in` on these paths, which the access log and the usage
  meter previously read as zero for every AI request.

  The linked action arm had a second gap: it ran the handler without
  ever dispatching the `body_mode: buffered` bundle policies that the
  header phase defers precisely because it has no body to give them. A
  fail-closed policy on such an origin was never consulted and the
  handler ran on content that policy would have denied. Those policies
  now run in configured chain order before the handler, the same way
  they already did for bundle actions, and each one's own
  `max_buffer_bytes` is checked before every append rather than once the
  read has finished, so a policy that declared a kilobyte never has the
  host cap streamed past it. Reachability, stated plainly: every
  action-plugin registration in this workspace is test-only, so a stock
  `sbproxy` binary cannot reach that arm from `sb.yml`; a downstream
  binary that links an action plugin reaches it with ordinary config.
  See the `max_body_size` rows in
  [docs/configuration.md](docs/configuration.md) and the linked-action
  body section of [docs/architecture.md](docs/architecture.md).

- Three log-redaction patterns (`api_key`, a `secret`-labeled 40-char
  value, and `password`) consumed the key separator along with the
  value, so a structured log line carrying one of those field names was
  no longer valid JSON. The field-key denylist runs only on a line that
  parses, so `prompt`, `messages`, `cookie` and bundle secret vars on
  that same line were emitted unredacted. All three now preserve the key
  and separator verbatim and mask only the value.

- **The MCP run-as-user token exchange now fails the tool call rather
  than dialing with a redirect-following client.** The exchange builds a
  client with redirects disabled, because the POST carries the caller's
  subject token in the form body and a `307` or `308` replays that body
  verbatim at whatever host the `Location` names. If that client failed
  to build, the call fell back to a default `reqwest` client, which
  follows up to ten hops, so the fallback reinstated the exact hole the
  no-redirect policy closes and did so only on runs where something had
  already gone wrong. The tool call now returns an internal error
  instead.

  The egress section of [docs/security.md](../security.md) also said
  outright that outbound dials pass a default-deny, DNS-pinned
  authorizer. Neither half held unconditionally: a purpose stays
  `ungated` until its sub-block under the top-level `egress:` section
  sets `mode: deny_by_default`, and three of the wired purposes (AI
  provider dispatch, the usage-sink webhook, and model-artifact
  downloads) re-authorize each redirect hop but still let their HTTP
  client resolve the host again at dial time. That page now says which
  purposes are armed by what, and reading `GET /api/egress` for a row
  still marked `ungated` is the way to tell what is actually enforcing.

- `prompt_injection_v2` now preserves typed local-classifier failures,
  fails closed with a generic 503 for mandatory policies, isolates
  deterministic cache entries by verified model semantics, and exposes
  bounded degraded health through metrics, events, Grafana, and the
  authenticated admin API.

- An MCP action running a colocated OAuth broker now refuses to compile
  unless the broker issuer it derives from `external_base_url` and
  `base_path` is listed in
  `oauth.resource_server.authorization_servers`. A mismatch previously
  left the verifier rejecting every token the colocated broker minted.
  The key half of the same mismatch is refused separately at startup:
  see the `public_jwk` entry.

- An MCP action with an OAuth `resource_server` now checks the verified
  token per operation: `tools/call` needs the `mcp.call` scope and every
  other method needs `mcp.read`, matching the vocabulary `docs/mcp.md`
  and `examples/mcp-oauth-discovery` publish. The mapping applies only
  when `oauth.scopes_supported` advertises those names, so a deployment
  using a scope vocabulary of its own is unaffected and keeps
  per-operation authorization at its authorization server.

- **A body-phase policy refusal now holds against an HTTP/2 upstream.**
  `openapi_validation`, `request_validator`, `content_digest`,
  `body_threat_protection`, `prompt_injection_v2`'s body scan, and the
  A2A push-notification check all decide on the buffered request body
  and refuse by aborting the upstream exchange. Pingora propagates that
  abort on an HTTP/1.1 upstream and swallows it on an HTTP/2 one, so
  against an h2 backend the upstream's own answer was forwarded to the
  client and the refused body counted as admitted. Since every TLS
  upstream negotiates h2 by default, that was the behavior for any
  `https://` backend that offers it. The proxy now withholds the
  upstream response and answers with the policy's configured status and
  body on both protocols. If you worked around this by pinning a backend
  to HTTP/1.1, you no longer need to.

- **A config fragment and an extension bundle manifest no longer resolve
  the compiling machine's secrets, and a config-authority bundle no
  longer reads its host directly.** Three powers now belong to config
  the operator wrote: naming a process variable (`${VAR}`,
  `${VAR:-default}`, `{{env.X}}`), referencing a secret the resolver
  reads straight off the host (`env:NAME`, `vault://env/NAME`,
  `file:PATH`), and naming a host path through one of the config keys
  that opens one (`rego_module_path`, `module_path`, `spec_file`,
  `bulk_list.path`, `feed.cache_file`, `agent_skills[].url`,
  `action.path`, the audit chain's four sinks, the access log's output
  path, `extensions.bundles_dir`, the engine binary a `serve:` block
  names, and the rest of the seventy-five in the docs). A config
  fragment loses all three and resolves only the `{{vars.X}}` inputs its
  caller binds. A config-authority bundle keeps `${VAR}` (the documented
  way to name per-node values in a fleet) and loses the other two. An
  extension bundle manifest may no longer resolve a secret for a config
  var it supplied the value for itself, including a `secret://`
  reference to a backend the operator declared, because guest code reads
  its own config; a value the operator wrote in `sb.yml` for that same
  var still resolves, and a signature on the bundle does not change
  either half. A git-sourced document gets the same treatment when its
  `source:` block sets the new `confine: true`, which defaults to
  `false` so no existing GitOps repository changes behavior on upgrade;
  an unconfined source whose document reaches for the host now logs one
  warning naming the source and the first finding, at boot and on
  refresh. Each refusal names the document and the field and never
  echoes a value. The secret-reference power is the one a template check
  cannot see: `api_key: "env:AWS_SECRET_ACCESS_KEY"` contains no
  template syntax at all and reads the same secret as
  `${AWS_SECRET_ACCESS_KEY}`. Publish validation and the subscriber both
  run the check, so a payload cannot pass the authority and then be
  refused fleet-wide. A `${VAR:-default}` default is treated as document
  text throughout: the document is checked a second time with its own
  defaults filled in, so a default cannot assemble a mapping key or a
  secret reference the pre-substitution check never saw, and a default
  that is itself a secret reference or an absolute path is refused
  outright. Not closed: a remote document may still name a process
  variable that resolves, which needs an operator-declared allowlist
  this release does not add, and the host-path half is a list of config
  keys rather than a rule about files, kept honest by a test that walks
  every JSON Schema this repository generates, all six of them, for
  every property whose name or description says it is a path.

- Credential-bearing types no longer derive `Debug`. An AWS secret
  access key, an Entra client secret, an inline GCP service-account key,
  a HashiCorp Vault client token or AppRole `secret_id`, a cached OAuth
  bearer token, a minted virtual key's one-time token, a plaintext
  credential at rest, an RFC 9421 HMAC verification key or signing seed,
  and a credential secret posted to the admin API all rendered in full
  through any `{:?}`, which is one `anyhow` chain or one rejected
  request body away from a log line. Each now has a manual `Debug` that
  prints `[REDACTED]` for the reusable half and keeps the identifiers
  that say which backend, role, or key failed. Redacting
  `CredentialMaterial::Plaintext` covers every record that contains it.
  Nine tests push a sentinel through each type and fail if it comes back
  out.

- Dial-time address checks refuse every IPv4-embedding IPv6 form, not
  just `::ffff:a.b.c.d`. The NAT64 well-known prefixes (`64:ff9b::/96`,
  `64:ff9b:1::/48`), the IPv4-translated SIIT form (`::ffff:0:a.b.c.d`),
  and 6to4 (`2002::/16`) over a private or reserved address all passed
  every range check, because `to_ipv4_mapped` and `to_ipv4` return
  `None` for them. NAT64 is how an IPv6-only Kubernetes cluster reaches
  IPv4, so on that network `64:ff9b::a9fe:a9fe` was a live route to the
  cloud metadata endpoint from an unauthenticated request.

- Every credential-bearing config type whose runtime twin was already
  redacted now redacts too, and every runtime type whose config twin
  was: the AWS secret access key and session token, the usage sink
  Langfuse, Datadog and ledger-signing credentials, the outbound client
  secrets, the legacy Vault token, the Web Bot Auth directory signing
  seed and the OLP signing and content-key seeds, the RAG embedding and
  vector store keys, the Stripe secret key, an imported LiteLLM provider
  key, the event and alert webhook HMAC keys, the Consul ACL token,
  seeded inbound keys and upstream credentials, the admin Basic-auth
  password, and the inbound token the header sweep lifts out of a
  request. A `redis://` DSN with a password in its userinfo now renders
  as its origin. The registry that enforces this covers 58 types and its
  detector no longer misses a rustfmt-wrapped derive or one separated
  from its declaration by an ordinary comment.

- Nineteen more credential-bearing types stop deriving Debug: inbound
  API keys, bearer tokens and Basic/Digest passwords, the JWT HMAC
  secret, the OIDC client and cookie secrets, stored refresh tokens,
  outbound OAuth and vault secrets, AI provider keys, usage-sink write
  keys, the CSRF and crawl-ledger signing keys, the admin session key,
  mesh enrollment tokens, and the config-side twins of the Vault, Entra
  and toolkit credentials. A CI guard now refuses a tree where any
  registered type regains its derive.

- OpenID Federation JWS verification checks a verifier-owned algorithm
  allowlist before it resolves the attacker-selected `kid`, and binds
  the header `alg` to the JWK's own `alg`, `use`, `key_ops`, `kty`, and
  `crv`. Missing required claims are named explicitly, a future `iat`
  outside five minutes of leeway is rejected, metadata-policy
  composition stays monotonic across all seven operators, the trust
  chain is walked anchor to leaf, and no error string interpolates a
  URL, a credential, or a transport error.

- OpenID Federation peer fetches run through the governed egress
  machinery. A peer URL that resolves to a loopback, RFC 1918,
  link-local, or CGNAT address is refused before any connect whether or
  not egress is configured, and the dial is pinned to the addresses that
  check resolved so a rebind between check and connect is refused too. A
  new `egress.federation` sub-block adds the host, scheme, and port
  allowlist and per-hop redirect re-authorization, and `federation`
  joins the fourteen purposes reported by `GET /api/egress` and
  `sbproxy_egress_refused_total`.

- OpenID Federation peer-trust chain walks have a real fetch budget.
  `proxy.federation.peer_trust.max_chain_depth` capped recursion depth
  and was documented as the fetch budget; it is not one, because
  `authority_hints` is an array and one entity naming five thousand
  superiors cost five thousand outbound GETs at depth 1. With
  `peer_trust` configured that made one unauthenticated request header
  an attacker-directed request amplifier. Four new keys bound a walk for
  real: `max_chain_fetches` (16), `max_chain_bytes` (2 MiB),
  `max_chain_duration_ms` (5000), and `max_authority_hints` (8), all
  refused at zero when the config compiles. No fetch is driven by an
  unverified document either: every entity configuration is
  signature-checked before its hints are read, against the pinned anchor
  key set where the entity is an anchor and against its own published
  `jwks` otherwise, and a configuration served at one URL claiming to be
  another entity is refused. The decision cache is keyed on the source
  address and the claimed entity id together rather than the entity id
  alone, which a caller defeats by rotating it, and `walks_per_minute`
  (30) limits walks per source.

- Rotated access-log backups are made owner-only at each rotation, not
  only when a sink opens the active file: an uncompressed rotation is a
  rename, so backups written by an earlier build kept their old mode for
  as many rotations as `max_backups` allows.

- The access log, its rotated `.gz` copies, the decision event feed, and
  the compiled file sink now create their files owner-only (`0600`) and
  their own directories `0700`, closing the last five sinks that still
  let the umask decide. Under the common `0022` they landed at `0644`,
  so every account on the host could read the path, the identity, and
  the decision for every request the proxy served. A file that already
  exists at a wider mode is tightened when the sink opens it rather than
  inherited, so a shipper or backup job running as a different user
  loses access on the first write after an upgrade; run it as the proxy
  user or point the sink at a fifo or `/dev/stdout`, which are left as
  the operator set them. A directory that already exists keeps its mode,
  so a shared `/var/log` is never narrowed.

- The device-code consent POST requires a same-origin `Origin` or
  `Referer` and a single-use form token bound to the signed-in subject,
  and both `/verify` responses refuse framing.

- The MCP OAuth broker canonicalizes IPv4-mapped IPv6 before every
  private-range check, so the `::ffff:10.0.0.5` spelling of a private
  address can no longer reach the CIMD fetcher or the OAuth egress
  client.

- The MCP OAuth broker no longer puts a raw `reqwest::Error` on a log
  line when an upstream `/token`, token-exchange, or introspection call
  fails. `reqwest` ends its `Display` with the request URL, and for a
  broker that URL is an operator credential, so those three sites now
  log `request_error_summary` instead.

- The MCP OAuth broker refuses a zero `session_ttl_secs`, and a zero
  `cimd_cache_ttl_secs` when CIMD is enabled, at startup. Either one
  built a store whose every row expired before the round trip that would
  read it, so the flow it backed could never complete; the broker booted
  anyway and rejected every callback.

- The MCP OAuth broker refuses an over-length URL-shaped `client_id`
  instead of downgrading it. The bound was applied by returning `None`
  from the CIMD detector, which fell through to the pre-registered
  client path where the only gate is the `redirect_uri` allowlist, so a
  deployment running both admitted the request with the metadata
  document own `redirect_uris` and scope checks skipped. `/token`
  applied no bound at all. Both now answer `invalid_client`, and the
  bound is sized to fit under the session store key budget so the
  refusal names the client id rather than a document that was never
  fetched.

- The MCP OAuth broker refuses three configurations at startup that used
  to fail or downgrade at runtime: a `base_path` of `/` or empty, which
  would capture every route on the origin; `device_code_enabled` without
  a `broker_signing_key`, which could never mint the token it promised;
  and an advertised `token_endpoint_auth_method` the broker cannot
  process. Device authorization also answers `invalid_scope` for a
  missing or unadvertised scope when `scopes_supported` is set.

- **The project write boundary is an allowlist, and `origin_sources` is
  denied to a config authority.** A project profile may set exactly the
  origin fields `OriginProfileSpec` names. Everything else on an origin
  is unrepresentable in a profile rather than merely rejected, so the
  parser refuses the document and names the key. An origin has 53 fields
  and gains more regularly, so a deny list would have made every future
  field a silent privilege grant to every project repository, with no
  review step that would catch it; a test enumerates the origin's fields
  and fails when one lands on neither side. The deny list first
  considered would already have missed `filters[].failure_posture` (a
  project flipping a platform security filter to fail-open while the
  config still advertises protection), `force_ssl: false`,
  `response_cache` (an authenticated response cached and served to
  somebody else), the `on_request` and `on_response` extension hooks,
  and `allowed_methods`. A profile is also a confined document, so it
  reaches the composing process environment through neither `${VAR}` nor
  `{{env.X}}`, carries no `env:NAME`, `file:/path` or `vault://env/NAME`
  reference, and names no host path the proxy opens: the one secret
  spelling it keeps is a provider URI resolved against a backend
  declared under `proxy.secrets`, which no project can write. A secret
  written out in full is refused without the refusal echoing it, and the
  check runs after inputs are substituted, so an entry binding a raw
  token is refused the same way. `origin_sources` joins `source` on the
  paths no config authority may set: `source` names one repository,
  while this block names N of them, and the documents it pulls carry
  Lua, WASM and JavaScript bodies the `{{ }}` interpolator deliberately
  never reads. Its sibling `origin_defaults` stays authority-writable,
  because that block is the platform raising a security floor, which is
  what the channel exists for. In a `production` tier every entry must
  pin a full commit sha or a tag spelled `refs/tags/<name>`; the tier is
  a property of the runtime document rather than of an entry, because an
  entry that could declare its own tier could declare its way out of the
  rule.

- The S3 Cache Reserve backend enforces `cache_reserve.max_size_bytes`
  before it calls AWS. An oversized declared `Content-Length` is refused
  up front, the body is read incrementally against a hard byte cap that
  accounts for the GCM tag, and the AWS clients are built on first use
  instead of at config compile.

- A CoMP redeem now fails closed on a `quote_id` this process never
  issued (`403 unknown_quote`, opt out with `comp.allow_unknown_quotes`)
  and on a buyer acceptance whose `accepted_at` is unparseable, more
  than five minutes ahead of the proxy clock, or older than a whole
  quote validity window. `CompRedeemResponse` no longer derives `Debug`,
  so a minted license token cannot reach a log line, a `dbg!`, or a
  panic message.

- The CoMP marketplace bridge is single-use per quote and bounded. A
  second redeem of the same `quote_id` is refused with `403
  already_redeemed`; a quote request past 50,000 live ledger rows is
  refused with `429 quote_ledger_full`, counted like every other
  refusal, so an unauthenticated flood on `POST
  /.well-known/iab-comp/quote` cannot grow the process out of memory. A
  catalog carrying more than one `authorization: olp` tier is now
  refused at config load, because a redeem names no tier and would mint
  whichever the manifest lists first.

- The unauthenticated `POST /.well-known/olp/token` endpoint now carries
  a per-source token budget.
  `origins.<host>.olp.token_rate_limit_per_minute` (default 60, `0`
  refused at config load) bounds how many Ed25519 bearer license tokens
  one source IP can mint; past it the answer is `429 slow_down` with
  `Retry-After`, counted as
  `sbproxy_olp_decisions_total{outcome="rate_limited"}` and logged as an
  `olp_decision` event. The budget is keyed on the raw socket peer, not
  `X-Forwarded-For`, because a forgeable header is not an identity on an
  endpoint that needs no credential.

- A credential carried in a URL's userinfo is now masked wherever
  secrets are redacted, including the YAML `GET /admin/config` and `GET
  /admin/config/effective` return and the output of `sbproxy config
  print`. `key_management.crypto.root_of_trust.address` is an unparsed
  URL under a key name no pattern matched, so
  `https://sbproxy:hvs.MUSTNOTAPPEAR...@vault.internal:8200` came back
  in full while the `token` beside it was masked. The scheme and the
  host survive the mask, so the route still says which key service is
  configured. The URL's authority is matched by an allowlist, and there
  are two, because one set could not serve both surfaces. The config
  routes above take `[A-Za-z0-9]`, plus `-._~%:@`, plus the userinfo
  sub-delims `!$&*+=`, so a base64-padded token such as
  `hvs.CAESIQpAbCdEf=` is reached; the access log takes the same set
  without `!$&*+=`, because a log line carries a caller's raw query
  string, whose delimiters the caller chose rather than the renderer.
  Neither set contains `"` or `\\`, so a deleted span can never leave
  the JSON string token or the YAML scalar it started in. Userinfo
  containing any byte outside the set that applies, including `,`, `;`,
  `'`, `(`, `)`, `/`, whitespace, and any non-ASCII byte, is left
  unmasked rather than masked halfway.

- An origin that configures `sessions` or `csrf` together with
  `response_cache` can serve one caller the `Set-Cookie` the proxy
  minted for another. The cache key partitions on the `Cookie` header a
  caller sends, so every caller that sends none shares one partition,
  and a stored entry replays the session identifier or CSRF token
  captured with it. This is long-standing behavior rather than a change
  in this release, and it is now documented under "Who a cached entry
  belongs to" in `docs/configuration.md` with the two remedies available
  today: leave `response_cache` off on an origin that mints either
  cookie, or raise `response_cache.epoch` to partition away from entries
  already written. The third pairing, `abtest` with `response_cache`, is
  refused at config load instead.

- Updated Wasmtime and WASI to 46.0.3 and cap-std to 4.0.3, applying
  upstream fixes for filesystem sandbox escapes and guest-controlled
  host allocations (RUSTSEC-2026-0268 and RUSTSEC-2026-0269).

### Added

- **Audit chain viewer: `GET /api/audit/chain` and the console's Audit
  view.** The four tamper-evident audit chains (`audit.path`,
  `audit.config_path`, `audit.key_path`, `audit.admin_path`) were
  CLI-only reads until now. The new route reads the chained files
  themselves with channel, actor, and time-range filters plus cursor
  paging, re-verifying every hash link and Ed25519 signature as it
  reads; reads are windowed (streamed one record at a time, never a
  whole-file load) and a verification failure is served in the response
  with the first broken sequence and reason, alongside the records that
  verified. A truncated or deleted chain file is reported as a failure
  too: what is left of a truncated file links and signs perfectly, so
  the read compares the walk against the number of records **this
  process** wrote to that chain, which means it catches a truncation the
  running proxy outlived and not one that survived a restart. The
  console's Audit view renders the four channel cards, the merged entry
  table, and a failure banner. GET-only, readable by the `read_only`
  role; a login narrowed with `proxy.admin.operators[].tenant` is
  refused, because the chains are deployment-wide and a per-tenant slice
  of an audit trail reads as "nothing else happened". Read access is
  wider than the bounded ring at `GET /api/audit/events` on two axes,
  both stated in [docs/audit-log.md](docs/audit-log.md): history is the
  whole chain rather than the last `max_audit_events` records, and each
  entry carries the chained payload verbatim rather than the ring's
  `detail` projection. No secrets cross either way; a deployment that
  wants the trail narrower turns the channel's chain path off or fronts
  the admin port. Every call is itself recorded on the admin channel
  (`read_audit_chain`, or `read_audit_chain_denied` on the refusal). See
  the audit-chain sections of [docs/audit-log.md](docs/audit-log.md),
  [docs/admin-api-reference.md](docs/admin-api-reference.md), and
  [docs/admin-ui.md](docs/admin-ui.md).

- **`body_threat_protection`: structural JSON and XML request-body
  limits.** A new `policies:` entry that refuses bodies by shape rather
  than by content: a thousand levels of nesting to blow a recursive
  parser's stack, a million-key object to soak CPU in hash insertion, an
  XML DTD whose entities expand into gigabytes. JSON limits are
  `max_depth` (64), `max_object_entries` (10 000), `max_array_items` (10
  000), `max_key_length` (1 024 bytes), `max_string_length` (128 KiB),
  and `max_containers` (50 000, objects plus arrays); XML limits are
  `max_depth` (64), `max_elements` (10 000), and `max_attributes` (256).
  Any single limit set to `0` disables that one check. A `<!DOCTYPE`
  declaration is refused unconditionally and is not configurable, which
  closes the entity-expansion class by construction rather than by
  pattern. The JSON scanner is iterative with an explicit stack and a
  hard 10 000-depth ceiling that holds even when the operator disables
  the depth check, so the attack the policy exists to stop cannot
  overflow the scanner itself. A violation answers `400` naming the
  limit and the observed and allowed numbers, and never echoes body
  content into the response, the log, or the audit record. `mode: tap`
  logs and counts without blocking, for sizing limits against real
  traffic before enforcing; the policy counter's `action` label keeps
  the two apart. One thing to know if you are migrating from the
  origin-level `threat_protection:` block: this policy has no body-size
  knob. The successor to `json.max_total_size` is
  `request_limit.max_body_size`, not a key here, and all three of the
  policy's structs refuse unknown fields, so an invented one fails
  config load instead of being silently ignored. See
  [docs/api-security.md](docs/api-security.md#structural-body-threat-limits)
  and
  [examples/body-threat-protection/](examples/body-threat-protection/).

- **First-class API deprecation: RFC 9745 `Deprecation`, RFC 8594
  `Sunset`, and the successor and documentation `Link` relations.** A
  `deprecation:` block on an origin or on a single forward rule stamps
  the standard announcement headers onto the responses that rule
  matches. Per-path deprecation, the normal case where `/v1/*` is going
  away and `/v2/*` is not, was not expressible before: response
  modifiers hang only off the origin, so it was the whole origin or
  nothing. `deprecated:` takes a date or an RFC 3339 timestamp and emits
  `Deprecation: @<unix>`, the structured-field Date the RFC requires; a
  bare `true` marks the route for spec emission and metrics but emits no
  header, because the draft-era literal `true` did not survive into the
  final RFC. `sunset:` emits the HTTP-date form, and a sunset earlier
  than the deprecation instant is refused at config compile rather than
  shipped as a contradiction. `successor:` and `link:` emit the
  `successor-version` and `deprecation` relations, appended so an
  upstream's own `Link` headers survive. `after_sunset: gone` retires
  the route with `410 Gone` and a JSON body naming the successor once
  the instant passes; the default `serve` keeps proxying, so a forgotten
  config never takes an API down by surprise. That refusal is
  enforcement, so it also emits a `policy_violation` audit record with
  `event_type: api_deprecation` carrying the tenant and the accountable
  key id. `openapi_validation.deprecation_headers:` (off by default)
  drives the same emission from operations a loaded spec marks
  `deprecated: true`, and `/.well-known/openapi.json` marks
  config-deprecated operations `deprecated: true` with
  `x-sbproxy-sunset` and `x-sbproxy-successor` extensions, so the
  published spec and the wire headers cannot disagree.
  `sbproxy_deprecated_requests_total{origin, route, past_sunset,
  outcome}` is the migration tracker: who is still calling, against
  which announcement, and whether they are being served or refused. See
  [docs/api-gateway.md](docs/api-gateway.md#deprecating-endpoints) and
  [examples/api-deprecation/](examples/api-deprecation/).

- **`hmac_auth`: signed-request authentication.** A new auth provider
  for machine callers that prove possession of a shared secret by
  signing each request (RFC 9421 HTTP Message Signatures, `hmac-sha256`)
  instead of sending a static credential. Config is a `keys` list of
  `key_id` + `secret` pairs (secrets resolve through the secret
  resolver) with optional per-credential metadata, a
  `required_components` list defaulting to `["@method", "@target-uri"]`,
  and a `clock_skew_seconds` window (default 300) enforced against the
  mandatory `created` parameter as the replay defense. Failures answer
  `401` with a `WWW-Authenticate: Signature` challenge that never
  carries key material. See the `hmac_auth` section of
  [docs/configuration.md](docs/configuration.md) and
  [examples/auth-hmac/](examples/auth-hmac/).

- **Key-lifecycle events reach the SIEM feed.** The `events:` type list
  grows to eighteen declared types with five key-lifecycle kinds.
  `key_minted`, `key_revoked`, `key_rotated`, and `key_blocked` bridge
  from the `key_audit` channel, so every admin mint, revoke, rotate, or
  block of a key or upstream credential publishes one typed event beside
  its audit-chain entry instead of a SIEM having to poll the admin API.
  `credential_resolved` fires once per actual resolution of an upstream
  credential's material (never per request), with `outcome:
  stale_served` marking the start of a rotation grace window serving
  through a secret-backend outage. That one is per outage, not per
  request in the window; the per-serve count is the `cache="stale"`
  series on the resolution histogram. Payloads are an explicit allowlist
  (`op`, `resource`, the public id, actor, tenant, outcome, and closed
  status labels), never the `key_audit` diff, a token, or a hash;
  `events.types:` filters the new kinds like any other, and
  `sbproxy_events_dropped_total` covers them. See
  [docs/events.md](docs/events.md#key-lifecycle-events-the-dual-record).

- **Key management gets its four operational metrics.**
  `sbproxy_key_operations_total{operation, outcome}` counts every admin
  key-lifecycle call at the dispatch seam, keeping `refused` (a 4xx the
  caller can fix) apart from `error` (the store or governance backend
  failed) so a busy console never reads as an outage.
  `sbproxy_credential_resolution_duration_seconds{cache, outcome}` times
  each bound-credential resolution and names the layer that answered,
  with `stale` marking a grace-window serve rather than folding it into
  `hit`. `sbproxy_key_lookup_cache_total{kind, outcome}` reports the
  keystore TTL cache, including `negative_hit` as its own value so a
  stampede of unknown keys stays visible. And
  `sbproxy_audit_write_failures_total{channel}` counts audit emissions
  that did not reach a sink they were promised, touching the series at 0
  on every emission so an `increase()` alert has a baseline from the
  first scrape; its two channels are the key-mutation trail (`key_path`)
  and the admin-console action trail (`admin_path`), which is why it is
  named for the audit signal rather than for the key plane. Every label
  value is a compile-time constant, so none passes through the
  cardinality limiter. The `sbproxy-security` Grafana dashboard gains
  the matching panels. See the operational metrics section of
  [docs/key-management.md](docs/key-management.md#operational-metrics).

- **New metric `sbproxy_audit_chain_read_total{channel, outcome}`.** One
  increment per chain walked per viewer read, with an `outcome` of
  `verified`, `broken`, or `unreadable`; a refusal increments all four
  channels with `denied`, because it refuses all four. A broken chain
  that only a person looking at the console can see is a finding nobody
  is on call for, and a tenant-scoped operator probing a deployment-wide
  security surface is one whose only other record sits inside the chain
  that operator was refused. Both leave the page: alert on
  `increase(sbproxy_audit_chain_read_total{outcome!="verified"}[15m]) >
  0`. That rule does not cover a chain file truncated at the tail and
  read after a restart: the boot re-baselines on what is left, every
  link and signature holds, and the read is `verified`. Pre-restart
  records are covered by `sbproxy audit verify` against an offsite copy.

- **`POST /v1/responses` resolves an object-valued `prompt` against the
  gateway prompt store.** A request carrying `{"prompt": {"id": "...",
  "version": "...", "variables": {...}}}` previously had the whole
  object dropped in translation. The `id` now maps onto a stored prompt
  name and `version` onto a stored version label, an absent version
  takes the pinned default, and caller `variables` render into the
  template before guardrails scan the result. One stored prompt serves
  every configured provider, which is the part a dashboard-hosted
  template cannot do. An unknown reference answers `404`, a malformed
  object or a failed render answers `400`, and nothing falls through to
  the raw input. Caller-supplied `variables` override an operator's
  static `variables:` on a version, so a constraint that must hold
  regardless of the caller belongs in the template text; see the
  prompt-object section of [docs/ai-gateway.md](docs/ai-gateway.md).

- **Reporting: multi-dimension spend aggregation and raw export on the
  request log, with shareable filtered views.** `GET
  /api/requests/report` aggregates the same filtered ring that `GET
  /api/requests` serves into one row per composite group: `group_by`
  takes any mix of `model`, `api_key_id`, `tenant`, and `user`
  simultaneously, and each row carries request count, tokens in/out, and
  estimated cost. `GET /api/requests/export` downloads the filtered rows
  as CSV or JSONL, bounded by the ring cap and hardened against
  spreadsheet formula injection. Every export is an audited admin action
  (`export_request_log`, naming the format, the row count, and which
  filter dimensions were set) and increments the new
  `sbproxy_admin_request_exports_total{format}` and
  `sbproxy_admin_request_export_rows_total{format}` counters, so every
  export is recorded and alertable. That record covers the export route,
  not every bulk read: `GET /api/requests?limit=<max>` returns the same
  rows under the same cap with no record and no counter, so a detection
  built on `export_request_log` alone covers the download button rather
  than the whole read surface. The response is bounded by the ring cap
  but materialized rather than streamed, because the admin dispatcher
  answers with a whole body; what the row-at-a-time encoding avoids is a
  second copy, not the response itself. All three routes share one
  filter surface, which gains exact `model`, `tenant`, and `user`
  filters, refuses a malformed `status`, `offset`, or `limit` with a
  `400` instead of ignoring it, and treats an empty filter value as
  "rows with nothing there", so the report's unattributed group drills
  through to its own rows like any other. The admin console's new
  Reports view drives them and serializes filter and grouping state into
  URL query params, so a filtered report is a shareable link. See the
  reporting sections of
  [docs/admin-api-reference.md](docs/admin-api-reference.md) and
  [docs/admin-ui.md](docs/admin-ui.md), and the worked example in
  [examples/admin-reporting/](examples/admin-reporting/).

- **Routing decision traces: `GET /api/routing-decisions` and the admin
  console's Routing decisions view.** Every routed request (AI dispatch
  or a load-balanced origin) now records a per-request decision trace:
  the strategy or operator plan that decided, the ordered candidates it
  weighed, the winner, the reason, the fallback chain actually
  traversed, and timing. The record's open `detail` map is additive by
  design so later explanatory columns land as keys, not schema changes.
  Bounded in-memory ring sharing `proxy.admin.max_log_entries` with the
  request log; server-side filters by origin, strategy, model (either
  side of a substitution), provider, and time range. See the
  routing-decisions sections of
  [docs/admin-api-reference.md](docs/admin-api-reference.md) and
  [docs/admin-ui.md](docs/admin-ui.md).

- **`sbproxy_ai_translation_dropped_total{surface, field}` counts every
  request field lost in translation.** `/v1/messages` and
  `/v1/responses` now push a note for each unrepresented top-level
  field, each dropped content block, and each extension attribute on a
  block they keep, then emit one aggregated warn per request naming at
  most eight distinct fields. `surface` uses the same `messages` and
  `responses` values as `sbproxy_ai_surface_requests_total`, so a
  drop-rate query joins the two. The log line to grep is `AI proxy:
  request fields dropped in translation`, and it carries the origin and
  tenant.

- **`sbproxy_target_health_state`: per-target load-balancer health as a
  Prometheus gauge.** Whether a target is actually taking traffic used
  to mean polling `GET /api/health/targets`. It is a gauge now, on
  LiteLLM's 0/1/2 deployment-state scale (0 healthy, 1 degraded with the
  circuit breaker half-open, 2 excluded from selection), so Grafana
  panels built against that convention port over unchanged. The value
  folds all three exclusion mechanisms, active probe, passive outlier
  ejection, and circuit breaker, and is sampled at scrape time from the
  same pipeline walk that renders the admin endpoint, so the two
  surfaces cannot tell different stories about one target. A target
  dropped by a config reload leaves the scrape on the next render
  instead of freezing at its last value. The `target` label is the
  configured URL, or the load balancer's own `url#index` identifier when
  one origin configures that URL more than once. A Target Health State
  panel ships on the origins dashboard, and a Budget Utilization by
  Scope panel on the AI gateway dashboard for the already-exported
  `sbproxy_ai_budget_utilization_ratio`; headroom is `1 -
  sbproxy_ai_budget_utilization_ratio` in PromQL, and there is
  deliberately no separate remaining family, because a family and its
  complement double the series without adding information. See
  [docs/observability.md](docs/observability.md#budget-headroom-and-target-health)
  and
  [examples/health-and-budget-gauges/](examples/health-and-budget-gauges/).

- **A signed extension bundle can ship a `runtime: rego` transform, not
  just a policy.** A `kind: transform` hook on a Rego bundle attaches
  under `transforms[]` by its `type` name and evaluates once per
  buffered response body. Its input is `input.body.body_base64` (the
  complete body, base64), `input.body.content_type`,
  `input.body.origin`, and `input.config`; the pinned rule must return a
  base64 string, which becomes the replacement body, bounded by
  `sandbox.max_output_bytes`. An undefined rule is the transform
  declining and the body passes through untouched. The module compiles
  once per hook at candidate load and its query is proved evaluable
  there, so a bad rule reference refuses the bundle instead of failing
  every request. Bounded by `sandbox.budget_ms` plus the buffer and
  output caps; `memory_mb` and `stack_kb` do not apply to Rego and are
  now refused on a Rego manifest rather than accepted and ignored. See
  the Rego transform section of
  [docs/extension-bundles.md](docs/extension-bundles.md).

- **Temporary, auto-expiring budget overrides on dynamic keys.** `POST
  /admin/keys/{id}/budget-override` raises a governed key's effective
  budget on top of its base caps (`max_tokens_increase`,
  `max_cost_usd_increase`) until a `ttl_secs` or `expires_at` expiry,
  after which the base caps resume with no operator action: expiry is
  persisted on the key record and evaluated lazily at every budget read,
  so it survives restarts and needs no sweeper. Read responses and the
  console's Keys page show the base budget, the override with its
  countdown and grantor, and the enforced `effective_budget`; `DELETE`
  on the same path ends a raise early. Three points in the raise's life
  land in the `key_audit` trail: `budget_override_grant` and
  `budget_override_clear` name the operator who granted or ended one,
  and `budget_override_expire` is the unattributed, time-driven end. All
  three routes are counted on `sbproxy_key_operations_total{operation,
  outcome}` alongside the other key mutations. See the temp-override
  section of [docs/ai-gateway.md](docs/ai-gateway.md) and
  [examples/temp-budget-override/](examples/temp-budget-override/).

- **A hard price ceiling per request.** `max_price_per_request` on an
  `ai_proxy` origin refuses a request whose estimated cost exceeds the
  ceiling before any provider is chosen, rather than capping spend after
  the fact the way a budget does. Callers can tighten it per request
  with `x-sbproxy-max-price` (the header only ever lowers the effective
  ceiling); a malformed or non-positive value is refused with 400 rather
  than ignored. Each routing candidate, including a cascade's tiers, is
  priced through the same resolution cost tracking bills with
  (`model_prices`, rate card, built-in catalog, then a pessimistic $5 /
  $5 fallback) against the model it would actually dispatch after
  `model_map`. When every candidate is over the ceiling the request
  fails closed with `402 price_ceiling_exceeded`, naming the ceiling and
  each excluded candidate's estimated cost and price source, and it
  writes a `security_audit` record so the refusal reaches a configured
  `events:` sink like every other gateway refusal. Its attributed
  outcome is `price_ceiling_block`, distinct from `budget_exceeded`. A
  ceiling estimate includes the output allowance a configured
  `reasoning:` budget will raise, so a reasoning request cannot dispatch
  above a ceiling it priced under. See the per-request price ceiling
  section of [docs/ai-gateway.md](docs/ai-gateway.md) and
  [examples/price-ceiling/](examples/price-ceiling/).

- **A pre-header streaming timeout that bounds the failover window.**
  `resilience.pre_header_timeout_ms` on an `ai_proxy` origin bounds
  connect through the provider's response headers on a streaming
  request, and hands the request to the next candidate when it elapses,
  where the origin's attempt budget defines one. Before this, a provider
  that accepted the connection and then went quiet was bounded only by
  `providers[].timeout_ms` (or the gateway's 30-second HTTP client
  default), and that budget has to be long enough for a real completion,
  so no failover happened for as long as it ran. The two budgets are
  distinct: this one ends at the upstream response headers, `timeout_ms`
  runs through the end of the response body. The key applies to
  streaming requests only, is refused at load when set to `0` or written
  at the action level instead of inside `resilience:`, and only ever
  shortens an attempt, so a value above the attempt's own `timeout_ms`
  (or above the gateway's 30-second HTTP client default when
  `timeout_ms` is unset) never fires. On a cluster it also bounds a
  `managed_model` served by another node, cold start included. A
  failover it takes is labeled
  `sbproxy_ai_failovers_total{reason="pre_header_timeout"}` rather than
  `transport`. Which origins can take one is worth knowing before you
  alert on that series: the attempt loop runs the whole provider order
  only when the strategy is `fallback_chain`, when
  `resilience.content_policy_fallback` is on, or when a typed fallback
  list is configured. On any other origin, `round_robin` among them, the
  budget has no successor to hand the request to, the caller gets a
  `502` naming the budget, and that failover series stays silent through
  the whole incident. What always ticks there is
  `sbproxy_ai_provider_errors_total{provider,error_kind="timeout"}`,
  which is what to alert on when the budget cannot hand anything on.
  Past the response headers the request is committed to that provider
  and a later candidate cannot replace output the caller is already
  reading, so a stall, reset, or guardrail block there ends the stream
  and ticks the new
  `sbproxy_ai_stream_post_commit_failures_total{provider, cause}` with
  `cause` one of `upstream_timeout`, `upstream_error`, or `guardrail`.
  See the [pre-header streaming
  budget](docs/ai-llm-aware-resilience.md#pre-header-streaming-budget)
  and [docs/ai-gateway.md](docs/ai-gateway.md).

- **A trust row on the AI Value dashboard.** Four panels on the
  `sbproxy-ai-value` Grafana board read four metric families no
  dashboard read before, so an operator can now see how much of the
  spend figure is measured rather than guessed:
  `sbproxy_ai_price_source_total` as the share of price lookups served
  by the shipped catalog, an operator rate card, config, or the flat
  fallback rate, which is the signal that spend, budget debits, and the
  price ceiling are all comparing against a guess;
  `sbproxy_ai_price_ceiling_total` split by outcome, where refusals
  climbing behind steady exclusions means the ceiling now sits below the
  cheapest available candidate; `sbproxy_ai_token_estimate_error_ratio`
  as signed p05 and p95 error per model, where positive means the
  estimator under-reserved against the budget it debited and negative
  means it over-reserved and held rate-limit headroom the request never
  used; and `sbproxy_ai_cost_saved_micros_total` as semantic-cache
  dollars per hour avoided, joined to the Tenant dropdown through the
  family's `tenant` label. All four families exist only once the feature
  that writes them is configured, so each panel carries a second
  `absent()` target drawn as a red `not reported` series. A red line at
  1 means the family was never written and the panel is not measuring
  anything; a flat zero with no red line is a measured zero. Each panel
  description also names the dropdowns its family cannot honor: price
  provenance, ceiling outcomes, and estimator error carry no tenant
  label, and cache savings carries no `api_key_id`, so a saving cannot
  be credited to a credential.

- **The admin console shows requests the AI gateway refused before any
  provider was called.**
  `sbproxy_ai_admission_decisions_total{surface,reason,outcome}` and the
  `ai.admission` decision record shipped with nothing in the console
  reading either, so the one class of refusal that is invisible in
  provider-side metrics, because no provider was called, was invisible
  here too. The AI performance page now carries a `Refused before
  dispatch` tile and a panel listing every `surface / reason` pair, with
  the bounded label values rendered as the phrase they mean (`OpenAI
  Responses`, `MCP tool block, which would reach an MCP server past this
  gateway`) and the raw code kept beside them so a row still joins the
  metric and the record. The counter is published on its first
  increment, so a proxy that has never refused a request before dispatch
  exports no family at all: the tile reads `not reported` rather than
  `0`, because a flat zero over a measurement nobody has taken reads as
  a healthy signal. A deployment whose only AI activity is refusals no
  longer renders the page's empty state, which is the state an operator
  opening the page to find that refusal would have hit. See the AI
  performance section of [docs/admin-ui.md](docs/admin-ui.md).

- **The admin console now reads three security signals that shipped with
  writers and no reader.** Guardrails gained a CORS panel over
  `sbproxy_cors_refusals_total{reason}` and an RFC 9421 panel over
  `sbproxy_signature_legacy_derivation_total{component}`, which is the
  number that has to reach zero before the pre-conformance `@target-uri`
  / `@request-target` fallback can be removed; acceptance was otherwise
  announced in one log line per process, which says a signer somewhere
  has not moved and nothing about whether that is still true today.
  Overview gained a certificate-store row over
  `sbproxy_cert_store_degraded{backend}`, and raises a warning block
  when the node is not persisting certificates: when the gauge reads 1,
  because the configured backend could not be opened, and when it reads
  0 on `acme.storage_backend: memory`, which opens cleanly and still
  loses every certificate on restart. Both spend the CA rate limit for
  the hostname by re-issuing on every boot. All three signals
  distinguish an absent family from a measured zero, so a signal nothing
  has ever incremented reads as "not reported" rather than as a healthy
  zero, and a scrape that did not answer reads as "unavailable" rather
  than dropping the row, and the CORS copy names the single reason the
  counter covers (`wildcard_with_credentials`) rather than letting a low
  total read as "every cross-origin request was allowed". See the
  Overview and Guardrails sections of
  [docs/admin-ui.md](docs/admin-ui.md).

- **A pre-provider AI gateway refusal now reaches the SIEM as a typed
  decision.** A `/v1/responses` body carrying `tools: [{"type": "mcp",
  ...}]` asks the model provider to reach an MCP server directly, behind
  this gateway's MCP governance. The gateway already refused it, but the
  only trace was a free-text warn and a bare 400, which reads in a
  metrics store exactly like a typo'd JSON body. Five refusal arms now
  publish `ai.admission`, a nineteenth decision event: the three of the
  inbound native-format shim (the Anthropic Messages translate, the
  Responses stored-prompt bridge, and the Responses translate) and the
  two of the shared stored-prompt resolver (a template that fails to
  render, and a reference on a native surface that no prompt layer
  holds), enabled with
  `observability.log.decision_audit.events.ai.admission: true`. Each
  record carries `surface` (`messages` or `responses` for a shim
  refusal, and the surface the request arrived on for a resolver
  refusal, `chat_completions` included) and `verdict`, a bounded reason
  code such as `tools_mcp_unsupported`,
  `previous_response_id_unsupported`, `store_unsupported`, or
  `prompt_object_unresolved`, and the matching series lands on
  `sbproxy_ai_admission_decisions_total{surface, reason, outcome}`. The
  refusal message is deliberately not carried on either: several codes
  interpolate caller bytes into it, and neither a metric label nor a
  decision record's structured detail is scrubbed. Coverage is those
  five arms only; a request refused later by a model gate, a guardrail,
  a budget, or a policy still records under that plane's own event.

- **AWS SigV4 request signing for Bedrock and SageMaker.** A new
  `aws_sigv4:` block on a `providers[]` entry makes SBproxy compute the
  `Authorization: AWS4-HMAC-SHA256 ...` header for each outbound
  request, so Bedrock and SageMaker work without a signing sidecar or a
  hand-rotated session token. `region` is required and is the credential
  scope, independent of `base_url` the same way an AWS SDK's
  `endpoint_url` override is, and it fills the `{region}` placeholder in
  the provider catalog when `base_url` is unset. Credentials come from
  the standard AWS provider chain by default, or from an explicit key
  pair (`source: static`) or an STS role session (`source: assume_role`)
  renewed 900 seconds before expiry, with a 600-second window in which a
  failed refresh is logged rather than fatal. Secret fields
  (`secret_access_key`, `session_token`, `external_id`) are dereferenced
  at config load through `${VAR}`, `vault://`, `awssm://`, `secret://`,
  and `file:`, an unresolvable reference is a hard error rather than a
  value AWS rejects later, and the resolved bytes are held in a type
  that renders `[REDACTED]` and zeroes on drop. An unusable `aws_sigv4:`
  block is refused at config load, so `sbproxy validate` catches it.
  Signing happens at the transport boundary, so it re-runs on every
  retry and every redirect hop rather than replaying a signature bound
  to the previous host. A signed provider sends no `api_key`; setting
  both is refused at config load. Active health checks are skipped for
  signed providers, since `bedrock-runtime` has no signable liveness
  route. See the `aws_sigv4` section of
  [docs/providers.md](docs/providers.md) and
  [examples/ai-bedrock-direct/](examples/ai-bedrock-direct/).

- **Bedrock guardrails inline on the Converse call.** A Bedrock provider
  entry can now set `bedrock_guardrail: {identifier, version, trace}`,
  which attaches `guardrailConfig` to the `Converse` request so AWS
  evaluates the prompt and the completion inside the generation instead
  of through a separate `ApplyGuardrail` call. Bedrock answers an
  intervention with a 200 and `stopReason: guardrail_intervened`, which
  previously relayed to the caller as a successful empty completion;
  SBproxy now turns it into a 403 `guardrail_violation` under the
  guardrail name `bedrock_guardrail`, records it on the
  `ai.guardrail.output` decision feed, counts it as
  `sbproxy_ai_external_guardrail_verdicts_total{provider="bedrock_inline",
  outcome="block"}`, flags the billed tokens as `validation_failed`
  waste, and writes nothing to the semantic cache or the idempotency
  store. The block reason names the policy types and your own topic and
  regex names, never the matched span, because a Bedrock assessment
  quotes the caller's own text. The intervention is read off every
  Bedrock response, not only off routes that set the new key: a
  guardrail attached to the model or profile outside SBproxy produces
  the same `stopReason`, and relaying that as a 200 was the bug. If you
  run Bedrock today and see a `guardrail_intervened` response, it
  becomes a 403 on upgrade; see
  [docs/config-stability.md](docs/config-stability.md#a-bedrock-guardrail_intervened-response-is-now-a-403).
  The key is refused at config load on any non-Bedrock provider, and a
  route that also configures `guardrails.external[]` with `provider:
  bedrock` gets one warning at load: both are legal, and AWS bills each
  evaluation. There is no failure posture, because a bad guardrail
  reference fails the generation call itself. Streaming requests are
  guarded upstream and the client sees `finish_reason: content_filter`,
  but they get no decision record. See
  [docs/guardrails.md](docs/guardrails.md#bedrock-guardrails-inline-on-the-converse-call).

- **Evidence records name the process that minted their sequence
  number.** `mcp_governance_decision` records now carry
  `sbproxy.evidence.instance` beside `sbproxy.evidence.seq`. The
  sequence counter lives in proxy memory and starts every tenant at 1,
  so two replicas serving one tenant each emit 1, 2, 3 and a restarted
  replica emits 1 again after reaching 901: a SIEM grouping on the
  tenant alone could neither find a hole nor deduplicate, and read a
  restart as a 900-record rollback. The guarantee is now stated as what
  it always was, gapless per `(sbproxy.evidence.instance,
  sbproxy.tenant.id)`, and rules that group on the tenant alone should
  add the instance. One case stays undetectable and is now documented as
  such: a run whose tail was cut off looks the same whether the replica
  was killed mid-stream or shut down cleanly. The proxy also has one
  instance identifier now instead of three. The alert webhook envelope,
  the callback webhook envelope, both surfaces' `x-sbproxy-instance`
  header, and `sbproxy.evidence.instance` each derived their own from
  the same host-plus-random-tag recipe, so one running proxy stamped
  three different strings under one name and a receiver could not join
  them. They all read the same value from today. See
  [docs/events.md](docs/events.md) and
  [docs/mcp-security.md](docs/mcp-security.md).

- **A Mesh Admission and Storage dashboard, and alerts on both halves.**
  `mesh_transport_inbound_rejected_total` and the two storage families
  `sbproxy_storage_op_duration_seconds` and
  `sbproxy_storage_op_errors_total` shipped with no panel and no rule on
  any of the three dashboard trees, and all thirty-four `mesh_*`
  families were uncharted: the one file that claimed to cover them,
  `crates/sbproxy-observe/dashboards/mesh-overview.json`, spells every
  metric `sbproxy_mesh_*`, which is not a sanctioned prefix and matches
  nothing. The new `dashboards/grafana/sbproxy-mesh-storage.json` charts
  the inbound refusal counter twice, once split by `reason` and once
  regrouped so each line names one thing an operator can change (the
  connection cap, mesh mTLS, or the peer), plus storage latency
  percentiles overall and per operation, errors by `error_kind` and by
  operation and record kind, throughput, and an error ratio taken
  against the latency histogram's `_count` series, which is observed on
  success and failure alike and so is genuinely bounded to 0 and 1.
  Neither family is zero on a deployment that does not run the mesh with
  its Redis backend; both are absent, and the mesh Redis backend is
  still the only production caller of the storage layer. Two header
  tiles say which case you are looking at, one from `mesh_node_isolated`
  and one an `absent()` check on the storage histogram, and every panel
  carries a no-data string instead of drawing a flat line at zero.
  `SBPROXY-MESH-INBOUND-REJECTED` (ticket, runbook `RB-MESH-ADMISSION`)
  fires off a recorded series that excludes `idle_timeout`, because the
  client half of the transport recycles a connection only when it next
  sends, so a quiet cluster reclaims idle peer connections by itself and
  an alert covering all six reasons would page on housekeeping.
  `SBPROXY-STORAGE-BACKEND-ERRORS` (ticket, runbook
  `RB-STORAGE-BACKEND`) groups by `error_kind` so a disconnected backend
  surfaces on its own, which is the rule
  `crates/sbproxy-storage/src/metrics.rs` has asked for in its module
  docs since it was written. A promtool test covers a connection-limit
  burn, the idle-reclaim control that must stay silent, a five percent
  disconnected rate, and an all-healthy control.

- **Admin console: inbound peer admission on Cluster, storage backend
  operations on Storage.** Three metric families that shipped with live
  writers were named nowhere in the console, so nothing rendered them
  and the only record of what they counted was a log line. Cluster now
  carries an **Inbound peer admission** panel reading
  `mesh_transport_inbound_rejected_total` off this node's own scrape
  rather than the fleet aggregate, since the node a refusal landed on is
  the part an operator can act on: peers turned away, connections closed
  at the inbound ceiling, idle connections reclaimed, and every `reason`
  listed with what it means. `idle_timeout` is counted apart from the
  refusal total on purpose, because a quiet cluster reclaims idle links
  by itself and folding those in makes an idle fleet look under attack;
  alert on `reason!="idle_timeout"`. Storage now carries a **Storage
  backend operations** panel reading
  `sbproxy_storage_op_duration_seconds` and
  `sbproxy_storage_op_errors_total`: operations completed, operations
  that returned an error, p95 across every backend and operation, the
  slowest `backend / op` pair, and failures by error kind. Both panels
  distinguish an absent family from a zero one. All three counters
  register lazily on first use, so a node that has refused nothing, or
  on which no backend has run, publishes no family at all and the panel
  says the counter is not reported rather than drawing a healthy-looking
  zero over a signal nobody has observed. The reverse case is stated
  too: a present latency histogram with no error counter is a true zero,
  because the error counter only increments on failure. Both panels read
  the `/metrics` scrape the console already consumes; no admin route was
  added. See [docs/admin-ui.md](docs/admin-ui.md).

- **Token limits, aliases, and groups on `GET /v1/models`.** Each listed
  model now carries `context_window` and, where a rate card declares
  one, `max_output_tokens`, resolved through the same lookup the
  `ai.catalog` routing base data reads, so a policy and a client are
  never told different numbers for one model. Both fields are omitted
  rather than nulled when this process was not told the limit. The
  LiteLLM rate card parser used to read the two cost keys and discard
  `max_input_tokens` and `max_output_tokens`; it now carries both, for
  every entry in the card rather than only the priced ones, so an
  embeddings or image model publishes its window too. The listing also
  gained the names it was missing: a `model_aliases` entry is listed
  under its own name with the facts of the id it resolves to, gated on
  that resolved id so an alias is never a way around `blocked_models`,
  and a `model_groups` entry is listed with the union of its members'
  capabilities and the floor of their windows, because a prompt has to
  fit whichever member serves it. Every entry now carries `created`,
  which the OpenAI `Model` object declares required and without which an
  SDK-shaped client refuses to deserialize the response; the gateway
  does not know a publication date and emits the epoch constant rather
  than inventing one. `ai.catalog` gained `max_output_tokens` from the
  same resolution, and its `context_window` now falls back to the rate
  card's `max_input_tokens`, so a policy writing `ai.model in
  ai.catalog` can now match a declared model that only the rate card
  knows and that carried no price. See the model discovery section of
  [docs/ai-gateway.md](docs/ai-gateway.md).

- **Shadow evaluation against more than one target.** `shadow:` now
  takes a `targets:` list, so one route can compare a primary against
  several candidate providers at once. The single-target `shadow:
  {provider: ...}` form still parses and means a one-entry list; an
  empty `targets:` list and two entries naming the same provider are
  both refused at config load, because the provider name identifies the
  target on every metric and every ledger row. Each target takes its own
  slot out of the same 16-task and 64 MiB admission ceiling, so a shared
  bound cannot be multiplied by editing a config list; a target that
  cannot get a slot is dropped as `saturated` while the others run.
  Sampling draws once per request and every target compares against that
  same draw, so target populations nest instead of diverging: everything
  a `sample_rate: 0.1` target saw, a `0.5` target on the same route also
  saw, which is what makes two targets comparable. Two new metric
  families, `sbproxy_ai_shadow_calls_total{target, status_class,
  finish_reason}` and `sbproxy_ai_shadow_latency_seconds{target}`,
  report per-target outcomes. See
  [docs/ai-gateway.md](docs/ai-gateway.md#shadow-eval) and
  [examples/ai-shadow/](examples/ai-shadow/).

- **Named model groups.** A `model_groups:` block on an `ai_proxy`
  action binds one public model name to several deployments, each naming
  a provider, the upstream model id that provider serves, and its share
  of traffic. Members may serve *different* model ids, which is what the
  same-model-name pool could never express: one group can front an
  OpenAI model and an Azure deployment name at once. Each group carries
  its own `routing:` and its own rotation cursor, independent of the
  action's, so two groups never interleave each other's round robin and
  a `weighted` group splits by member weight rather than by provider
  weight. A group resolves on the dispatch path at the point a
  `model_aliases` entry does, before every gate, so `blocked_models`,
  the credential's allowlist, the per-model rate limiter, the budget
  scope, and the price ceiling all judge the member's real model id and
  never the group name. The pick is resilience-aware: an open circuit
  breaker, an outlier ejection, or a failed health probe moves traffic
  to a sibling member instead of refusing. A group with no member left
  to pick refuses rather than routing to a provider nobody named: `403`
  when the credential's provider policy forbids every member, `503` when
  every member's provider is switched off. Either refusal logs the group
  name and publishes an `ai.admission` decision record carrying
  `model_group_forbidden` or `model_group_no_member`, so it reaches the
  SIEM feed rather than only the client. Thirteen selection strategies
  are accepted per group; `cascade`, `cost_quality`, `race`,
  `semantic_route`, `prefix_affinity`, and `token_rate` are refused at
  config load, because each dispatches through its own action-level path
  a per-group pick never reaches. Config load also refuses a group that
  shadows a served model, a `model_map` key, a `default_model`, or an
  alias; an alias that resolves to a group; two members on one provider;
  a member the provider does not serve; and an all-zero weighted split.
  Groups appear on `GET /v1/models` and on the LiteLLM-parity `GET
  /model_group/info`, the latter with per-member provider, model, and
  weight. Every pick increments
  `sbproxy_ai_model_group_selections_total{group, provider}` and writes
  a `model_group: <name> -> <provider>/<model>` reason on the admin
  routing row. See the model groups section of
  [docs/ai-gateway.md](docs/ai-gateway.md) and
  [examples/ai-model-group/](examples/ai-model-group/).

- **Nine AI routing and reliability metrics are now on a dashboard, and
  one of them alerts.** The AI Gateway board
  (`dashboards/grafana/sbproxy-ai-gateway.json`) gains a routing and
  reliability section covering
  `sbproxy_ai_stream_post_commit_failures_total` by cause and by
  per-provider share, `sbproxy_ai_key_fallbacks_total` by provider and
  outcome, `sbproxy_ai_model_group_selections_total` by group and
  member, `sbproxy_ai_cache_affinity_decisions_total` drawn against
  `sbproxy_ai_cache_affinity_evictions_total` on one axis,
  `sbproxy_ai_service_tier_decisions_total` by disposition,
  `sbproxy_ai_request_timeout_override_total` by outcome, and
  `sbproxy_ai_shadow_calls_total` and
  `sbproxy_ai_shadow_latency_seconds` by target. Five of those families
  are absent rather than zero until the feature behind them is
  configured, so four `absent()` tiles head the section reading `In use`
  or `Not in use` and every panel sets a `noValue` string saying which
  kind of emptiness it is showing. A new ticket-tier alert,
  `SBPROXY-AI-STREAM-POST-COMMIT`, fires when more than 1% of one
  provider's accepted responses fail part way through the stream for 15
  minutes. That failure is invisible everywhere else: response headers
  already carried a 200, so the availability SLO scores it a success,
  and failover is impossible past the commit point, so the caller is
  handed a truncated body with nothing in the response saying so.
  Guardrail terminations are excluded, because those are the gateway
  enforcing what it was configured to enforce. See
  [RB-AI-STREAM-POST-COMMIT](docs/operator-runbook.md#rb-ai-stream-post-commit)
  and [SLO-AI-STREAM-COMMIT](docs/observability.md).

- **Per-request timeout overrides, behind an operator opt-in.** A caller
  can send `x-sbproxy-timeout-ms` to replace the selected provider's
  `timeout_ms` for one request, but only on an `ai_proxy` origin that
  sets `allow_request_timeout_override: true`, and only up to that
  origin's `max_request_timeout_ms`. Both default off, and the flag
  without a ceiling is refused at config load rather than defaulted,
  because an unbounded caller timeout is the failure the gate exists to
  prevent. With the flag off the header is ignored rather than refused,
  so a caller hitting a fleet where only some origins opted in does not
  collect 400s from the rest; the drop is counted on the new
  `sbproxy_ai_request_timeout_override_total{outcome}` alongside
  `applied`, `over_ceiling`, and `invalid_header`. A header above the
  ceiling, or one that is not a positive whole number of milliseconds,
  is refused with 400 `invalid_request_timeout` naming the accepted
  range rather than silently clamped, so a caller does not build a retry
  schedule on a budget it never got. The honored budget rides a
  per-request clone of the AI client, so the race legs, cascade tiers,
  and every retry attempt inherit it; the gateway's own semantic-cache
  embeddings, semantic-route embeddings, and shadow copies deliberately
  do not, and neither does a `managed_model` served by another node in a
  cluster, which dispatches over the model plane. An honored header
  replaces the gateway's 30-second HTTP client default as well as the
  provider's `timeout_ms`, so the ceiling is the only thing bounding how
  long one caller can hold a connection open. The ceiling bounds one
  attempt, so `max_retries` and the candidate count multiply it. See
  [docs/ai-gateway.md](docs/ai-gateway.md) and
  [docs/headers-reference.md](docs/headers-reference.md).

- **Pre-provider AI refusals are now on a dashboard and on an alert.**
  `sbproxy_ai_admission_decisions_total` counts requests the gateway
  refuses at the inbound native-format shim or the shared stored-prompt
  resolver, before it dials any provider. Because nothing upstream is
  contacted, those requests were invisible on every panel of the AI
  Gateway dashboard: no provider error, no latency, no tokens, no cost.
  An operator watching a client integration break saw traffic quietly
  disappear. Three panels close that. "Pre-provider Refusals by Reason"
  breaks the refusals down by bounded reason code, which is the label
  that names the fix. "Pre-provider Refusal Share by Surface" divides
  the refusals by `sbproxy_ai_surface_requests_total` on the same
  `surface` label, an exact join because the surface counter increments
  on arrival, and marks the 5 percent line the alert files at. "AI
  Requests Arrived, Dispatched, and Refused" puts arrivals, provider
  dispatches, and refusals on one axis so a gap that this funnel cannot
  explain is visible as a gap. Both refusal panels declare a "no data"
  string rather than drawing a zero: the metric family is registered on
  first use, so an empty panel means no request has been refused since
  start, not a broken scrape. A new recording rule,
  `sbproxy:ai:admission_refusal_share:5m`, and a ticket-tier alert,
  `SBPROXY-AI-ADMISSION-REFUSAL-SHARE`, fire when more than 5 percent of
  one surface's arriving traffic is refused for 15 minutes, with a
  `RB-AI-ADMISSION` runbook section that sorts the reason codes into
  caller-side, prompt-layer, and malformed-body fixes. This is the one
  class of AI failure the availability SLO cannot see: a refusal answers
  4xx, so `sbproxy:slo:substrate:availability` reads 1.0 the whole time.
  The alert ships with a promtool unit test carrying a firing case and
  two controls, one of which pins that an absent refusal family records
  no series rather than a healthy zero, and
  `scripts/check-prometheus-rules.sh` now globs every test file instead
  of naming one.

- **Prompt-cache affinity.** A new `cache_affinity:` block on an
  `ai_proxy` action routes a caller's repeated requests back to the
  provider that already holds their warm prompt cache, so the cached
  prefix is billed at the vendor's discount instead of being re-sent at
  full price to whichever provider came next in the rotation. It keys on
  the caller's own `prompt_cache_key`, or `user` when that is absent,
  and never writes either field; a request that sends neither is routed
  by the configured strategy alone. It is not a routing strategy: it
  layers over whatever `routing.strategy` is set, `round_robin`
  included, and only moves a live lease holder to the front of the order
  that strategy produced. The four strategies that own their ordering
  outright are left alone, and record no lease: `fallback_chain`,
  `cascade`, `cost_quality`, and a `routing_policy` plan. It is a
  preference, never a pin, so an unhealthy, breaker-open, ejected, or
  policy-ineligible holder is skipped and a lease recorded against a
  different resolved model is dropped rather than followed. The lease
  identity is a digest over the tenant, the credential, the origin, the
  API surface, and the caller's key, so one tenant's key can never steer
  another's routing. `ttl_secs` (default 300) and
  `max_keys_per_provider` (default 1024) bound the process-local table
  and are refused at zero; the block sits beside `routing:` and is
  refused with an explanatory error if written inside it.
  `sbproxy_ai_cache_affinity_decisions_total{outcome}` reports `hit`,
  `miss`, `missing_signal`, `ineligible`, and `model_changed`, and
  `sbproxy_ai_cache_affinity_evictions_total{reason}` reports `ttl`,
  `capacity`, and `model_changed`. See the prompt-cache affinity section
  of [docs/ai-gateway.md](docs/ai-gateway.md).

- **Provider eligibility by data-handling posture (ZDR / data-retention
  allow-deny).** Every provider-catalog entry now declares a
  `data_posture` block (`retains_data`, `zdr_available`, optional
  `data_region`), seeded for every entry from each vendor's published
  data-processing terms and pessimistic where no commitment is
  published. A `data_posture:` block on an `ai_proxy` action
  (`require_zdr`, `allow_data_collection`), or the per-request
  `x-sbproxy-require-zdr` / `x-sbproxy-disallow-data-collection`
  headers, gates provider eligibility as a hard candidate-set filter
  ahead of every routing strategy, fallback order, cascade tier, race
  fan-out, shadow dispatch, model listing, realtime session admission,
  and the semantic cache's embedding call. `/v1/messages` and
  `/v1/responses` are gated identically, because both reach routing as
  the canonical chat body. A request left with no eligible provider
  fails closed with a `no_posture_eligible_provider` error naming the
  constraint and the excluded providers, and an origin whose own block
  excludes every provider it configures is refused at config load rather
  than left to deny every request at runtime.

- **Provider-key failure fallback, with an explicit per-entry opt-out.**
  An AI provider entry can now name an operator-held credential to retry
  on when the provider refuses that entry's own `api_key` with a `401`
  or `403`. Two keys on `providers[]`: `fallback_credential_id`, naming
  a record under `key_management.seed.credentials[]` rather than a
  second secret written into the origin, and `on_key_failure`
  (`fallback`, the default, or `fail_closed`). Before this, a credential
  rejection was terminal: it is not retryable, it opens no availability
  failover, and it reached the caller verbatim. The retry is once per
  request, against the same provider, and it does not spend the
  availability budget. It never fires for a caller-owned native
  credential: the caller presented their own key and the provider
  refused it, so spending the operator's would bill the operator for
  someone else's authorization failure. The fallback credential resolves
  per request through the key plane, so it picks up a rotation with no
  config reload and is refused across tenants; when it does not resolve,
  the provider's own rejection stands and the warn names the credential
  id, never the material. A new `credential_fallback` typed event
  carries the provider, the credential id, the status, and `outcome`
  (`engaged` or `unavailable`); the same pair is scrapeable as
  `sbproxy_ai_key_fallbacks_total{provider,outcome}`, and `unavailable`
  is the one to alert on, because a broken house credential otherwise
  looks exactly like a broken tenant key. A new `credential_source`
  field (`provider_entry`, `native_caller`, `fallback`) lands on the
  admin request row and the usage ledger as the outbound counterpart to
  `key_mode`. Key fallback owns `401`/`403` and nothing else; a `429`, a
  `5xx`, or a timeout stays with the provider failover and
  `cooldown_policy`, because a different key against a rate-limited
  provider is still rate limited. See
  [docs/multi-tenant.md](docs/multi-tenant.md#when-a-tenants-provider-key-is-refused)
  and [examples/tenant-key-fallback/](examples/tenant-key-fallback/).

- `sbproxy connect` points the coding agents installed on this machine
  at the gateway, and `sbproxy disconnect` puts them back. It detects
  Codex, Claude Code, Cursor, Cline, and Copilot; writes
  `$CODEX_HOME/sbproxy.config.toml` as a Codex profile of its own (never
  your `config.toml`) through a temp file and a rename, after taking a
  one-time `.sbproxy.bak` copy; and prints the exports or
  settings-screen fields for the rest. `disconnect` copies the profile
  to `<path>.sbproxy.removed` before it unlinks it, so a hand edit made
  after connecting survives the removal that the `.sbproxy.bak`, which
  holds the file as it was before the first `connect`, was never going
  to hold. `--dry-run` shows the unified diff and writes nothing. No
  credential is read or written: the config names the environment
  variable each client reads its key from. The four per-editor connect
  pages collapse into `docs/use-case-connect-coding-agents.md`.

- **The Security dashboard covers CORS refusals, RFC 9421 legacy
  signature derivation, and certificate-store degradation, and a
  degraded certificate store now alerts.** All three families shipped
  with no panel, and the two counters and the one gauge go wrong in
  three different ways if they are all charted as a flat line at zero.
  `sbproxy_cors_refusals_total` is broken out by `reason`, because a
  refusal count with no breakdown does not tell an operator what to fix;
  the only value today, `wildcard_with_credentials`, names a config that
  was applied before that pairing became a compile error and is still
  running. `sbproxy_signature_legacy_derivation_total` gets both a
  per-component rate and a 24h count, since the number that decides
  whether the compatibility fallback can be removed is the one that has
  to hold at zero across a full traffic cycle, weekly and monthly batch
  callers included, not the one that is quiet this afternoon.
  `sbproxy_cert_store_degraded` is a gauge and is queried as one, with
  no `rate()`, and its panel carries a second `absent()` series: the
  family is published only by a proxy that has an `acme` block, so an
  absent series is a deployment that does not terminate TLS and is not a
  healthy zero. `SBPROXY-CERT-STORE-DEGRADED` (ticket, runbook
  `RB-CERT-STORE-DEGRADED`) fires off `max by (backend)` of that gauge
  so one degraded pod in a fleet is not averaged away, and a promtool
  test covers the one-of-two-pods case, the all-healthy control, and the
  family-absent control.

- **`semantic_route`: semantic (embedding-similarity) AI routing.** A
  new AI gateway routing strategy that routes on what the request means:
  each deployment declares its specialty as exemplar prompts or
  precomputed centroids, the proxy embeds the request's final user
  message through the configured embedding source (the semantic cache's
  `provider` / `sidecar` / `openai` source shapes), and the best cosine
  match above `min_similarity` pins that deployment. Below-floor scores,
  promptless requests, and embedder failures all fall to the declared
  `fallback` deployment (or round-robin), counted on
  `sbproxy_ai_semantic_route_decisions_total{outcome}` and
  `sbproxy_ai_routing_fallbacks_total`, never failing the request. A
  missing embedding source or an unknown deployment name refuses at
  config compile. Routing embeds are metered through the origin's
  `quota_pool` like every other embedding call, and the exemplar index
  is bounded: one build at a time, at most 256 exemplars, and a failed
  build is negatively cached behind a retry floor that doubles from 30s
  to 300s, so an unreachable embedder cannot turn each request into an
  N-call amplifier. See the `semantic_route` section of
  [docs/ai-gateway.md](docs/ai-gateway.md) and
  [examples/semantic-routing/](examples/semantic-routing/).

- **Shadow usage rows carry `shadow_of` and `finish_reason`.** A shadow
  evaluation's ledger row had no way back to the request it evaluated,
  so cost and latency per target could be totalled but not compared
  against the primary they mirrored. Rows now carry `shadow_of`, the
  primary's request id, as the join key, and `finish_reason`, which the
  shadow path already parsed and then discarded and which is the
  cheapest disagreement signal there is: one target stopping on `length`
  where another stopped on `stop` truncated its answer, and no cost
  comparison says that. `finish_reason` is a shadow-row field; the
  primary's finish reasons stay on the request span as
  `gen_ai.response.finish_reasons`, so comparing a target against the
  primary on that axis joins the ledger to the trace. `shadow_of` is
  carried as data and never as the ledger's dedup key, because the
  correlation-id feature lets a caller choose the primary's request id
  and a derived key would let one caller suppress another caller's rows
  on replay. Both fields are absent on ordinary completions. Shadow
  response *text* is still drained rather than retained, so what this
  compares is numbers, not answers.

- The **Spend console** now answers what a period cost against the
  period before it, where the money went, what the gateway saved, and
  how much of the figure is measured. `GET /api/usage/spend` is called
  twice, once for the selected window and once for the equal-length
  window before it (a new `from`/`to` client call over the same route,
  no server change), so every figure above the fold is windowed and
  durable: spend against the prior period, a run rate in dollars per day
  with its basis window printed on the tile, unattributed spend promoted
  from a table row to a headline, and blended cost per million tokens.
  The chart is a two-series line of this window against the last with a
  per-bucket and cumulative toggle, re-bucketed client-side to between
  24 and 40 points so a 30 day window stops rendering 720 rows. The
  breakdown carries share of window, dollar delta per row with `new` and
  `gone` marked rather than shown as a zero, cost per million tokens,
  and requests blocked before dispatch, and it groups by every dimension
  the rollup accepts, with `tenant` and `agent` added to the selector.
  Three panels below read the metrics scrape that no console view read
  before: realized savings per lever from the semantic cache and context
  compression, per-key budget headroom with money held in reserve as its
  own bar segment, and a trust panel showing price provenance,
  price-ceiling outcomes, and signed estimator error per model. Absent
  is never rendered as zero: every block branches on whether the metric
  family exists, so an unconfigured cache reads "not reported" while a
  configured one that saved nothing reads `$0.00`. Two figures are
  deliberately withheld and say so on the page: the dollars avoided by
  refused requests, which nothing accumulates, and any per-key savings
  total, which no attribution supports. See the Spend section of
  [docs/admin-ui.md](docs/admin-ui.md).

- **Typed fallback triggers: `context_window_fallbacks` and
  `content_policy_fallbacks`.** Two new lists on the `ai_proxy` action,
  siblings of `routing:`, each naming providers to reroute to for one
  specific failure class. A chat prompt whose pre-flight token estimate
  overflows the primary model's context window reroutes to a
  larger-window provider before anything dispatches (streaming
  included); a content-policy refusal reroutes to the aimed list instead
  of the generic chain's next provider. Unknown provider names fail
  config load, and nesting either key inside `routing:` or inside
  `resilience:` is refused rather than silently ignored (the singular
  `resilience.content_policy_fallback` boolean remains a real key
  there). A new `resilience.cooldown_policy` maps the same failure
  classes to provider cooldown seconds (a `429` can park a provider for
  30s), fed directly by the dispatch loop's failure classification.
  Provider cooldowns are counted on
  `sbproxy_ai_provider_cooldowns_total{provider, cause}`, so a fleet
  quietly parking providers is alertable. The admin request log gains a
  `failover_trigger` column (`context_window`, `content_policy`, or
  `generic`) and the LogsView failover badge names the trigger. See the
  typed fallback triggers section of
  [docs/ai-llm-aware-resilience.md](docs/ai-llm-aware-resilience.md) and
  [examples/typed-fallbacks/](examples/typed-fallbacks/).

- **Zone-aware target selection.** The load balancer prefers targets
  whose `targets[].zone` matches the proxy's own zone and spills across
  zones, per request, only when no same-zone target is healthy, so
  cross-zone traffic is a failover path rather than a steady state. The
  proxy's zone comes from a new `proxy.zone` key, with the `SB_ZONE`
  environment variable as the fallback (config wins); a proxy with no
  zone identity selects exactly as before and warns at boot when zone
  labels are authored anyway. Locality runs as a narrowing stage between
  the health filters and the priority filter, so it composes with every
  algorithm, registered strategy, and deployment mode;
  `locality.min_pool_size` (default 2) deactivates it for small pools.
  The admin surfaces show the mechanism working: `GET
  /api/health/targets` reports `proxy_zone`, per-origin `local_zone`,
  and each target's `zone`, and `GET /api/requests` entries carry a
  `zone_locality` verdict (`local` or `spilled`). The same verdict is on
  the access log as a `zone_locality` field and on a new
  `sbproxy_lb_zone_locality_total{origin, verdict}` counter, so
  `rate(sbproxy_lb_zone_locality_total{verdict="spilled"}[5m]) > 0`
  alerts on a cross-zone spill without the admin server enabled. Both
  are absent, rather than empty, on a request the locality stage never
  engaged for. This also reverses the short-lived compile refusal of
  `targets[].zone`: the key is back, now that it routes. See the
  zone-aware routing section of [docs/routing.md](docs/routing.md) and
  [examples/multi-zone/](examples/multi-zone/).

- A new `abtest` action splits traffic across weighted backend variants,
  with a sticky cookie pinning a returning client to its first
  assignment.

- A new `ai_schema` transform validates AI provider responses against an
  operator-supplied schema, with a `block`/`warn`/passthrough
  `on_failure` mode independent of the pipeline's shared failure
  posture.

- A new `https_proxy` action relays a request to its own resolved host,
  allow-listed by `allowed_hosts`, for wildcard origins that want to
  narrow which hosts actually get proxied.

- A new `license_leak` output guardrail scores AI responses against an
  operator-supplied corpus of licensed documents and blocks, warns, or
  logs on a confident match.

- A new `pdf_markdown` transform (behind the opt-in `transform-pdf`
  cargo feature) projects an `application/pdf` response body into
  Markdown, the same shape `html_to_markdown` produces.

- MCP `tools/call` requests can now be governed by a Cedar ABAC policy
  (`cedar_policies:` on the `mcp` action), running alongside the
  existing RBAC `tool_access` gate rather than replacing it.

- New `sbproxy-federation` crate: OpenID Federation 1.0 entity
  statements, JWS sign and verify, RFC 7638 key thumbprints, a
  well-known issuer, and a trust-chain resolver, backed entirely by
  in-process memory (no Postgres, sqlx, or Redis dependency).

- New `sbproxy-licensing` crate: IAB CoMP marketplace bridge (manifest,
  signed quote, redeem), minting license tokens in the OSS OLP wire
  format on redeem so they verify against an origin's own
  `/.well-known/olp/introspect`; no Postgres, ClickHouse, or NATS
  dependency.

- New `sbproxy-mcp-gateway` crate: a standalone MCP OAuth 2.1 broker
  (PKCE, DPoP, mTLS-bound tokens, device-code grant, RFC 8707/8693/7591)
  plus a resource-server companion, both backed by an in-process store
  with Redis as the optional multi-replica backend.

- Ported `sbproxy-classifier`, a rich multi-tenant classification
  sidecar (gRPC + TCP/MessagePack) with quality scoring, PII-redacting
  normalization, intent/content-type detection, and per-token streaming
  safety, plus a `FallbackClassifier` in `sbproxy-classifier-client`
  that degrades to the existing in-process ONNX classifier when no
  sidecar is deployed or reachable.

- Two new policies, `geoip` and `user_agent_parser`, resolve client
  geography and parse the User-Agent header into typed data for identity
  and anomaly hooks, and optionally as X-Geo-*/X-Parsed-Ua upstream
  headers.

- Added the bounded live AI toolkit: scoped governed agent workflows,
  immutable offline-evaluation datasets, stable weighted prompt
  rollouts, authenticated admin and CLI operations, typed content-safe
  events, one closed-cardinality Prometheus family, Grafana panels, and
  no-Redis examples.

- New `sbproxy_classifier_client_fallback_total{reason}` counts every
  classifier call the proxy served from its in-process fallback, and the
  matching warning is held to one line per reason per 60 seconds.

- **The AI request span carries `sbproxy.ai.intent`.** The detected
  intent category was recorded on an undeclared field, which the tracing
  core dropped, so it reached neither a span exporter nor a trace
  backend. It now sits on the request span under the same spelling the
  access log uses.

- A buffered AI response records `usage_source` on the access log the
  same way a streamed one does, so filtering for invoiceable rows no
  longer drops every non-streaming AI request.

- A colocated MCP OAuth broker is visible to an operator. `GET
  /admin/mcp-oauth` on the proxy admin API reports every `mcp` action
  carrying an `oauth.broker` block, what each has wired in, and whether
  a resource server is configured to check the tokens it mints. The
  broker own `GET {base_path}/admin/status` stays unmounted in process,
  because that route tree sits on the public MCP origin ahead of the
  resource-server check; this is the same JSON behind operator auth,
  matching what `GET /admin/federation` does for the federation half.

- **A credential provider lock on an AI cascade is now visible to the
  caller, the admin console, and Prometheus.** A cascade that dispatched
  no tier because the credential's `provider` policy excluded every one
  of them used to be indistinguishable from a dead upstream on every
  surface. The `502` now carries the RFC 9209 error token
  `credential_provider_locked`: on `Proxy-Status` where the origin sets
  `proxy_status.enabled: true`, and in the problem document's `detail`
  field where it sets `problem_details.enabled: true`. Both surfaces are
  opt-in, as they already were for every other error token, and an
  origin with neither still returns the plain `bad gateway` body. The
  token is all the caller is told, so no policy contents, key ids, or
  provider names cross the boundary. The request's admin Routing
  Decisions row carries the reason, metering classifies it as a policy
  denial rather than an upstream failure, and the refusal reaches a
  configured `events:` sink as a `policy_denied` record.
  `sbproxy_ai_cascade_tier_outcomes_total` gains the closed `outcome`
  values `credential_lock`, `data_posture`, `disabled`, `not_found`, and
  `unhealthy`, all of which used to be filed under `retry` alongside
  real dispatch failures; `retry` still counts every tier that
  dispatched and did not produce an accepted response, so existing
  alerts on it are unchanged.

- Added a shared embedded state store, a `PersistentKv` and
  `EphemeralKv` pair backed by redb, so subsystems that need durable
  state get one ACID store rather than a database dependency each. Every
  operation runs on tokio's blocking pool, since a redb write ends in an
  fsync and holding an executor thread through one stalls whatever else
  it was scheduled to run. Metric families across the new modules
  register without `expect`, so a duplicate or malformed family name
  logs an error rather than panicking inside whichever request first
  reached the new code path.

- Added `proxy.agent_registry`: an owner-approval queue for agents that
  register themselves, plus a signed agent catalog verified with Ed25519
  over canonical JSON, both on one embedded store with no database
  behind them. A reviewer's decision is durable and keyed on the
  fingerprint of the description they decided about, so a rejected or
  revoked registration is refused for good and an approved description
  cannot become a second agent with its own credentials. The admin
  surface honors the operator tenant from `proxy.admin.operators`: a
  tenant-scoped operator sees and acts only inside its own tenant, and
  the deployment-wide catalog listing and feed refresh are refused
  rather than silently narrowed. The configured feed is read at boot and
  on a timer derived from `stale_grace_secs`, the catalog reports on
  `/readyz` as `agent_catalog`, and the whole block is boot-only: a
  reload that changes it is refused by name rather than accepted and
  ignored. Decisions publish an `agent_registration_decided` event and
  appear on a new Agents page in the admin console.

- Added `proxy.notifications`: outbound webhook subscriptions with
  per-subscription event filters and signing keys, three backed-off
  delivery attempts, and a durable deadletter queue with paged listing
  and replay, all on one embedded store. A filter is an exact event
  name, a family prefix like `key_*` anchored on the separator, or `*`;
  a wildcard that reaches the per-request lifecycle events needs
  `allow_firehose: true` in the same call, because one webhook delivery
  per proxied request is not a rate this worker can serve. A replay
  drops its record only once the worker has taken the delivery, so a
  full queue answers `429` with `replayed: false` and keeps it. Like the
  registry, the block is boot-only and a reload that changes it is
  refused by name. Manage subscriptions from the new Notifications page
  in the admin console.

- Added two optional destinations for the request-event stream:
  `request_events.sink: nats` publishes one message per event to a NATS
  subject tree, and `sink: clickhouse` inserts batches over the HTTP
  interface. Neither adds a dependency, and a delivery watermark in the
  shared embedded store replaces the reconciliation table. The NATS
  client reads the server's `INFO`: a message past `max_payload` is
  skipped and counted rather than killing its batch, and a broker
  advertising `tls_required` is refused at connect rather than handed
  the authentication token on a plaintext socket. `request_events` is
  boot-only and a reload that changes it is refused by name.

- AI gateway: a non-streaming provider call is now cancelled when the
  caller's connection breaks while the model is still generating,
  instead of running the generation to completion and billing for a
  response nobody received. The signal is the downstream connection
  itself and never a timer: a TCP reset or read error on HTTP/1, or an
  `RST_STREAM` or `GOAWAY` on HTTP/2. A bare HTTP/1 half-close never
  cancels by default, because RFC 9112 section 9.6 makes it
  indistinguishable from a client that has simply finished sending; such
  a client keeps its generation until a write to it fails, unless the
  origin sets `cancel_on_half_close`. The cancelled call settles on the
  `client_disconnected` receipt outcome, carries
  `error.type=client_disconnected` on its span, and is counted on
  `sbproxy_ai_provider_attempts_total{outcome="client_disconnected"}`.

- AI gateway: new `cancel_on_half_close` boolean on the `ai_proxy`
  action (default `false`). Off, a downstream HTTP/1 half-close is not
  treated as the client leaving, because RFC 9112 section 9.6 makes it
  indistinguishable from a client that has finished sending and is
  waiting to read. On, that half-close cancels the in-flight provider
  call and the request bills as `client_disconnected`, which is what
  makes the common HTTP/1 abandonment (a caller whose own deadline fired
  and closed its socket) reachable. Enable only when your clients never
  half-close after sending. HTTP/2 stream resets and TCP resets cancel
  either way.

- Behavioral anomaly detection: a rolling per-tenant, per-agent-class
  window over the TLS fingerprint, resolver-source, headless-library,
  and per-address rate signals the proxy already collects, flagging what
  sits in the long tail. `AnomalyDetectorHook` had been declared and
  dispatched since Wave 5 with nothing implementing it, so the verdict
  loop ran over an empty list on every request. Verdicts now reach
  `sbproxy_anomaly_detected_total`, a structured log line, a typed
  `anomaly` decision-audit record, and a per-tenant reputation score on
  `sbproxy_agent_reputation_score`. The score is advisory until an
  operator sets `proxy.anomaly.reputation.deny_below` or
  `challenge_below`, which turn it into an admission decision; both are
  unset by default. See
  [docs/anomaly-detection.md](docs/anomaly-detection.md).

- Cache Reserve gains an object-storage backend: S3, Google Cloud
  Storage, Azure Blob, or a local directory, with optional AES-256-GCM
  sealing before an entry leaves the process. Entries are named by the
  SHA-256 of their cache key, fanned out two levels. A new
  `sbproxy_cache_reserve_errors_total` counter makes a failing cold tier
  visible, since every reserve error is swallowed on the request path by
  design; `operation="init"` is the one to alert on, because a backend
  that never built reads as flat zero on every other reserve series. New
  background behavior worth knowing before you point this at a paid
  bucket: the proxy now runs the reserve's expiry sweep every fifteen
  minutes, listing and reading at most 1,000 objects per tick and
  resuming where the previous tick stopped. A bucket lifecycle rule is
  still the answer at scale. See
  [docs/cache-reserve.md](docs/cache-reserve.md).

- Cache Reserve reports its own health. A `cache.reserve.health`
  decision record names the backend, state, and a closed reason code on
  every transition; `sbproxy_cache_reserve_degraded` and
  `sbproxy_cache_reserve_health_transitions_total` chart it; and `GET
  /admin/cache` carries a bounded `reserve` object. A reserve that fails
  to initialize or starts failing at runtime is now visible instead of
  silently absent, and the health state belongs to its pipeline
  generation so a config reload cannot leave a stale gauge behind.

- **A fallback taken is now scrapeable.**
  `sbproxy_fallback_total{trigger, origin, tenant}` counts every
  `fallback_origin` response served, with `trigger` either `status` (the
  primary answered with a status listed under `on_status`) or `error`
  (the primary failed outright and `on_error` caught it). Until now the
  only evidence a fallback had fired was the `fallback_triggered`
  boolean on an access-log row, so alerting on "the fallback is carrying
  checkout.local" meant scraping logs. A fallback is a degraded response
  by construction, and its rate is the first number worth an alert when
  a primary starts failing. Drawn on the Origins dashboard
  (`dashboards/grafana/sbproxy-origins.json`).

- **`GET /admin/origin-composition`.** Which project repositories this
  node's configuration pulls, what hosts each one claims, and the
  platform floor every composed origin starts from, read off the
  effective config with nothing fetched. `origin_sources` names the
  hosts itself, so the pin state and the two-writers-one-hostname check
  are both properties of the document: an operator sees a collision
  before an aggregation run does, and `sbproxy validate` refuses it at
  config load. A repository URL is credential-stripped, an entry
  credential is reported as present or absent and never by value, and an
  input is reported by name only, because an input value is exactly
  where a secret reference lands. The metric
  `sbproxy_origin_source_entries{tier,pinned}` carries the same two
  facts for alerting, with a panel on the origins dashboard. All four
  series are written every time a pipeline is applied, including the
  apply where the block is gone, so deleting it shows up as the drop to
  zero the panel describes and promoting a document between tiers does
  not leave the old tier's series standing. They are written at the
  apply seam rather than at config compile, because compile also
  validates candidate documents and an authority payload can never carry
  the block. See
  [docs/admin-api-reference.md](docs/admin-api-reference.md#get-adminorigin-composition).

- MCP OAuth enforcement decisions reach an operator:
  `sbproxy_mcp_gateway_decisions_total` counts the resource-server 401,
  the per-operation scope refusal and its fail-open twin, the
  `/authorize` limiter, the session-capacity refusal, the stale
  AS-metadata fallback, and the consent CSRF refusal, each with a
  decision log line and a typed audit record.

- **Project-owned origin profiles: `origin_defaults`, `origin_sources`,
  and the composition resolver.** A project repository can now commit
  the part of the proxy config it actually knows about. It ships a
  hostless profile at `sbproxy/origin.yaml` declaring its action,
  policies, transforms and the inputs it needs from whoever deploys it,
  and never names a hostname, because a hostname is an environment fact.
  The runtime config keeps `proxy:`, the new `origin_defaults` floor
  every origin starts from, and the new `origin_sources` list saying
  which project repositories to pull and what hosts each answers on. A
  service team changes its own rate limit by merging in its own
  repository, and the platform team adds a WAF default no project can
  switch off. One profile may declare more than one origin from day one,
  so `entry.hosts` binds a map of profile origin name to hosts rather
  than a bare list. Layering is `origin_defaults`, then the profile
  `base:`, then the profile `environments.<env>:` the entry selected,
  then the entry `overrides:`, so the runtime bookends the stack.
  `policies`, `transforms`, `request_modifiers` and `response_modifiers`
  merge entry by entry against a `name:` key while every other list
  replaces wholesale, which means `policies: []` in a project profile
  leaves the floor intact rather than deleting it. `locked: true` on a
  default refuses a project override and names the policy, the profile
  and the entry, and refuses the three ways a project could otherwise
  reach the same effect without one: an addition sharing the locked
  entry's `type:` or its header paths, an addition carrying a script
  body into a modifier list that holds a lock, and an override of an
  unlocked entry that rewrites it into a locked entry's mechanism. A
  lock binds what an entry does, not what it is called; `disabled: true`
  drops an unlocked default and records the drop, because there is no
  delete verb and an absence leaves no record. Composition runs in one
  aggregator and publishes through the config authority that already
  exists, so a node keeps the subscriber it has and never clones a
  project repository. Both blocks are checked at config load rather than
  at the aggregator: every top-level key must be a real origin field,
  every merged-list entry must carry a `name:`, and every
  `origin_defaults` policy and transform must name a `type:` some module
  answers to, because neither block carries `deny_unknown_fields` and a
  misspelling used to surface at the far end of a GitOps loop. A
  document that declares an extension bundle source warns on an
  unrecognized type instead of refusing it, because the built-in list is
  not the whole vocabulary and config load cannot resolve what a bundle
  provides. This release ships the schema, the resolver and the config
  blocks; the aggregator command itself follows. See
  [docs/configuration.md](docs/configuration.md#project-owned-origin-profiles)
  and [examples/origin-profiles/](examples/origin-profiles/).

- `proxy.federation` serves its entity configuration with a
  `Cache-Control` directive and `authority_hints` a peer can chain, and
  `proxy.federation.peer_trust` verifies a caller claimed entity against
  pinned trust anchors on the request path. `GET /admin/federation`
  reports both.

- **Shadow evaluation gains a comparison surface.** The dispatch half of
  shadow eval could tell you a candidate provider cost less and answered
  faster; it could not tell you whether the candidate answered *worse*,
  because the target's response text was drained. Retention now rides
  the same two-sided gate the primary content store uses (the origin's
  `capture_content` **and** the calling key's `allow_content_capture`),
  so with either side off no sink is installed and the text is never
  held rather than held and discarded. The pair is whole or absent: a
  target's answer whose primary was not captured is refused by the store
  rather than kept on its own, and an answer is never written into a
  sample belonging to a different tenant, because the store key is a
  correlation id a caller can choose and a shadow answer arrives from a
  task that outlives its request. Retained pairs arrive on the existing
  `GET /api/requests/{id}/content` under `shadow_responses[]`, through
  the same redaction stack and payload cap as the primary's own answer,
  capped at eight targets per request.

  A new `GET /api/ai/shadow/report?window=15m|1h|24h|7d|30d` folds a
  window into one row per target, and it leads with provenance (requests
  seen, the sample rate applied, pairs retained, pairs dropped by
  reason, and the three sum) because a delta over four pairs and a delta
  over four thousand read identically once each is a single number.
  Under that: cost delta per request and extrapolated to the eligible
  population, latency delta at p50 and p95 rather than a mean because a
  mean hides the tail regression that kills a migration, the
  finish-reason distribution, error rate by class, and a
  `cost_to_decide_usd` line, every one of them over the same retained
  pairs. The ring behind it holds the last 512 requests that reached
  per-target admission, and `provenance.evicted_before_primary` counts
  the requests that left it before their primary leg landed, so a report
  over a saturated ring says its counts are a truncated sample instead
  of certifying them. A copy that has been admitted and has not answered
  yet is counted under `pairs_dropped.not_reported` and stays off the
  error axis, so `errors.shadow_rate` does not climb with concurrency on
  a target whose every call succeeds. Both sides of the cost delta are
  priced on the vendors' prompt-cache counters, so a candidate serving a
  warm prefix is not reported as dearer than the primary it beat.

  A `shadow.judge:` block configures the batch judge that will score
  agreement, and takes three keys: `provider`, which is resolved against
  this action's `providers[]` at config load and refused when it names
  nothing; `max_spend_usd`, required and refused at zero because an
  unbounded judge is the failure the key exists to prevent; and
  `spend_window`, `daily` or `weekly`, both rolling from when the window
  opened rather than from a calendar boundary. One `max_spend_usd` is
  one ceiling for the whole block: every target under one `shadow:`
  draws on the same budget rather than getting a copy of it. Nothing
  behind the key runs yet. The deterministic divergence pre-filter and
  the cap are implemented and tested and have no caller, because the
  batch job that would call them is the judge prompt and the scoring
  loop, which are a scoped follow-up; the block's entire runtime effect
  today is that `agreement.status` reads `scoring_pending` and
  `judge_spend_cap_usd` appears in the row. Do not read the cap as a
  control in force. Streaming shadows stay out of scope and the reason
  is now written down. See the shadow-eval section of
  [docs/ai-gateway.md](docs/ai-gateway.md), the two endpoints in
  [docs/admin-api-reference.md](docs/admin-api-reference.md), and
  [examples/ai-shadow/](examples/ai-shadow/).

- `stream_include_usage` asks an OpenAI-compatible provider to end a
  stream with a usage frame, by adding `stream_options.include_usage` to
  the outbound body. Off by default: with it on the caller receives one
  extra terminal chunk whose `choices` is empty.

- The access log records `usage_source` (`measured`, `estimated` or
  `absent`) beside `tokens_in` and `tokens_out`, so one AI request can
  be attributed to a provider's own count or to the gateway's estimate.
  `sbproxy_ai_usage_parse_miss_total` carries the same label.

- The proxy can serve its own OpenID Federation entity statement. A new
  `proxy.federation` block names the entity id, signing key, algorithm,
  JWKS, statement lifetime, refresh margin, and `authority_hints`, and
  the public listener answers `GET /.well-known/openid-federation` with
  the compact JWS. Config compile refuses an http entity id, a missing
  key reference, an algorithm outside the asymmetric allowlist, an empty
  JWKS, a refresh margin at or above the lifetime, and an http authority
  hint.

- The readiness report carries a `durable_file_modes` component naming
  what the build enforces on the files its durable sinks write, so the
  posture is visible where an operator looks rather than only in a
  startup log line.

- The redb and SQLite key-value backends implement atomic create and
  conditional swap, so `idempotency.backend: redis` single-flights on
  them instead of degrading. The in-memory backend honors the TTL it is
  given.

- **The admin request row names the prompt-cache tokens.** `GET
  /api/requests` already carried the provider, the model, the prompt and
  completion tokens, the derived cost, and `credential_source`, which is
  the record an operator reads to answer what one request cost and which
  secret paid for it. The provider's own prompt-cache read and write
  counts were not on it: they reached the request-event envelope and
  `sbproxy_ai_tokens_attributed_total{direction="cache_read"}` and
  stopped there, so the one per-request record could show a bill that
  dropped without showing the cache hit that explains it. The operator's
  service tier was in the same position: it reached
  `sbproxy_ai_service_tier_decisions_total{disposition}` and the
  outbound body, and that counter answers a deployment-wide question
  rather than a per-request one, so the row could show a bill without
  showing the tier that priced it. `tokens_cached`, `tokens_cache_write`
  and `service_tier` now ride on the row and on the CSV and JSONL
  exports, appended after `credential_source` so an importer keyed on
  column position keeps working. `service_tier` is always the
  operator's: a caller's own `service_tier` field is stripped before
  dispatch and never reaches the row. It carries the tier as written on
  the provider entry (`flex`, `standard`, `priority`), which is not
  always the spelling the vendor sees on the wire: OpenAI's catalog
  spells the `standard` tier `default`, and the row shows the word the
  operator wrote. The two token counts are subsets of `tokens_in` rather
  than additions to it, and both are absent when the provider reported
  neither; `service_tier` is absent when the serving provider entry
  declared none. See the request-log section of
  [docs/admin-api-reference.md](docs/admin-api-reference.md).

- Three auth providers ship as built-ins: `ext_authz` (Envoy-style
  external authorization), `oauth_introspection` (RFC 7662 opaque-token
  validation), and `kya` (Know Your Agent identity with an optional
  spend floor). Each carries its own metric family and a Grafana panel.

- A config revision is promoted to last known good only after it
  survives a soak window judged on four signals: degraded subsystems,
  upstream health across every origin (circuit breakers, active health
  checks, and outlier ejections), the request-outcome delta, and an
  operator probe. The upstream signal abstains rather than passing when
  an origin exposes none of the three, so a revision is never promoted
  on health nobody looked for. The verdict is three-way, so a window
  that measured nothing is inconclusive rather than a promotion. `POST
  /admin/config/confirm` closes the window early for a pipeline that ran
  its own smoke test.

- Added `POST /admin/config/rollback` and `sbproxy config rollback`:
  re-apply any config revision the node already stored, naming a
  revision, a content digest, or the last known good. A rollback is an
  ordinary candidate that resolves, compiles, publishes through the same
  reload transaction, and soaks, so rolling into a second bad config is
  caught the same way the first one was. It refuses a stale
  `expected_current` naming both revisions, refuses a lineage break
  unless forced, refuses a restart-class or breaking change until the
  caller names the revision back, and appends a new ring entry rather
  than rewinding, so the rollback is itself in the history. `GET
  /admin/config/diff` and `sbproxy config diff` render a plan between
  two stored revisions, or between one and what is running, without
  touching either.

- Added `proxy.config_history.soak.auto_revert`, off by default: with it
  armed, a failed soak re-applies this node last known good on its own.
  It arms only for a change an in-process swap can undo, so a listener
  port, admin block, cluster identity, or origin action-type failure
  logs its blast radius and leaves boot fallback and manual rollback as
  the answer. A revision an earlier revert restored that then fails its
  own soak escalates instead of reverting to itself, a revert that will
  not compile leaves the running pipeline serving, and an inconclusive
  verdict never reverts. New counter
  `sbproxy_config_apply_total{outcome}` separates an automatic revert
  from an operator rollback.

- Break-glass emergency access to the key and credential admin API under
  `/admin/break-glass`: scoped, time-boxed, N-of-M quorum approved with
  no self-approval, every action tagged with the grant id in the audit
  chain, and an expired grant held on a review queue until a human signs
  off.

- **Cheap change detection and coalesced publishes.** Polling asks `git
  ls-remote` which commit a reference points at, in one round trip with
  no working tree, and clones only when that sha moved. An entry pinned
  to a full commit sha is never polled, because a sha cannot move; two
  entries naming one repository at one revision are one fetch; and a
  round where nothing moved composes nothing, publishes nothing, and
  leaves every subscriber on its `304`. A debounce window collects a
  burst of unrelated project merges into one composed document and one
  published revision, with a ceiling measured from the window's first
  movement so a continuously-changing entry still publishes. Timings
  live under `origin_sources.aggregator` with the defaults documented
  alongside what they cost in requests per hour per repository.

- **Composition provenance.** Every leaf of a composed origin records
  the layer that set it (`origin_defaults`, the profile's `base`, its
  environment layer, or the entry's `overrides`) and, for the two layers
  a project authored, the entry, the repository and the resolved commit.
  `sbproxy aggregate --explain <host>` and `sbproxy plan
  --explain-origin <host>` render it for a human without a JSON tool. A
  field-level override reports per field, so the fields a project did
  not touch still name the floor; a policy dropped by `disabled: true`
  records both the layer that dropped it and the layer that had
  introduced it, because an absence explains nothing on its own; and the
  merged lists are keyed by `name:` rather than by index, because an
  index moves whenever an earlier entry is dropped. Provenance carries
  no values at all: a composed leaf can be a `secret://` reference an
  entry bound, so it says which layer and which repository, never what.

- Config-authority subscribers now report what they applied, not just
  what they fetched. On each poll a subscriber sends the revision and
  config hash it is actually serving, a status in OpenTelemetry OpAMP
  `RemoteConfigStatus` terms, an error when the last attempt failed, its
  own soak verdict, and whether its boot fallback is active. `GET
  /admin/config-authority/status` answers "31 of 34 nodes applied r42, 3
  failed" instead of leaving that to be inferred from who fetched, keeps
  a degraded apply distinguishable from a clean one, renders a
  subscriber that has never reported as unknown rather than as applied,
  discards a revision above what the authority has published, and
  separates a node that has not polled recently from one that polled and
  failed. The report rides the existing bundle fetch, so it adds no new
  auth surface.

- `--config-fallback=last-known-good` boots on the config revision ring
  when the configured document does not work, pins the node loudly, and
  suspends the file watcher, SIGHUP, and the `source:` refresh poller
  until `DELETE /admin/config/fallback` clears it, which also applies
  the config file in the same call so recovery finishes in one step. Off
  by default; an exhausted ring exits 78 naming every revision it tried.

- Customer-managed root of trust for the upstream-credential envelope:
  `key_management.crypto.root_of_trust` wraps and unwraps each envelope
  data key through HashiCorp Vault Transit, so sbproxy never holds the
  key. Revoking the grant stops decryption within
  `unwrap_cache_ttl_secs` in full, or at the next failed liveness probe:
  a decrypted credential inherits the time left on the data key that
  opened it rather than starting a second window. `GET
  /admin/crypto/root-of-trust` reports the mode, the last liveness
  check, the cached data keys a revocation still has to age out, and the
  revocation-latency bound.

- docs/config-rollback.md is the operator runbook for a config that
  broke production: read the history, roll a running node back, boot a
  dead one on its last known good, and undo a fleet-wide publish at the
  authority. examples/config-rollback runs the middle of it against a
  real binary.

- docs/origin-profiles.md and docs/origin-aggregation.md are the two
  guides for project-owned origin profiles: one for a service team
  writing its first profile, one for a platform team standing up the
  aggregator.

- **Federated MCP server runtime is distinct from per-tool-call auth.**
  A scope step-up on one `tools/call` stays on that call; the server
  keeps serving other tools. `GET /admin/mcp-runtime` reports each
  server as `starting`, `ready`, `authRequired`, `error`, or `stopped`,
  plus in-flight challenges. `requiredScopes` is parsed from
  `WWW-Authenticate: Bearer scope="..."`, not from metadata
  `scopes_supported`. The same `sbproxy_mcp_tool_dispatch_total` family
  records `server_auth_required` and `call_auth_required`. A console
  page is separate scope.

- Gateway-originated MCP approval holds park a high-risk `tools/call`
  against a content snapshot, not a tool name. The caller is not kept
  waiting on HTTP: JSON-RPC `-32097` returns `hold_id` immediately.
  Operators approve or deny via `/api/mcp/approvals`. TrueFoundry is the
  surveyed SOTA for this gate.

- **`GET /admin/origin-composition` reports the aggregator.** The route
  now carries the configured timings, including
  `polls_per_hour_per_repo`, and `last_round` on the one node that
  aggregates: what it decided, which revision it published, how long it
  took, which entries resolved or fell back to a cached profile, and
  which repositories are unreachable by name. Four metric families back
  it: `sbproxy_aggregate_entries{outcome}`,
  `sbproxy_aggregate_compose_duration_seconds`,
  `sbproxy_aggregate_published_revision` and
  `sbproxy_aggregate_rounds_total{outcome}`, with panels on the origins
  dashboard. The entry name is deliberately not a metric label; fifty
  entries would be fifty series that churn as the block is edited.

- **gRPC, Cedar, and digest-auth docs now have a page or a runnable
  example.** [docs/grpc.md](docs/grpc.md) plus an offline
  [examples/grpc-h2c/](examples/grpc-h2c/) fixture;
  [docs/cedar-policy.md](docs/cedar-policy.md) plus
  [examples/cedar-mcp-full/](examples/cedar-mcp-full/); digest auth
  linked from [docs/configuration.md](docs/configuration.md#digest) and
  [examples/auth-digest/](examples/auth-digest/).

- **hmac_auth can consume an RFC 9421 nonce for exactly-once replay
  defense inside the clock-skew window.** Set `nonce_store: memory` (or
  inject a `NonceStore` the way `bot_auth` does) and the first
  presentation of a nonce verifies; a replay is `nonce_replay`. A wired
  store requires a nonce and fails closed on a store error. Omit the key
  to keep timestamp-window-only replay defense. This config takes no
  filesystem path.

- **hmac_auth can require body coverage without forcing it on GET.** Set
  `require_body_digest: true` (or the same key on one entry) and a
  header-only signature on a request that carries a body is refused with
  a reason that names the missing `content-digest` coverage and never
  echoes key material. Bodyless requests stay header-only, matching
  Apache APISIX `hmac-auth` `validate_request_body`. Default remains
  false.

- **Inspect-only `ai_guardrail_input` hooks can set `execution.mode:
  parallel` to run alongside the upstream call.** A block cancels the
  in-flight generation. Allow adds no time-to-first-token; a reject may
  still be billed by the provider. Watch
  `sbproxy_ai_parallel_moderation_total` (`allow`, `block`,
  `cancelled_upstream`, `refused`) and
  `sbproxy_ai_provider_attempts_total{outcome="moderation_cancelled"}`.
  Parallel cannot combine with `mutates: true`.

- Key-lifecycle events are also emitted as ArcSight CEF on the
  `key_audit_cef` tracing target, and every record on the feed now
  carries `sbproxy.evidence.seq` and `sbproxy.evidence.instance` so a
  SIEM can detect a dropped record.

- Leased upstream credentials for cloud IAM: a credential can name a
  dynamic-secrets mount instead of storing anything static, and resolved
  material is never cached past the lease. Scoped to AWS, GCP, and Azure
  IAM and Vault-fronted database mounts; `lease` on an AI provider with
  no short-TTL issuance is refused with the limitation named.

- **`max_message_size` is now a first-class key on `websocket`,
  `load_balancer`, and `ai_proxy`.** Unset keeps the previous 10 MB cap.
  `0` means unbounded. The cap is keyed on the action, not the origin,
  so two actions on one host can differ.

- **Offline aggregation.** `sbproxy aggregate --out <path>` composes to
  a file rather than publishing, which is the single-node and self-host
  path and the natural fit for a CI job that wants to review the
  composed output before it ships. The written document is ordinary
  config: it boots normally, reloads normally, and needs none of the
  runtime machinery. It carries no `origin_sources` block, because a
  composed output is not a source of further composition and
  re-composing one would loop, and no `origin_defaults`, because the
  floor is already folded into every composed origin. The same inputs at
  the same revisions produce a byte-identical file, so a CI diff means
  something, and `--dry-run` prints what would change against a file
  already there rather than writing. A header comment names every source
  entry and its resolved sha, so the file is traceable after it lands in
  a repository. A resolve failure writes nothing at all, not even a
  partial.

- `POST /admin/credentials/{id}/rotate` rotates an upstream provider
  credential with a bounded overlap window: the previous material stays
  usable only while the new material will not resolve, for
  `key_management.crypto.rotation.credential_grace_secs`. Credential
  views carry `rotated_at` and `rotation_age_days`, and
  `sbproxy_key_rotation_age_days` is the gauge to alert against the
  named crypto periods.

- Read and access audit for credential resolution:
  `sbproxy_credential_read_total` counts every read unconditionally, and
  `key_management.read_audit` adds a rate-limited detail record per
  credential per window on the `key_audit` channel, with the credential
  id HMAC-hashed by default.

- Refused config candidates are kept under the revision ring with the
  reason, the refusing stage, the provenance, and the document as
  written, and read back at `GET /admin/config/rejected`.

- **`sbproxy aggregate`.** One aggregator fetches every project
  repository an `origin_sources:` block names, composes the `origins:`
  map from the platform floor and the project profiles, and publishes
  the result through the config authority that already ships, so it goes
  through `compile_config`, the pipeline construction and the
  model-runtime check before it is signed. What travels is an overlay
  built from the composed and hand-written `origins:` plus
  `origin_defaults`, and nothing else: the node running the aggregator
  necessarily declares `proxy.config_authority`, and an entry with a
  `credential:` needs a `proxy.secrets` backend in the same file, so a
  payload assembled by removing keys from the runtime document would be
  refused by the denied-path screen on every real configuration and
  would be the wrong thing to send even if it were not. Nodes are
  unchanged: they keep the subscriber they already have and never clone
  a project repository. A proxy that both declares entries and publishes
  an authority runs the same loop in process at boot; a node with
  entries and no authority logs that it is not composing rather than
  doing it quietly. Two failure classes are kept apart: one unreachable
  repository falls back to its last resolved profile and is named in the
  output, while an entry that has never resolved refuses the whole round
  rather than publishing an `origins:` map silently missing that
  project's hosts. Fetches run concurrently under a bounded pool with
  one deadline for the round. See
  [docs/configuration.md](docs/configuration.md#project-owned-origin-profiles).

- SBproxy now measures how much of a worker's stack the AI request path
  uses, warns once per process when it passes three quarters of it, and
  holds the measurement to a budget that can only fall.

- The config authority keeps a bounded archive of earlier revisions, so
  POST /admin/config-authority/rollback and sbproxy config authority
  rollback --to-revision N can return a fleet to a revision from further
  back than one step. proxy.config_authority.publish.archive_keep sets
  how many revisions a rollback can name and defaults to 20, so the ring
  holds one file more than that and a ring of one offers one real
  target; zero keeps the one-step rollback exactly as it was. An
  archived revision is written before the served bundle rotates, so a
  disk-full or permission error on the ring cannot leave a publish the
  operator was told had failed to be adopted at the next start.

- The IAB CoMP marketplace bridge is now a configured proxy surface.
  `origins.<host>.comp` serves
  `/.well-known/iab-comp/{manifest.json,quote,redeem}` on that origin: a
  signed catalog of licensing tiers, a signed price for a requested
  volume, and a redeem endpoint that exchanges a paid buyer acceptance
  for an OLP license token signed with the origin's own
  `olp.signing_key`. `GET /admin/licensing` reports what each configured
  origin publishes and which quote-signing key is live. See
  `docs/comp-marketplace.md` and `examples/comp-marketplace/`.

- The Kubernetes operator reads each proxy pod boot-fallback pin,
  reports it as a ConfigFallbackActive condition on the SBProxy naming
  the rescued revision and the compile failure, and stops pushing
  configuration to that SBProxy until the pin is cleared. A config that
  arms proxy.config_history.soak.auto_revert under operator ownership is
  refused at validation with an error naming the owner.

- The `license_leak` guardrail takes a `max_scan_bytes` cap (default 256
  KiB) applied before its detectors allocate, so an oversize AI response
  cannot drive unbounded per-request work.

- The RSL Open Licensing Protocol endpoints are now observable.
  `sbproxy_olp_decisions_total{endpoint,outcome}` counts token issuance,
  JWK publication, RFC 7662 introspection, and RFC 7009 revocation; each
  emits an `olp_decision` structured event carrying the bound `sub`, the
  license URN, and the signing kid but never the token; and `GET
  /admin/licensing` reports each origin's issuer configuration alongside
  its CoMP bridge. Two Grafana panels draw the family.

- Time-boxed MCP RBAC grants (`tool_access[].ttl` plus
  `grant_ledger.path`) expire unless an operator renews them. An elapsed
  grant is hidden from `tools/list` and refused on `tools/call` with
  JSON-RPC `-32098`. Renew with `POST /api/mcp/grants/renew`.

- **`/.well-known/openapi.json` and `.yaml` accept `version=` to emit
  OpenAPI 3.1.** `3.0`, `3.0.3`, `3.1`, and `3.1.0` are the accepted
  values. Omit the parameter and the document stays 3.0.3. An unknown
  value is 400 rather than a silent default. Admin `GET
  /api/openapi.json` stays 3.0.3.

- Boot fallback covers a configured document that parses and compiles
  but whose modules will not construct, which is where most operator
  typos land. Without the construct check such a document exits fatally
  with no pin, no boot counter and no ring walk on every restart, even
  with --config-fallback=last-known-good; it is rescued from the
  revision ring like any other failure and the pin names the
  construction error. Neither the flag nor this check has appeared in a
  release, so they ship together.

- **Cedar MCP policies participate in `sbproxy plan` and `sbproxy cedar
  replay`, and Confirm parks in the admin queue.** A Cedar-only edit is
  a named Reload. `cedar replay --against` evaluates a JSONL traffic
  sample, optionally `--baseline` to preview a change. A Confirm verdict
  with `approval:` parks, fires `mcp_confirm` on existing alerting
  channels, and shows at `/admin/ui/mcp-approvals`. Holds still expire
  fail-closed after 15 minutes.

### Changed

- **`POST /admin/keys/{id}/rotate` returns the current `sbp_` token
  shape, and refuses a key id it cannot mint one for.** Every shipped
  release before this returned the legacy `sk-<id>-<secret>` shape from
  this endpoint while `POST /admin/keys` had already moved to
  `sbp_<id>_<secret>`. Any operator script matching `^sk-`, or splitting
  a rotated token on `-` to recover the key id, needs updating.

  The refusal is the part to check before you upgrade. A minted key id
  is sixteen lowercase hex characters, and the strict parser on the
  inbound path asserts exactly that. A key seeded from config under
  `key_management.seed.keys[]` can carry any id its author wrote, and
  rotating one produced a token nothing could parse: the endpoint
  answered `200` with a credential that authenticated on no code path,
  and when the grace window closed the working token died with it.
  Rotating a non-conforming id now answers `409 {"error": "key id is not
  in the minted format ..."}` and changes nothing. If you rotated a
  seeded key on a build carrying the earlier behavior, the token you
  were handed is not usable; create a replacement key with `POST
  /admin/keys`, move callers over, and revoke the seeded id.

- **`tool_choice` is honored end to end, and `top_k` is now stripped for
  OpenAI-format upstreams.** `/v1/messages` used to parse neither field,
  so both were dropped silently and a forced-tool request came back as
  an ordinary completion. Both are honored now, and each provider
  translator rewrites `tool_choice` into that provider's own spelling:
  `{"type": "any" | "none" | "tool"}` for Anthropic,
  `toolConfig.functionCallingConfig` for Gemini, and Bedrock already
  mapped it. `top_k` has no OpenAI Chat Completions equivalent, so the
  OpenAI arm drops it rather than forwarding an argument
  `api.openai.com` answers with a `400`. Check this one before you
  upgrade if you point an origin with `format: openai` at an
  OpenAI-compatible upstream that does honor `top_k`, such as Together
  or a self-hosted vLLM: that value used to be forwarded and is now
  removed, and sampling will change. `format: custom` byte-forwards the
  body and is the escape hatch. See the translation section of
  [docs/ai-gateway.md](docs/ai-gateway.md).

- **`transport: stdio` MCP servers now run as one supervised persistent
  child per configured server, not one process per JSON-RPC exchange.**
  Server-side session state survives between calls, and process startup
  is paid once per child rather than once per call. The supervisor
  health-probes an idle child with an MCP `ping`, restarts a crashed
  child under bounded exponential backoff, replays the `initialize`
  handshake on the replacement child, fails in-flight calls closed with
  a typed error on a crash or timeout instead of hanging, and kills the
  child when its server leaves the configuration. Legacy one-shot
  commands that answer a single request and exit keep working: a child
  that dies after serving is respawned on the next call. See the stdio
  section of
  [docs/mcp-gateway-guardrails.md](docs/mcp-gateway-guardrails.md).

- **Every upgraded WebSocket tunnel is now scanned, and every one that
  is not a `websocket` action's is held to a 10 MB message ceiling.**
  The frame scanner was armed inside a match on `Action::WebSocket`, so
  `/v1/realtime` (which runs under an `ai_proxy` origin and hands off to
  transparent forwarding) and any `type: proxy` or `type: load_balancer`
  origin fronting a WebSocket backend opened a completely unscanned
  tunnel. Those now get the scanner, with the same documented 10 MB
  default a `websocket` action gets when it configures nothing. A `101`
  for a non-WebSocket upgrade is still left alone.

  Check this one before you upgrade if you front a WebSocket backend
  through any action other than `websocket` and your peers send messages
  larger than 10 MB. Those tunnels were unbounded on every prior release
  and are not any more: the first oversized message drops both TCP
  connections mid-message, with no close frame and no HTTP status,
  because nothing HTTP may be written into a stream the client is
  already reading as frames.
  `sbproxy_websocket_teardowns_total{reason="message_too_large"}` and a
  `websocket_message_too_large` audit record are how it shows up. There
  is no config key to raise the ceiling for those origins yet;
  `max_message_size` is a `websocket`-action field, so today the escape
  hatch is to front the backend with a `websocket` action, which also
  gets you the subprotocol allowlist. Widening the key to the other
  action types is tracked separately.

- **`compression.algorithms` selects in the order you wrote, and `q=0`
  means no.** The list was documented as a priority order on three
  surfaces and read as a membership set, with a hardcoded zstd > br >
  gzip ladder deciding the winner, so `algorithms: [gzip, br]` served
  Brotli to a client that accepted both. The list is now walked as
  authored and the first entry the client accepts is served; an empty
  list keeps the built-in best-ratio-first order. An entry naming no
  codec (`algorithms: [deflate]`) fails config compile rather than
  silently serving every response uncompressed. `Accept-Encoding`
  quality values are also honored as refusals per RFC 9110 §12.5.3:
  `gzip;q=0` refuses gzip, `*` stands in only for codings the header
  does not name, and the standard opt-out `identity;q=1, *;q=0` now gets
  an uncompressed response instead of zstd it declared it could not
  decode. See the upgrade note in
  [docs/config-stability.md](docs/config-stability.md).

- **CORS: the wildcard-plus-credentials refusal moved to config load,
  and a plain `OPTIONS` reaches the upstream.** `allowed_origins: ["*"]`
  with `allow_credentials: true` passed `sbproxy validate` and then
  emitted zero CORS headers plus one `warn` line per request for as long
  as the config was live. It fails config compile now; the runtime guard
  that remains logs once per process and counts every occurrence on a
  new `sbproxy_cors_refusals_total{reason}`. Separately, a CORS
  preflight is now what the Fetch standard defines it as, an `OPTIONS`
  request carrying `Access-Control-Request-Method`. `Origin` alone rides
  on every cross-origin request of every method, so adding a `cors:`
  block used to make the proxy answer 204 to any browser `OPTIONS` and
  silently delete an upstream's own `OPTIONS` endpoint (a discovery
  route answering with `Allow:`, anything WebDAV). A refused preflight
  also no longer publishes the configured method and header allowlists
  on its 204. See the upgrade notes in
  [docs/config-stability.md](docs/config-stability.md).

- **gRPC transcoding now percent-decodes captured path segments, and
  reads a query parameter according to the kind of field it names.** A
  capture is decoded except for the RFC 3986 reserved characters, so a
  `%2F` stays encoded rather than becoming a path separator the template
  never allowed. On the query side, a parameter naming a real field
  whose value will not read into it now returns 400 instead of being
  dropped and sending the upstream that field at its default:
  `?count=abc` against an `int32`, and `?dry_run=yes` against a `bool`,
  which used to arrive as `false` under a 200 and run the job for real.
  `bool` now reads the twelve spellings Go's `strconv.ParseBool` reads
  (`1 t T TRUE true True` and `0 f F FALSE false False`) and refuses the
  rest, and an enum resolves by declared value name and then by number,
  so `?status=ACTIVE` reaches the upstream instead of being dropped. A
  parameter with nothing to read is still ignored rather than refused: a
  name matching no field, a `message` or `bytes` field, and an empty
  value such as `?count=` or a bare `?count`. Check any client sending a
  boolean flag spelled outside those twelve forms, because those
  requests now get a 400 where they used to get a silent `false`. See
  [docs/routing.md](docs/routing.md#grpc-limits).

- **Three metric families are renamed under the `sbproxy_` prefix, and
  the drift guard now refuses an unsanctioned one.**
  `storage_op_duration_seconds`, `storage_op_errors_total`, and
  `prompt_injection_v2_results_total` carried neither sanctioned prefix
  and appeared in no registry, no dashboard, and no alert rule, so a
  scrape config or federation relabel built from the `sbproxy_` and
  `mesh_` prefixes `docs/metrics-stability.md` sanctions dropped all
  three at the scrape: they produced no series at all. They are now
  `sbproxy_storage_op_duration_seconds`,
  `sbproxy_storage_op_errors_total`, and
  `sbproxy_prompt_injection_v2_results_total`, declared in the metric
  registry with their writers. No deprecation window applies, because
  the old names were never published. The coverage guard used to scan
  only for names that already carried a sanctioned prefix, which is why
  it could not see any of them; it now collects every declared family
  and refuses the prefix by name.

- **The provider catalog is re-verified against vendor documentation,
  and seven dead entries are gone.** Every one of the 72 catalog entries
  was checked against the vendor's own current API docs. Seven services
  no longer exist and were removed: Anyscale Endpoints (API host 404s),
  Lepton AI (folded into NVIDIA DGX Cloud Lepton, host returns 530),
  Lambda Inference (host is NXDOMAIN), kluster.ai (sunset after the MITO
  acquisition), OpenPipe (migrated to Weights & Biases and CoreWeave),
  GitHub Models (retired, endpoint returns 410 Gone), and Aleph Alpha
  (no hosted base URL appears in any current PhariaAI doc). Five were
  added: `meta` (Meta Model API, which replaced the Llama API), `wandb`
  (W&B Inference on CoreWeave), `gmi` (GMI Cloud), and the `sglang` and
  `localai` self-hosted runtimes. Nine base URLs and two auth headers
  were stale and would have failed at request time rather than at config
  load: `cohere` pointed `format: openai` at Cohere's native v2 API
  instead of its compatibility host, `writer` is not OpenAI-shaped at
  all and is now `custom`, `upstage` carried a `/solar` path segment the
  vendor has dropped, and `perplexity`, `together`, `azure`, `novita`,
  `crusoe`, `nebius`, `moonshot`, `dashscope`, and `zhipu` all moved
  host or path. `reka` authenticates with `X-Api-Key` and `oracle` with
  a signed `Authorization` header that must not be given a `Bearer `
  prefix. The catalog now ships 70 providers: 63 OpenAI-wire
  passthrough, 3 with in-tree translators, and 4 native pass-through.

- **The JavaScript sandbox documents the globals it actually provides.**
  Only `json_encode` and `json_decode` are registered; there is no
  `atob`, `btoa`, `Buffer`, `TextEncoder`, or `crypto`. A hook that
  needs encoding carries its own. The `hello-javascript` example now
  encodes `body_base64` in the sandbox instead of shipping a hardcoded
  string.

- **AI toolkit dataset registration is charged against a per-scope
  ceiling.** A scope may hold `max_datasets` x `max_dataset_versions`
  versions and that many `max_request_bytes` of serialized entries,
  clamped to the process totals, so a registration past it is refused
  with `dataset_versions_scope` or `dataset_bytes_scope` rather than
  reading as the whole process running out. The ceiling is derived from
  the scope caps alone and does not shrink with the number of origins a
  gateway compiles.

- **Four AI metric families gained a label value or a label.**
  `sbproxy_ai_toolkit_operations_total` adds the closed outcome
  `agent_failed`, which a customer agent rejecting or failing a call now
  records instead of `internal`;
  `sbproxy_ai_quality_routing_decisions_total` adds `prompt_too_large`
  for a prompt refused ahead of the quality hook; and the four
  chargeback tracker families carry an `origin` label naming the origin
  whose billing a refusal invalidated. Alerts that match on
  `outcome="internal"` or aggregate the chargeback families without
  `origin` need updating.

- **`sbproxy validate` now resolves the shared secret of every
  configured AI toolkit agent.** Validation used to substitute a
  placeholder, so a config whose
  `proxy.ai_toolkit.agents[].auth.shared_secret` names an unset `env:`
  variable or an absent `file:` path passed validation and then failed
  at startup. Export the same secrets in the validating environment, or
  point the reference at material the validating process can read.

- Fallback origin: `fallback_origin.on_error` no longer runs for an AI
  request the gateway cancelled because the caller's connection broke
  mid-generation. There is no caller left to serve, and on an `ai_proxy`
  fallback the substitute action would be a second paid provider call.
  Every other failure, including one attributed to the client such as a
  malformed request header, serves the fallback exactly as before.

- **`openapi_validation` now publishes its `policy_verdict_event` from
  the phase that decides.** The header-phase dispatcher used to publish
  an `allow` for this policy before the request body it validates had
  arrived, which was the only audit record a refused request ever got.
  The verdict is now published where the body is checked, carrying
  `deny` for a refused body and `allow` for one that passes, and a
  refusal also emits a `security_audit` record of type
  `openapi_validation` with reason `schema_violation` and sets the
  `policy_blocked` billing outcome. One request produces one record for
  this policy: a SIEM query filtering `policy_id="openapi_validation"
  AND verdict="allow"` no longer matches requests the policy denied. A
  request that never reaches the body phase, because an earlier policy
  refused it or the action answers without going upstream, now produces
  no record for this policy rather than a premature `allow`.

- The ported MCP OAuth, OpenID Federation, and CoMP marketplace crates
  no longer end the process on a path an operator cannot recover from.
  Lock poisoning in the CoMP key manager, revocation denylist, buyer-key
  registry, quote ledger, and federation entity-configuration cache now
  recovers the guarded value instead of unwrapping it; a Prometheus
  family that fails to register is dropped with a warning naming it
  instead of aborting startup; and the in-memory session store, CIMD
  cache, DCR cache, and local KV store build without a fallible step.

- An enabled `key_management` block now refuses to boot when
  `crypto.pepper` or `crypto.master_key` is unset, naming the missing
  key, instead of minting an ephemeral one and warning. Set
  `key_management.crypto.allow_ephemeral_secrets: true` for a local
  development run that wants the old behavior.

- **Codex Compact, resume, and stateful follow-ups get a 400.** `sbproxy
  connect` now names those flows: a first turn that resends the full
  conversation in `input` works, but `previous_response_id`,
  `conversation`, and `store: true` are refused because the gateway does
  not hold server-side Responses state.

- **Docs start at four walkthroughs; upgrade.md no longer pins a rotting
  tag.** [docs/all-traffic-gateway.md](docs/all-traffic-gateway.md) and
  [docs/getting-started-inbound.md](docs/getting-started-inbound.md) are
  the hubs. [docs/features.md](docs/features.md) and
  [docs/comparison.md](docs/comparison.md) are stubs that keep the bound
  claim rows. [docs/upgrade.md](docs/upgrade.md) points at GitHub
  releases and documents Restart vs reload, including
  `proxy.config_history`.

- **Each `ai_proxy` origin keeps its own price table.** Two origins with
  different `model_prices` or rate cards no longer clobber each other,
  `ai.catalog` reads the origin that is handling the request, and a
  validation-only compile never installs the candidate as the process
  global.

- Pingora worker, blocking-pool and offload threads now get an 8 MiB
  stack instead of tokio's 2 MiB default, so a debug build of the
  request path no longer aborts with a stack overflow. New
  `SB_WORKER_STACK_BYTES` overrides it.

- The `backend` label on `sbproxy_cache_reserve_degraded` and
  `sbproxy_cache_reserve_health_transitions_total` now names the
  object-storage provider (`s3`, `gcs`, `azure`, `local`) rather than
  `object_store`, so an S3 reserve and an Azure one are separate series.

- An `abtest` action and `response_cache` on the same origin are now
  refused at config load, whether the action is the origin's own or
  reached through a `forward_rules` entry. The cache lookup runs before
  the variant is chosen and the variant is not part of the cache key, so
  a cache hit served one variant's body to clients assigned another.

- The customer-managed root of trust liveness probe now round-trips a
  fixed non-secret value through `transit/encrypt` and `transit/decrypt`
  instead of reading `transit/keys/<name>`. It therefore needs exactly
  the grant the credential path needs, `update` on those two paths and
  nothing more, which is the least-privilege policy now documented in
  [docs/key-management.md](docs/key-management.md). Against that policy
  the old key-read probe failed on every interval on a healthy
  deployment, dropping the data-key cache each time; against a
  revocation that removed encrypt and decrypt while leaving the key
  readable, it stayed green and the "or at the next failed liveness
  probe" clause never fired. No working deployment needs a config
  change: a deployment that could resolve credentials already granted
  both capabilities.

- **Pingora refreshed to upstream main.** The proxy includes upstream
  HTTP/2 cancellation, timeout, and cache fixes through `09696b5`, while
  retaining SBproxy's dynamic TLS certificate resolver, retry boundary,
  listener preparation, and runtime stack configuration. The fork is no
  longer behind upstream at this release cut.

### Removed

- **`AdaptiveBreaker` is removed from `sbproxy-platform`.** Nothing in
  the workspace constructed one, and the type could not do what its
  documentation described: `record_failure` set `Open`, the only
  transition out fired on `HalfOpen`, and nothing anywhere assigned
  `HalfOpen`, so the breaker latched open on the first error spike past
  `min_samples` and stayed open for the life of the process. Its
  counters were lifetime cumulative with no window, so the "recent
  traffic history" it adapted against did not exist either. Use
  `CircuitBreaker`, which implements the timed Open to HalfOpen
  transition and is the type every consumer in the workspace already
  uses.

- **The unused convergent secret-reuse scaffolding is gone from
  `sbproxy-vault`.** `ConvergentFingerprinter` derived a
  per-installation key, hashed secret values with it, and would have
  persisted a generated key at a reserved vault path on first run. No
  configuration key, metric, event, admin surface, or other crate ever
  reached any of it, so no installation has one of those keys and
  nothing an operator wrote could have produced one. Deleting it also
  removes the read-then-write race in its first-run key generation,
  where two processes starting together would each have generated and
  stored a different key. Secret-reuse detection was never a shipped
  capability and this does not remove one.

- Cache Reserve now ships one object-storage backend.
  `cache_reserve.backend.type: object_store` covers S3, Google Cloud
  Storage, Azure Blob, a local directory, and any S3-compatible store an
  `endpoint` names; the separate AWS-SDK `type: s3` backend is retired
  and refused at config load with the replacement block printed in the
  error. See `docs/cache-reserve.md` for the field-by-field migration
  and what happens to KMS envelope encryption.

### Fixed

- **A `failure_posture: closed` transform now fails a `static` or `mock`
  response closed instead of serving it untransformed.** The transform
  chain has reached generated bodies since the response-phase work
  landed, but a fault there logged a warning and continued with the
  untransformed buffer, whatever the transform's declared posture. A
  redaction transform on a `type: static` origin therefore shipped the
  exact string it existed to strip whenever it faulted (a budget
  overrun, a non-string result, a body over the buffer cap). A `closed`
  transform's fault now answers `500` with `x-sbproxy-transform-error:
  <transform>` and never writes the generated body, matching the proxied
  and plugin-action paths. `failure_posture: open`, which is what a
  `transforms:` entry defaults to, keeps warning and continuing.

- **GraphQL validation refuses before connecting upstream.** On a
  validated `graphql` origin without `request_modifiers`, an invalid
  document now gets its `400` in the request phase, before any upstream
  connection is attempted; previously validation ran only after the
  connect, so an invalid query against a down upstream surfaced as a
  `502`. Routes with `request_modifiers` still validate at the
  post-modifier seam, since the modified request is the one the contract
  holds.

- **A large request body no longer costs the client the response sbproxy
  already wrote.** Any response the proxy generates itself goes out
  before the client's body has been read: `type: mock`, `type: static`,
  `type: echo`, `type: beacon`, every policy denial, and the 502 for an
  upstream that could not be reached. The socket therefore still held
  unread bytes when the session ended, and closing a socket in that
  state makes the kernel send a TCP RST rather than a FIN, which
  discards whatever the peer had buffered but not yet read, the response
  included. Clients saw a reset connection instead of their 200, 403, or
  502. The proxy now reads and discards the rest of the body before
  closing, bounded at five seconds the way nginx bounds
  `lingering_close`; the response still goes out immediately and only
  the teardown waits. Hitting the bound increments the new
  `sbproxy_request_body_drain_timeout_total`. One consequence worth
  knowing: a client that sends `Expect: 100-continue`, receives the
  final response instead of a 100, and then correctly sends no body now
  holds its connection for that bound rather than being closed at once.

- **`ldap_auth` and its `ldap` alias validate clean.** Both were missing
  from the OSS auth catalog, so `sbproxy validate` reported that the
  type "is not in the OSS catalog (will fail at runtime)" on every LDAP
  config, including this repository's own `examples/auth-ldap/sb.yml`,
  which was false. The same omission stopped both names being reserved
  against a bundle hook claiming them.

- **Mid-tunnel failures on an upgraded websocket tear the connection
  down instead of writing an HTTP error body into the frame stream.**
  Once the `101` reaches the downstream wire the client is speaking
  WebSocket frames, but a post-upgrade failure fell through to the
  generic upstream-error tail and wrote a synthesized `502 Bad Gateway`
  response, which arrives as garbage bytes spliced into the frame
  sequence. Every post-upgrade failure (upstream reset, timeout, read
  error) now closes both connections and writes nothing, on both
  surfaces that upgrade: the `websocket` action, and the AI gateway's
  realtime tunnel (`type: ai_proxy` reaching `/v1/realtime`), where a
  provider reset used to splice a `502` into a client's audio frames.
  What decides it is the `101` reaching the wire rather than which
  action opened the tunnel, so pre-upgrade failures still render an
  ordinary HTTP error a client can read: a connect error, a refused
  subprotocol negotiation, or a realtime handshake the provider answered
  `401`. The real failure mode still lands in the log, classified the
  way the `Proxy-Status` machinery classifies upstream errors, and on
  `sbproxy_websocket_teardowns_total{reason="upstream_error"}`. See
  [docs/websocket.md](docs/websocket.md#mid-tunnel-errors-never-write-http-bytes).

- **`print()` inside a Rego bundle hook is bounded and redacted.** A
  transform hook's input is the complete buffered response body, so
  `print(input.body.body_base64)` copied every response into the log at
  `info`, uncapped and unredacted. Messages now pass through the secret
  redactor, are truncated at 512 bytes, and at most eight events are
  emitted per evaluation with one summary line for the remainder.

- **Prompts admin page "Add version" now sends the field the backend
  expects.** The form built a `content` key while `POST
  /admin/prompts/<host>/<name>/versions` deserializes into a required
  `template` field with no alias, so every submission 400ed. The form
  now sends `template`; the same operation already worked via the raw
  admin API.

- **`type: mock` and `type: beacon` responses declare
  `Content-Length`.** Without it the body was close-delimited, so the
  only end-of-body signal was the connection closing: a client could not
  tell a complete body from a killed one, and every mock or beacon
  response burned a connection even when it advertised `keep-alive`.
  That missing header is why the reset above surfaced on the mock path
  from roughly 70 KB while `type: static`, which has always declared its
  length, survived to a megabyte. Neither arm declares a length on 204
  or 304, where RFC 9110 section 8.6 forbids it; `type: static` no
  longer does either.

- **The `websocket` action's `max_message_size` and `subprotocols` are
  enforced.** Both fields parsed and did nothing. `max_message_size`
  (default 10 MB, now enforced including the default) closes the
  upgraded tunnel as soon as a message in either direction declares more
  payload than the cap; frame headers are scanned, payloads are never
  read or buffered. A non-empty `subprotocols` list now allowlists
  `Sec-WebSocket-Protocol` negotiation: the client's offer is filtered
  to it before going upstream, an offer with no allowed entry is refused
  with a `400` before any upstream connection, and an upstream selection
  outside the negotiated set fails the upgrade with a `502`.

- **A WebSocket control frame can no longer disable
  `max_message_size`.** Control frames do not count toward a message
  total, so their declared payload length was skipped rather than
  checked. A fourteen-byte masked pong header declaring `u64::MAX` was
  enough: the scanner spent the declared count skipping payload bytes,
  never parsed another frame header, and the cap stopped applying in
  that direction for the life of the connection, with nothing logged and
  no teardown. RFC 6455 section 5.5 is now enforced on the frames it
  governs: a control frame over 125 payload bytes, or one arriving
  without `FIN`, closes the tunnel.

- **A certificate, its private key, and its metadata now publish as one
  atomic record.** `put_cert_bundle` documented atomic persistence and
  performed three independent writes, so a crash between them left a new
  certificate paired with the previous generation's key, and metadata
  describing material the store could not serve steered peers away from
  repairing it. The bundle is now a single versioned, digest-checked
  record written in one backend operation (the file backend also gained
  write-temp-then-rename, so a concurrent reader never observes a short
  read). Readers validate the whole record, including the
  certificate/key pairing, before serving it; legacy three-key rows are
  adopted read-only only when the pair proves to match, and a torn row
  is quarantined instead of served.

- **A failed transcoded gRPC call reaches the REST client as an HTTP
  error.** gRPC reports the outcome of a call in `grpc-status` and
  leaves the status line at 200, and the transcoder mapped that code to
  an HTTP status for the JSON error envelope in the body and then
  discarded the mapped value, so a `NOT_FOUND` or a `PERMISSION_DENIED`
  arrived as a 200 whose failure was discoverable only by parsing the
  document. The mapping now reaches the status line, using the same
  `google.rpc.Code` table `grpc-gateway` uses, whenever the upstream
  reports the failure in the response headers, which is what tonic and
  grpc-go send for a unary handler that returns an error. A `status`
  response modifier on the same origin still wins. The one shape that
  does not change is a failure reported in real HTTP/2 trailers after
  the response headers, typically a server-streaming method that fails
  partway: the status line is committed downstream before the trailers
  arrive, so that response stays 200 with the error in the body.
  `grpc_web: true` is untouched, since gRPC-Web requires HTTP 200 with
  the outcome in the trailer frame. The mapped status is also what the
  access log, the `status` label on the request metrics, response-cache
  eligibility, the RFC 9209 `Proxy-Status` header, response `assert`
  policies, and `on_response` callbacks see. One surface is now excluded
  on purpose: `fallback_origin.on_status` is no longer consulted on an
  origin with `transcode` or `grpc_web: true`, because both translated
  modes own the response body and a fallback that fired there would
  commit the fallback's status and `content-length` over a body that
  never changed. `on_error` is unaffected. Error-rate alerts on affected
  origins move; see the gRPC limits in
  [docs/routing.md](docs/routing.md) and the upgrade note in
  [docs/config-stability.md](docs/config-stability.md).

- **A late Redis failure no longer discards the RAG vector store's
  replacement connection.** The `redis` vector-store adapter caches one
  multiplexed connection and drops it when a search fails on a dead
  socket, so the next search reconnects. That discard named no
  particular connection: it cleared whatever was cached at the moment it
  ran. Searches that were in flight together on a dropped socket do not
  fail together, so a search whose failure surfaced late threw away the
  connection a search in between had already opened and validated. Under
  steady traffic against a flapping Redis the adapter re-dialed once per
  failed search instead of once per drop, and each dial re-ran the
  protected DNS resolution, so a store under load could churn
  connections without settling on one. The cache slot now carries a
  generation and a discard only evicts the generation the failing
  command actually ran on; a straggler complaining about a socket that
  is already gone leaves the replacement alone. See the vector stores
  section of [docs/rag.md](docs/rag.md).

- **A Redis key revocation can no longer be missed for the life of the
  positive cache.** Key-store mutations ran the record write, the
  revision bump, and the invalidation publish as three separate
  commands, so a failure between them could commit a revocation without
  ever announcing it; a replica whose pub/sub subscription dropped
  during a revoke missed the message permanently (Redis pub/sub has no
  replay) and kept accepting the credential until its L1 TTL expired.
  Mutations now run as one atomic Lua script, so an acknowledged change
  has always published, and the subscriber clears its whole local cache
  on every (re)subscription, after the subscription is live, so a
  revocation during a gap is covered either by the resync or by the
  stream. A subscription stream that ends now reports an error, so the
  supervising loop resubscribes with backoff instead of treating silence
  as health.

- **ACME fleet followers install the leader's certificate without a
  restart.** A shared certificate bundle was loaded into the TLS
  resolver exactly once, during startup. A replica that booted against
  an empty store, waited while a peer issued, and then saw valid
  metadata skipped issuance and kept serving its self-signed bootstrap
  certificate indefinitely; after a renewal, followers stayed on the old
  certificate until a restart. Every path that observes the shared store
  now installs through one helper: initialization, every renewal tick,
  the lease-wait path (a follower installs the winner's bundle within
  seconds of publication), and the post-publication path. The installer
  tracks the installed generation per hostname, so an unchanged bundle
  is a no-op, a regressed one is refused, and a torn or corrupted one
  keeps the last good certificate serving while the renewal path repairs
  the store. A node that never wins the issuance lock says so again on
  every tick, and the per-hostname wait is now bounded by a budget
  shared across the whole tick rather than per hostname, so a proxy with
  dozens of hostnames cannot spend hours inside one renewal pass.

- **`expected_user_agent_pattern` documentation now matches what the
  matcher does.** The field's description called the pattern "anchored,
  case-insensitive" and it is neither: it is compiled exactly as written
  and searched for anywhere in the `User-Agent` header. An operator who
  believed the description wrote `Acme-Crawler/\d`, saw
  `acme-crawler/2.1` fall through to `unknown`, and never got the price
  or policy rule keyed on that agent; the same belief in the other
  direction made `MyPartnerBot` classify `Mozilla/5.0 (compatible;
  MyPartnerBot-imposter)` as the partner and hand it that entry's
  allowance. The behavior is unchanged, because anchoring or
  case-folding every pattern would silently change the meaning of every
  catalog already deployed. The documentation is corrected instead, in
  the field's own description, in the `agent_classes` table of
  [docs/configuration.md](docs/configuration.md), and in the pricing
  example in [docs/ai-crawl-control.md](docs/ai-crawl-control.md), and
  the proxy now warns once at load for each catalog entry whose pattern
  carries no inline `(?i)`, which is the case that fails silently. Write
  the `(?i)` and your own boundary: prefer `(?i)\bMyPartnerBot/\d` to
  `MyPartnerBot`.

- **The Anthropic translator carries the whole tool surface, in both
  directions.** A multi-turn tool conversation aimed at an Anthropic
  upstream used to reach the provider with an OpenAI `role: "tool"`
  turn, a top-level `tool_calls` key, and OpenAI-nested tool
  definitions, none of which Anthropic accepts, so the call failed with
  a 400 naming a role the client had every right to send. The request
  direction now converts tool definitions to `{name, description,
  input_schema}`, an assistant turn's `tool_calls` to `tool_use` content
  blocks, and a `tool` turn to a `user` turn holding a `tool_result`
  block. A `developer` turn hoists into `system` like the `system` turn
  it renames, a `system` turn whose content is a block array contributes
  its text instead of vanishing, and `user` maps onto Anthropic's
  `metadata.user_id`. The response direction surfaces `thinking` blocks
  as `message.reasoning_content`. Every remaining drop (`logit_bias`,
  `n`, `presence_penalty`, `frequency_penalty`, `response_format`,
  `seed`, an unrepresentable `tool_choice`) is counted on
  `sbproxy_ai_translation_dropped_total{surface="anthropic_translator"}`
  and named in the request's one aggregated warn, rather than dropped in
  silence.

- **`basic_auth` now sends the `WWW-Authenticate` challenge its `realm`
  configures.** The key parsed and validated, and then nothing read it:
  a denied request got a bare `401` with `{"error":"unauthorized"}` and
  no challenge header, so no browser prompted for credentials and a
  conforming client had no way to learn which scheme to retry with.
  Missing-credential and wrong-password denials both now carry
  `WWW-Authenticate: Basic realm="<realm>"`. RFC 9110 section 11.6.1
  requires the parameter, so an origin that configures no `realm` is
  challenged as `Basic realm="restricted"` rather than left without a
  challenge. A `"` or `\` in a `basic_auth` or `digest` realm is now
  escaped into the quoted string instead of being able to end it and
  append auth-params nobody configured. In a list-form `authentication:`
  composition, the basic slot's challenge joins the merged 401 alongside
  every other slot's. One shape change to know: an origin that authored
  an `error_pages` entry, or turned on `problem_details`, now gets that
  body on a challenge-carrying denial too; the challenge header and the
  body are chosen independently. One thing to check before you upgrade
  if you read the raw audit stream: a `basic_auth` denial is now a
  header-carrying denial, so its `security_audit` record's `event_type`
  moves from `auth_denied` to `auth_denied_with_headers`, the value
  `digest` and `cap` denials already carry. A SIEM rule matching that
  field exactly stops seeing Basic denials; match on the `auth_` prefix
  instead. The typed `events:` feed is unaffected, since every `auth_*`
  record still bridges to one `auth_denied` event. See
  [docs/configuration.md](docs/configuration.md) and
  [examples/auth-basic/](examples/auth-basic/).

- **Cache decision scripts no longer run on the connection loop.** The
  `cache.key` and `cache.admit` events under `origins.*.response_cache`
  were evaluated inline on the worker that owned the connection. An
  operator script is allowed a 100 ms CPU budget by default and has no
  yield points, so a script that spent its budget stalled every other
  connection that worker was serving, not only its own request. Both
  events, and the copy of `cache.admit` the stale-while-revalidate
  refresh runs, now evaluate on the blocking worker pool. Nothing
  changes for an origin with neither event configured: the scheduling
  hop is only paid when a script exists to run. For an origin with an
  `admit_event`, the cache write-back is dispatched one hop later than
  before, and the deferral is capped at 64 evaluations in flight so a
  slow script cannot pile up response bodies in memory; past the cap the
  event runs on the connection loop rather than queueing. The Lua arm
  also stops building a throwaway VM per evaluation, since a Lua engine
  holds no script state and every call already builds its own sandboxed
  VM; JavaScript deliberately keeps a per-evaluation engine, because a
  shared one would carry one tenant's context into the next tenant's
  script. See the cache-event section of
  [docs/scripting.md](docs/scripting.md).

- **Circuit breakers now admit one probe at a time in half-open, instead
  of all traffic.** `allow_request()` returned true unconditionally in
  `HalfOpen`, so the moment `open_duration_secs` lapsed every concurrent
  request was dispatched at the upstream that had just been failing,
  before any of them had reported back, once per open duration for as
  long as the upstream stayed down. Four places already documented the
  opposite. Half-open now hands out a probe slot through a
  compare-and-swap: the request that wins it goes through, the rest are
  refused as if the breaker were open, and the slot returns when that
  probe calls `record_success` or `record_failure`. A caller whose
  request produced no verdict about the upstream at all hands the slot
  straight back: the crawl-control ledger client does that on a hard,
  non-retryable refusal such as an already-spent token, which a healthy
  ledger answers with and which deliberately does not flap the breaker.
  A slot nothing returns is written off after one more open duration, so
  a breaker cannot get stuck refusing. Reaches the `load_balancer`
  action's `circuit_breaker:` block, the AI router's breakers, and the
  AI crawl-control ledger client. On a load balancer the breaker is
  still advisory: when it filters out every target in the pool the
  request is routed anyway rather than failed. See
  [docs/config-stability.md](docs/config-stability.md#circuit-breakers-now-admit-one-probe-at-a-time-in-half-open).

- **`config_revision` is a function of the config again, not of the
  process that read it.** On any config with more than one origin the
  revision changed across restarts with nothing else changing: the
  compiler assigned each origin its index by walking a `HashMap`, and
  the revision hash consumed those indices, so a two-origin file
  reported two revisions across three boots and an N-origin file had up
  to N! of them. `config_revision` rides the request log, the access
  log, the CSV export, webhook envelopes and `policy_version`'s prefix,
  where it is read as the config generation that served a request, so a
  value that moved on its own made that unanswerable across a restart
  and fired a revision-change signal on every reboot. Origin indices are
  now assigned in sorted key order, which also makes the compiled origin
  list itself deterministic, and the hash pairs each hostname with its
  rank in that order rather than with a stored position. Two upgrade
  notes: a single-origin config hashes to exactly the value it did
  before, and a multi-origin config settles on one of the values it was
  already alternating between, so anything keyed on a revision sees at
  most one final change and none after that. The `servers` array in an
  emitted OpenAPI document is now ordered by hostname for the same
  reason; it was previously in whatever order that config's origins
  landed in.

- **`content_digest`'s `on_missing: require` refuses before the upstream
  is dialed.** The missing-header check ran in `request_body_filter`,
  which Pingora reaches only after `upstream_peer` has selected a peer
  and the connection is up. The verdict was never wrong, only late, and
  late is an availability problem: every refusal paid for a full
  upstream dial and held the connection slot for it, and pointed at an
  upstream that was slow or unreachable the client got the upstream's
  failure instead of the policy's. Against an unreachable upstream the
  proxy answered `502` rather than the configured `400`. Nothing about
  that verdict depends on the body, so it now runs in the header phase:
  the upstream is never dialed, `missing_status`, `error_body`, and
  `error_content_type` are honored exactly as before, and `on_missing:
  skip` still falls through to the body filter unchanged. Digest
  refusals from either phase now increment
  `sbproxy_policy_triggers_total{policy_type="content_digest",action="deny"}`,
  which none of the body-phase refusals did, and log on the
  `sbproxy::content_digest` target with a `reason` naming the outcome.
  See [docs/content-digest.md](docs/content-digest.md).

- **Ephemeral storage refuses a TTL it cannot honor instead of rounding
  it up.** `EphemeralKv` promises an entry is evicted on or before its
  TTL elapses, but the Redis backend clamped anything under a second up
  to one second, so a caller asking for a 200ms lifetime would have got
  a record readable for a full second, while the in-memory test double,
  which keeps the whole `Duration`, expired it on time. No shipped path
  reaches that: the only consumer is the mesh backend and it counts TTLs
  in whole seconds, so no deployment was affected and this is the
  contract being closed before a caller such as a single-use nonce or a
  PKCE verifier lands on it. Both backends now reject a zero TTL with
  `InvalidConfig`, and the Redis backend rejects anything under one
  second because Redis expiry counts in whole seconds; the rejection
  happens before the connection is opened, so it does not depend on
  Redis being reachable. The in-memory double still accepts sub-second
  TTLs, which is the documented difference between them. The mesh
  backend's `expire` refuses a zero TTL rather than guessing between the
  two conventions that collide on it, Redis `EXPIRE key 0` meaning
  delete and its own `set` meaning no expiry.

- **`EventBus::publish` no longer calls subscriber closures while it
  holds the handler-map lock.** A handler that blocked on a socket used
  to stall every other thread publishing to the bus, and a handler that
  called back into `publish`, `subscribe`, or `subscriber_count`
  deadlocked its thread permanently, because `parking_lot::Mutex` is not
  reentrant and waits rather than panicking. Fan-out now runs against a
  snapshot of the subscriber list taken when `publish` starts: a handler
  registered during a fan-out first receives the next event rather than
  the one in flight, and nested publishes on one thread stop at eight
  with a `warn` naming the event type instead of overflowing the stack.
  Only code that embeds the workspace crates reaches this bus; the
  `events:` file and webhook sinks were never routed through it and are
  unchanged.

- **`rollout_percent`'s documentation named the wrong hash.** The field
  doc said a request's bucket is `xxhash(flag_name + key) % 100`; the
  bucketer is and always was FNV-1a 64-bit over `flag_name`, a `|`
  separator byte, then `key`. Anyone reproducing the documented formula
  to preview a canary cohort or audit rollout fairness got different
  buckets than the proxy computes. The doc now states `fnv1a64(flag_name
  + "|" + key) % 100` and calls out the separator, and a test recomputes
  the documented formula independently so the two cannot drift again.

- **The Kubernetes Gateway controller publishes `sb.yml` whole or not at
  all.** It rendered the document straight over the existing file, so a
  controller pod killed between the truncate and the write left a
  partial config on the shared volume, and a data plane restarting on it
  could not boot. Each publish now writes a temporary file in the same
  directory, flushes it, renames it into place, and syncs the directory,
  so a reader opens either the previous complete document or the new
  one. A publish that fails leaves the last good document byte for byte
  intact and no temporary behind, and a mode an operator set on the
  published file survives the next reconcile. Rename atomicity and
  `fsync` durability are the filesystem's promise, so on an NFS-backed
  volume this is as strong as the server underneath it. A volume that
  refuses the directory `fsync` outright logs a warning and still counts
  as a successful publish, because the rename has already landed by
  then. See [docs/gateway-api.md](docs/gateway-api.md).

- **`GET /api/openapi.json` and `.yaml` refresh on every reload.** The
  admin OpenAPI render is cached, and the cache was keyed on
  `config_revision`, which identifies the set of origins served and
  deliberately holds still when the behavior behind an unchanged
  hostname changes. So a reload that added an auth block, edited a
  forward rule or set a deprecation left the cache in place and the
  admin routes served the pre-reload document for the life of the
  process. It is keyed on the pipeline generation now, which moves on
  every swap. The per-host `/.well-known/openapi.json` route was never
  affected; it rebuilds per request. Three docs that described
  `config_revision` as a content hash of the configuration have been
  corrected to say what it identifies, most importantly
  [docs/metering.md](docs/metering.md), which told buyers to verify a
  signed receipt's pricing against it.

- **`GET /v1/models` no longer advertises a surface the gateway
  refuses.** The per-model `capabilities` array came from the provider
  catalog's `supports_chat`, `supports_embeddings`, and
  `supports_streaming` keys in
  `crates/sbproxy-ai/data/ai_providers.yml`, while the request path
  decided its 501 from the per-provider surface matrix in
  `crates/sbproxy-ai/src/api_routes.rs`. The two disagreed on 43 of the
  72 shipped catalog entries: a `bedrock` origin advertised `embeddings`
  and then answered `POST /v1/embeddings` with 501. Every model listing
  now publishes the intersection of the two, so a caller can act on what
  a listing names. The array is never wider than the 501 gate and can be
  narrower, because the matrix answers on the wire format while the
  catalog keys answer on the vendor. An `openai`-format provider is
  still forwarded every OpenAI path, but its listing names only the
  surfaces the catalog records for that vendor, so a `deepseek` model
  lists `chat_completions`, `messages`, `responses`, and `streaming`
  rather than the whole OpenAI set, and a `voyage` model lists
  `embeddings` alone. Absence from the array is not a refusal. Three
  smaller changes ride along: `vertex` now declares
  `supports_embeddings: true`, which its OpenAI-compatible endpoint has
  always served; `messages` and `responses` appear wherever chat does,
  since the gateway translates them itself; and the LiteLLM-parity `GET
  /model/info` and `GET /model_group/info` carry the same array, a group
  reporting the union across its deployments. See
  [docs/providers.md](docs/providers.md) and the model-listing section
  of [docs/ai-gateway.md](docs/ai-gateway.md).

- **gRPC streaming support is described accurately.**
  `examples/grpc-h2c/README.md` reported that server reflection (`list`)
  came back as a garbled framing error through the proxy and steered
  readers away from it. Rechecked against a grpc-go server with
  reflection registered: `list` works, `grpcurl describe` returns
  byte-identical output through the proxy and straight at the upstream,
  and bidirectional streaming round-trips every message. New end-to-end
  coverage pins all of it; there was none before. A new [gRPC
  limits](docs/routing.md#grpc-limits) section records what is genuinely
  narrower, including one composition worth avoiding: a body-reading
  policy on a `grpc` origin needs the complete request body, so it
  stalls every streaming RPC on that origin while leaving unary calls
  working.

- **`default_model` now applies on the hosted AI dispatch path, not only
  on locally served providers.** The field's own schema description says
  "Default model used when the request omits an explicit model", and the
  main JSON dispatch path never read it: it substituted the empty string
  and shipped that to the provider. The empty string is not a harmless
  placeholder, because every model-aware gate is written as "if a model
  was named", so `allowed_models`, `blocked_models`, a virtual key's
  per-key model scoping, model-scoped budgets, provider eligibility, and
  the context-compression pipeline were all skipped for exactly those
  requests. Against an upstream that infers the model itself (an Azure
  deployment-scoped `base_url`, a single-model vLLM or Ollama) the
  request reached the provider ungated. A request that omits `model` now
  takes the origin's default when every enabled provider naming one
  names the same one; providers that name nothing abstain, a disabled
  provider gets no vote, and two enabled providers that disagree leave
  the request modelless rather than picking whichever is listed first.
  Two carve-outs keep the old behavior and say so. The fallback is
  scoped to the chat-shaped surfaces (`/v1/chat/completions`,
  `/v1/messages`, `/v1/responses`), because `default_model` names a chat
  model and surfaces like `/v1/moderations` and `/v1/images/generations`
  treat `model` as optional and default it upstream from their own
  vocabulary. And a multipart request (audio transcription, image edits,
  image variations) with no `model` form field is still forwarded
  without one, because the multipart rewrite can replace a `model` part
  and cannot add one. See [docs/ai-gateway.md](docs/ai-gateway.md).

- **The `jsonl_file` usage sink no longer interleaves two concurrent
  rows onto one line.** It wrote the row and its newline as two separate
  appends and held no lock, so two calls landing together, the shadow
  legs of one request or two requests finishing at the same instant,
  produced `{row}{row}` on one line followed by two blank ones. Both
  rows were written and neither was parseable, which reads to any JSONL
  consumer as rows that were never recorded at all rather than as a
  corrupt file. The row and its newline now go out in one append, which
  is atomic against other appenders. The other durable line sinks
  (`session_ledger`, the request event sink, and the verifiable usage
  ledger) each serialize their writers already and were never affected.

- **Output-guardrail decisions are recorded for live provider
  responses.** `ai.guardrail.output` was published for an idempotency
  replay and a semantic-cache hit but not for the response the provider
  actually generated, so a route with output guardrails and
  `decision_audit` enabled saw decisions only for the replayed subset.
  The live relay and the cascade arm now run through the same funnel and
  publish once per response, for the allow as well as for the block.
  Expect more records on that feed: if you size a SIEM pipeline on
  `ai.guardrail.output` volume, this is a volume change, not a behavior
  change to the guardrails themselves. Streamed and live multipart
  responses still publish nothing, because neither materializes a body
  to evaluate.

- **A stored-prompt reference on `/v1/messages` or `/v1/responses` now
  resolves instead of being dropped.** `"prompt": "name@version"`
  belongs to no provider wire format, so both native translators dropped
  it, and the shared resolver reads the already-translated canonical
  body where it no longer existed. A `prompts:` origin plus a
  `/v1/messages` request naming a stored prompt therefore reached the
  provider with no rendered system turn at all, running without the
  template it asked for. The reference is now lifted off the inbound
  body before translation and put back on the canonical body afterwards,
  so the same resolution, the same `system` turn, and the same run
  metadata apply on all three surfaces. Fail-closed where the field can
  only be a gateway reference: on the two native surfaces a name a
  configured store does not hold is a 400 and an origin with no prompt
  store at all answers 404, in both cases without the gateway-only key
  reaching the provider. The canonical `/v1/chat/completions`
  pass-through is unchanged, because `prompt` is also a legacy
  completions field there. Both refusals publish an `ai.admission`
  decision record with a `verdict` of `prompt_render_failed` or
  `prompt_reference_not_found`. See the stored-prompt surface matrix in
  [docs/ai-gateway.md](docs/ai-gateway.md).

- **The emitted OpenAPI document no longer names a method the gateway
  refuses, and no longer drops an operation it serves.**
  `allowed_methods` accepts any valid HTTP method token, and the request
  path enforces that set exactly with a `405`, but emission mapped every
  verb outside OpenAPI 3.0's eight onto `get`. An origin allowing only
  `PROPFIND` therefore published a `get` operation the gateway would
  refuse, said nothing about the verb it does serve, and collapsed two
  such verbs onto one key so only the second survived. Those verbs are
  now listed on the path item under `x-sbproxy-unrepresentable-methods`
  and no operation is invented for them, one entry per method and host
  so a shared path key cannot claim a verb against a host that answers
  it with a `405`. Separately, the write that placed an operation was
  unconditional, so two forward rules resolving to the same path and
  method (two origins in the all-hosts document, or two rules on one
  origin separated by a `header`, `query`, `body`, `method`, or `when`
  condition) silently overwrote each other. The first now keeps the key,
  matching the runtime's first-match-wins rule order; the rest are
  preserved under the path item's `x-sbproxy-alternate-operations` and
  summarized in a top-level `x-sbproxy-collisions` array. Each operation
  also carries its own `servers` entry naming the origin that serves it,
  and an `x-sbproxy-match` extension describing the matcher conditions
  OpenAPI cannot express. `x-sbproxy-match` names the field a rule looks
  at and the comparison it performs and stops there: the per-host
  document is served without authentication, so a shared-secret routing
  header, an internal query token, or the text of a `when:` predicate
  would otherwise be published to anyone who can fetch the spec. Two
  rules that differ only in a withheld value are kept apart by a
  `variant` counter rather than by a digest, which would let a holder of
  the document confirm a guessed value offline. A config with no
  unrepresentable verbs and no colliding rules emits the document it
  emitted before, with none of the new keys.

- **A successful operator hot reload no longer repeats on every
  requeue.** The hot-reload decision's last gate compared the new config
  hash against the pod template's `sbproxy.dev/config-hash` annotation,
  and the hot-reload success path deliberately skips the workload patch,
  so that annotation could never advance on the path it gated. It was
  therefore permanently stale, the gate was permanently true, and every
  300s requeue plus every watch event on the `SBProxy`, `ConfigMap`,
  `Service`, `Deployment`, or `SBProxyConfig` fanned `/admin/reload` at
  every pod again, rebuilding each handler chain and dropping warmed
  per-process state for a config the fleet already ran. The gate now
  reads `status.configHash`, which advances on both delivery paths, so a
  pass over an unchanged `SBProxy` reloads nothing. The pod template
  keeps the hash the pods were started with until something has to roll
  them: re-stamping the current hash there would have restarted the
  whole fleet for a config it was already serving, which is what the hot
  reload existed to avoid. Both the Deployment and the clustered
  StatefulSet paths are fixed. See the reconcile-loop section of
  [docs/kubernetes.md](docs/kubernetes.md).

- **`SBProxy.status.configHash` is stamped after the rollout lands, not
  before it starts.** The operator patched `configHash` and cleared
  `lastError` immediately after validating the referenced
  `SBProxyConfig`, before the ConfigMap, Service, and workload applies.
  A 403 on the ConfigMap patch (an operator Role missing
  `configmaps/patch` in that namespace), or a 409 or 500 from the
  apiserver, therefore left `kubectl get sbproxy demo -o yaml` reading
  `configHash: H1` with an empty `lastError` while every pod kept
  serving H0. Since the CRD documents `configHash` as the hash "rolled
  out" and `lastError` as "cleared on successful runs", that is the
  documented signal for a completed rollout, and the only contrary
  evidence was one warn line in the operator's own log. Both writes now
  happen after the workload apply succeeds, or after every pod has
  accepted a hot reload. The early write moved to a new
  `status.observedConfigHash`, which says the operator has read and
  validated the config and nothing more, so `configHash` trailing
  `observedConfigHash` is now the visible signal that a rollout is in
  progress or stuck. Upgrade the CRDs with the operator image: the
  operator only trusts a `configHash` that has an `observedConfigHash`
  beside it, because the older build wrote `configHash` before applying
  anything and a hash meaning "seen" must not read as "delivered". Until
  the CRD carries the new field the apiserver prunes it, and the
  operator re-delivers the config once per requeue instead of skipping
  the pass. `helm upgrade` handles it; a raw `kubectl apply` needs
  `deploy/crds/sbproxy.yaml` reapplied too. See the reconcile-loop
  section of [docs/kubernetes.md](docs/kubernetes.md).

- **Outlier ejection now restarts the endpoint's measurement window.**
  The failures that caused an ejection kept counting against the
  endpoint after it was re-admitted, until `window_secs` expired from
  the original window start. A recovered endpoint serving four clean
  requests and then one unrelated 5xx was re-ejected at a 60 % lifetime
  error rate even though its post-recovery rate was 20 %, on repeat, so
  a configured 30 s `ejection_duration_secs` behaved as a
  `window_secs`-long one. Ejection now zeroes the endpoint's counters,
  so the probe after re-admission is graded only on post-ejection
  traffic. See
  [docs/config-stability.md](docs/config-stability.md#outlier-ejection-restarts-the-endpoints-measurement-window).

- **`error_pages` and `problem_details` now cover policy denials, not
  only authentication ones.** An `ip_filter`, `waf`, `dlp`, `rego`,
  `csrf`, `object_authz`, or other `policies:` refusal answered with a
  hard-coded `{"error": ...}` in `application/json` regardless of what
  the origin configured, so an operator who opted in to RFC 9457 got
  `application/problem+json` from an auth denial and a different body
  shape from a policy denial on the same origin. Both blocks now render
  those refusals, with the same precedence they already had: an authored
  page wins, the renderer catches the rest. This also makes
  `include_detail: false` mean something on the policy path, where it
  previously suppressed nothing: the WAF's message appends the id of the
  rule that matched, and that reached the client verbatim. Unchanged on
  purpose are the refusals whose body a protocol pins, which keep their
  own shapes: the 429 rate-limit set, the AI-crawl payment family,
  settlement responses, and agent-to-agent chain refusals. So do the
  three policies that write their own body on every refusal, configured
  or not, and therefore never reach the renderer: `concurrent_limit`,
  `content_digest`, and `prompt_injection_v2`. Also still outside the
  renderer, and now stated as such: the 404 for a `Host` matching no
  origin, `bot_detection`'s 403 and the other refusals that run before
  the policy chain, and the AI gateway surface. See
  [docs/configuration.md](docs/configuration.md) and
  [examples/problem-details/](examples/problem-details/).

- **`prompt_injection_v2`: the URI and header scan now honors
  `block_body` and `block_content_type`.** The policy can block from
  four places. Three of them (the buffered request body, the `ai_proxy`
  prompt segments, and A2A message parts) wrote the operator's
  configured rejection body and media type to the wire. The fourth, the
  synchronous scan of the request line and non-auth headers, denied
  through the generic policy renderer instead: it wrapped the body in a
  fixed `{"error": "<block_body>"}` envelope and always answered
  `Content-Type: application/json`. `block_content_type` was ignored
  outright on that path, and a `block_body` that was already JSON came
  back double-encoded as a string inside an `error` field, so
  enforcement depended on which internal path happened to run. All four
  paths now serve `block_body` verbatim with `block_content_type`. If
  you pre-wrapped `block_body` to work around this, unwrap it. Each
  block increments the new
  `sbproxy_prompt_injection_blocks_total{scan_path,tenant}` counter, so
  the four paths can be compared rather than merged.

- Provider prompt-cache token counts now reach the attribution metrics.
  The billing choke point parsed `cached_input` and `cache_creation` off
  the provider's usage block and then passed literal zeros for them, so
  a cache hit showed up in dollars, because the cost table already
  discounts both, and nowhere in tokens.
  `sbproxy_ai_tokens_attributed_total{direction="cache_read"}` and
  `{direction="cache_write"}` now carry real numbers. Both are subsets
  of `direction="input"`, not additions to it, so sum the directions
  separately rather than folding the label. The usage record also gained
  a `tokens_cache_write` field beside the existing `tokens_cached`.

- **`proxy.attestation.role: claim` and `role: both` are refused at
  config load, because this build implements neither.** Both spellings
  parsed, validated, and produced nothing: no claim is written before a
  call is served, nothing ever reads `proxy.attestation.queue`, and no
  ceiling is computed for `proxy.attestation.enforcement_mode` to act
  on. A proxy set to `claim` compiled clean and served traffic that
  produced neither a claim nor a receipt, so an operator who had
  configured a spend ceiling and a bounded queue got an unmetered proxy
  and no signal that anything was wrong. Config load now refuses both
  roles with a message naming the three missing pieces and pointing at
  `role: receipt`, the half that is complete, and it refuses the same
  widening on a per-origin `attestation.role` so one host cannot slip
  past the proxy-wide check. Boot also stops creating the claim queue's
  directory: nothing in this build can write there, and state an
  operator has to explain is worse than none. The ledger's directory is
  still created, because the receipt chain is opened in it. `role:
  receipt` and `role: off` are unaffected, and no shipped example or e2e
  config used either refused role. See the `role` section of
  [docs/metering.md](docs/metering.md).

- **`docs/comparison.md` no longer advertises PROXY protocol support.**
  The table listed PROXY protocol v1 as shipped. A complete v1 parser
  exists in the source tree, nothing calls it, no listener reads the
  preamble, and there is no configuration key of any spelling. An
  operator who enabled PROXY protocol on the load balancer in front of
  SBproxy got a 400 on every connection, because the `PROXY TCP4 ...`
  line reached the HTTP parser as the request line, and the address the
  access log, the WAF, and the IP-filter policy evaluated was the load
  balancer's. The row now reads "No (v1 parser present, not wired to a
  listener)", a build guard fails if the row and the wiring ever
  disagree, and
  [docs/config-stability.md](docs/config-stability.md#there-is-no-proxy-protocol-configuration-key)
  says what to do instead.

- **Three rustdoc claims that the code did not have.** The reverse-DNS
  verifier's docs said the verdict cache TTL was "the smaller of the
  observed PTR / forward TTLs"; the resolver port returns no TTL at all
  and the caller passes a fixed value, now documented as the fixed value
  it is. The same file said the verifier "never silently falls back to
  `User-Agent` matching", while its only production consumer falls
  through to UA matching for every non-verified verdict, which is now
  what it says. The SSRF module's caller-status list, which exists so a
  reviewer can enumerate every path needing dial-time re-validation,
  named seven call sites and asserted `validate_url_with_allowlist` had
  none outside the module; the `events:` webhook sink had two it did not
  name. The list is now nine, split by whether the caller pins the
  address it validated, and a test fails the build if a new call site
  lands without being added to it.

- **The `html` transform's `rewrite_attributes` stamps every matching
  tag.** It used to rewrite the tags that already carried the attribute
  and stop, and when no tag carried it, add it to the first match only,
  so a page that mixed the two came out half-rewritten. One pass now
  handles both: a tag with the attribute has its value replaced, a tag
  without it has the attribute inserted before the closing `>`, and a
  self-closing `/` is kept. The attribute match also requires a
  whitespace boundary, so a `target` rewrite no longer fires inside
  `data-target`, and a configured value containing `$1` stays literal
  text.

- **The secrets-manager keystore no longer loses key-index entries or
  revision bumps to concurrent writers.** Each mutation is three
  unguarded vault round trips, two of them a read-modify-write on a
  secret shared by every record of that kind, on the one backend that
  refuses compare-and-set for exactly that reason. Two concurrent mints
  could each read `["a"]` and write their own array over the other's,
  dropping a key id from the index forever: `list_keys()` never returned
  it and the console could not revoke it, while `get_key()` still
  authenticated it. Mutations are now serialized within the process, the
  index and revision writes read back what they wrote and re-apply on a
  mismatch, and the write order is chosen so a mid-sequence failure
  leaves a survivable state: the index entry goes in before the record
  (a dangling id is skipped by `list_keys`) and the tombstone goes down
  before the index entry is removed. A writer this process cannot see, a
  second replica on the same prefix or an operator editing the secret by
  hand, is narrowed by the read-back retry rather than excluded; only a
  real conditional write could exclude it.

- **`security_headers`: a configured `content_security_policy` is no
  longer silently dropped.** Setting both a `headers:` array and a
  `content_security_policy` block emitted the array and no CSP at all
  whenever `enable_nonce` was false and no `dynamic_routes` were set: no
  error, no warning, just responses with no CSP. The two now merge, with
  the `content_security_policy` block as the single source of truth for
  that header and `headers:` supplying everything else. Two siblings of
  the same bug went with it: `report_only` and `report_uri` were
  consulted only on the nonce path, so a policy asking for report-only
  monitoring was emitted as an enforcing one, and a CSP block whose
  `policy` string was empty emitted nothing. Authoring a CSP in both
  places at once is now refused at config compile rather than resolved
  quietly, and a `headers:` array that supersedes legacy flat fields
  logs which ones it is dropping. Emitted policies are counted by
  `sbproxy_security_headers_csp_emitted_total{mode,tenant}`.

- **A metering node no longer holds one claim id per request for the
  life of the process.** `SegmentRecorder` folds a retry into the sale
  it belongs to by remembering the claim ids it has already counted, and
  nothing ever removed one. Because a claim id is a fresh per-request
  value, a proxy with a metering role at 1,000 requests a second added
  around 86 million distinct 26-character ids a day to a set that only
  grew, on the order of a gigabyte a day of unreclaimable heap until the
  process was killed, and nothing reported the set's size so the growth
  read as generic memory pressure rather than as the meter. The recorder
  now keeps a fixed window of the 65,536 most recent claim ids, which is
  65 seconds of traffic at that rate and far longer than any attempt at
  one claim survives, and reports the window's occupancy beside the
  lifetime claim count in its `Debug` output. The published `claims`
  figure on a chain segment is unchanged: it is a separate lifetime
  counter, so bounding the window does not shorten the total.

- **One broken settlement sweep no longer cancels the rest of the
  tick.** The recovery worker chained its six sweeps with `?`, so a
  single store error, from a second process holding the write lock past
  the busy timeout for instance, returned from the whole tick and the
  sweeps below it never ran. For as long as the contention recurred,
  reconciliation stopped asking providers what happened to ambiguous
  writes and expired recovery ciphertext was retained past its hard
  expiry, while the sweep that retires unresolved payments kept running
  ahead of them. Every sweep is now attempted independently: the one
  that failed logs at warn under its own name, increments
  `sbproxy_payment_recovery_total{operation="<sweep>",
  outcome="failed"}`, and the tick reports the first error only after
  all six have run. `sbproxy_payment_worker_ticks_total` still counts
  only ticks where every sweep completed, which now means something it
  could not mean before: a flat tick rate beside a moving `failed` rate
  reads as a degraded worker rather than a dead one. See the `worker`
  section of [docs/payment-settlement.md](docs/payment-settlement.md).

- **Each shadow target's usage row gets its own ledger id.** The shadow
  usage record minted its `:shadow` request id when it was built rather
  than when it was recorded. With one target that was invisible; with
  the multi-target lists this release adds, every target's row would
  have carried the same id, and that id is the verifiable ledger's dedup
  key, so N rows would have collapsed to one on replay. The id is now
  minted per recorded row.

- `routing.strategy: sticky` is now documented as what it does. The
  session-affinity map exists in the router and nothing on the request
  path supplies it a session key, so every request has always taken the
  round-robin fallback; the documentation claimed it pinned a user or
  session to one provider. The strategy still loads, so no config
  breaks, and the docs now point at `cache_affinity` for caller affinity
  that works.

- **The ACME issuance lease renews for as long as the CA takes, and a
  holder that lost it can no longer publish.** The fleet issuance lock
  was a fixed 120 second TTL with no heartbeat, while a normal ACME
  order can legitimately poll longer than that; stale takeover on the
  file and object-store backends was read-then-overwrite, so two
  replicas racing the same expired lease both believed they won. The
  lease is now renewed every 20 seconds for the whole order, a holder
  whose renewals keep failing fences itself before any successor can
  have started, takeover is a conditional write (an atomic create-marker
  on the file backend, an etag precondition on object storage, a single
  Lua script on Redis) so exactly one contender per expired lease wins,
  and every acquisition mints a strictly increasing fencing generation
  that publication is checked against. An object-store backend with no
  conditional write support refuses the takeover instead of quietly
  double-acquiring.

- **The file log sink counts every record it drops.** An append that
  failed after the file was already open discarded its error, so a sink
  on a full volume, a read-only remount, or a failing disk stopped
  writing while `sbproxy_telemetry_dropped_total{kind="file_sink"}`
  stayed flat and an operator alerting on that counter read the sink as
  healthy. A failed append now ticks `reason="write_error"`, a failed
  open ticks `reason="open_failed"` (it warned before but counted
  nothing), and a failed rotation ticks `reason="rotate_failed"`. All
  four file-sink warnings, including the existing `mkdir_failed` one,
  are now rate-limited to one per minute per sink path: they fire once
  per emitted record, so the first ENOSPC used to turn a broken sink
  into a log flood at request rate. The counter carries the rate.

- The Kubernetes Gateway API controller no longer publishes a truncated
  `sb.yml` while a watch relist is in flight. The replayed objects are
  staged beside the live snapshot and swapped in when the relist
  completes, which is also the only point a relist schedules a
  reconcile, and the first document a fresh controller writes waits for
  all four watched kinds to finish their first list.

- **The Kubernetes Gateway controller renews its leader Lease and fences
  every write on loss.** Leader election acquired the 15 second Lease
  once and returned, so after 15 seconds a standby took it over while
  the original leader kept writing `sb.yml` and Gateway API status, and
  takeover used force-apply, which lets a non-holder steal the holder
  field. Leadership is now a lifecycle: the leader renews every 5
  seconds, takeover is conditional on the Lease's `resourceVersion` so
  racing standbys see exactly one winner, and a leader that cannot renew
  fences its own config and status writes after 10 seconds, fails
  readiness, releases the Lease on graceful shutdown, and exits so the
  Deployment restarts it as a standby.

- The Redis virtual key store, its L2 cache tier, and the shared Redis
  storage backend now reconnect after their socket dies. A Redis
  restart, failover, or `CLIENT KILL` used to leave a cached connection
  that never reconnects, so every later key resolution and every later
  mesh membership write failed for the life of the process.

- **The translated gRPC paths negotiate away message compression instead
  of mis-reading it.** `transcode` decodes the response frame to build
  JSON and `grpc_web: true` re-frames it for a browser, and neither can
  read a compressed payload, but neither said so: no request carried
  `grpc-accept-encoding`, the frame's compression flag was parsed and
  then never read, and the `grpc-encoding` response header was stripped
  from both paths regardless of what it said. A gzipped frame was handed
  to the protobuf decoder as if it were a message, which fails as a
  schema error or, for bytes that happen to parse, succeeds with the
  wrong field values. Both paths now advertise `grpc-accept-encoding:
  identity` upstream, so a compliant server stops compressing; a frame
  whose compression flag is set anyway is refused by name rather than
  decoded; and the gRPC-Web bridge keeps a non-`identity`
  `grpc-encoding` header on the response, because the frames under it
  are forwarded byte for byte. Plain gRPC passthrough never looks inside
  a frame and is unaffected. See the gRPC limits in
  [docs/routing.md](docs/routing.md).

- **The upgrade guide's provider count.** `MIGRATION.md` described the
  AI provider catalog as "90+" entries, a number it has carried since
  the initial commit and that the catalog has never held. It ships 72,
  which is what every other page already published. The count is now
  read out of `crates/sbproxy-ai/data/ai_providers.yml` at check time
  rather than written down in prose: `scripts/check-doc-drift.sh` holds
  every digit-form provider total in the scanned docs to the catalog's
  entry count, holds the published wire-format breakdown of that total
  ("66 of the 72 catalog entries", "3 custom-format entries") to the
  catalog's `format:` values wherever it appears on a line carrying such
  a total, scans `MIGRATION.md` for the first time, and runs on a change
  to the catalog itself, so a provider added without updating the docs
  fails the lane instead of shipping. Word-form counts stay the job of
  the fixed-string list beside it, and a breakdown claim reworded off a
  total's line stops being read, which the check reports rather than
  passes over.

- **The usage-bridge example replays the metrics it shows.**
  `examples/usage-bridge-queue/README.md` published a
  `sbproxy_usage_bridge_enqueued_total` scrape and its counter values
  that nothing re-ran, on a page the capture harness otherwise covers.
  The block now carries a `CAPTURE` marker like the three steps above
  it, and `scripts/check-doc-captures.py` refuses any `bash` block on a
  covered page whose next fenced block shows output, unless a marker
  replays it, a heading separates the two, or the block is recorded with
  the reason it cannot be replayed. Each recorded reason must match
  exactly one block, so a later block cannot inherit an older exemption.
  The fence parser behind that now reads any info string CommonMark
  allows, and reports a fence it cannot read instead of walking past it:
  a ```rust,no_run block on `docs/audit-log.md` was silently costing the
  page one of its 31 blocks and inverting code and prose for everything
  below it.

- **The usage ledger now writes each entry in one syscall and forces it
  to disk.** The append path called `writeln!` followed by
  `Write::flush`, which `std::fs::File` documents as a no-op, so entries
  the ledger reported as written lived in the page cache until the host
  wrote them back. A power cut lost them silently: a truncated hash
  chain is still a valid hash chain, so the shortened file verified
  clean, `sbproxy_meter_chain_gap_total` counted nothing, and the
  revenue was simply unbilled with no marker anywhere. `writeln!` also
  lowered to two writes, so a process killed between the payload and its
  newline left a line the next append merged into, after which
  `UsageLedger::open` refused the file permanently and a `failure_mode:
  closed` deployment refused traffic until somebody edited it by hand.
  Each entry is now a single `write` of the line and its terminator
  followed by `sync_data`, and a write that moved some bytes and then
  failed marks the ledger unappendable rather than chaining onto a torn
  line; a write that failed having moved nothing, which is what a full
  disk does, leaves the file intact and the ledger appendable, so
  metering resumes when the space does. The cost is one `fsync` per
  metered call, inside the mutex that already serializes appends and
  inside what `sbproxy_meter_append_duration_seconds` measures: put
  `proxy.attestation.ledger.path` on local storage. See
  [docs/metering.md](docs/metering.md) and the upgrade-affecting section
  of [docs/config-stability.md](docs/config-stability.md).

- x402 settle now reads the HTTP status before the body, so only a 2xx
  response saying `success: false` is an authoritative refusal. A settle
  answered outside 2xx moves the intent to `NeedsReconciliation` instead
  of closing it `Terminal`, whatever a foreign error envelope
  deserializes to.

- **`ai_guardrail_output` now evaluates streamed model output.** The
  hook used to run only on a buffered completion, so a `stream: true`
  client bypassed it. An enforcing output hook holds the stream until
  close and can replace or refuse the assembled assistant text.

- **`ai_tool_call` now evaluates non-streaming tool calls, and a block
  after stream headers writes an SSE error.** A buffered tool-call
  completion used to skip the hook, and a streaming block after headers
  used to close the connection with no payload. Both now refuse with the
  same bounded error envelope as the pre-header path.

- **Buffered bundle policies now run on empty-body requests and on
  `ai_proxy` origins.** `body_mode: buffered` (the hook default) used to
  skip GET/HEAD and every AI request, so a deny hook never saw them.
  Those requests now dispatch against the complete body, including an
  empty one.

- **Git-sourced config and extension bundles no longer require a `git`
  binary.** Fetch prefers `git` on `PATH` and falls back to an
  in-process clone when it is missing, which is what the official
  distroless image needs. `verify_signature: true` still requires `git`,
  because GPG and SSH signature verification are not in the in-process
  path.

- **Linux Model Host spawn no longer wraps the engine in `/bin/sh`.**
  Distroless images have no shell, so a serve entry on the official
  image never reached exec. The startup gate now waits in the child
  before the engine image is exec'd. macOS still uses a shell wrapper
  because Darwin has no `pipe2`.

- **`transforms:` on an `ai_proxy` origin are refused at config load.**
  Those origins never reach the transform pipeline, so a listed
  transform used to load as active and then silently no-op. Use the AI
  bundle hooks `ai_guardrail_output` and `ai_tool_call` to inspect model
  output instead.

- **A confidence cascade that dispatches no tier now says which
  exclusion stopped each one.** A cascade tier naming a provider the
  calling credential's `provider` allow/block policy excludes used to
  log a bare `cascade exhausted without dispatching any tier` before the
  client's `502`, naming neither the lock nor the requested provider.
  When that lock is the only reason no tier dispatched, the logged error
  now reads `cascade exhausted: every candidate tier was excluded by the
  credential's provider policy (allowed=..., blocked=...); routing plan
  requested provider(s) ..., which this credential cannot reach`. When
  the causes are mixed the message stays generic and appends each tier's
  own closed reason, `(skipped: openai (data_posture), anthropic
  (credential_lock), ...)`, so a mixed cause is diagnosable instead of
  silent. A tier excluded by the request's data-handling posture
  (`x-sbproxy-require-zdr`, `x-sbproxy-disallow-data-collection`, or the
  origin's `data_posture:` block) is reported as `data_posture` and
  never as the credential's own lock, and a tier naming a provider that
  is not configured is reported as `not_found`.

- **`fallback_origin`'s `on_status` trigger now serves a clean,
  correctly framed fallback response.** It used to edit the primary's
  response header in place, overwriting a handful of names and leaving
  every other header the primary set (`Server`, its own
  `Access-Control-Allow-*`, and the rest) on what is meant to be an
  independent response, and it stashed the fallback body for
  `response_body_filter` to swap in later. Pingora only calls that hook
  when the primary actually produces a body chunk, so a primary that
  answered with no body at all (`Content-Length: 0`, the common shape
  for a bare `503`) sent the fallback's declared `Content-Length` with
  zero bytes behind it and desynchronized the keep-alive connection. The
  fallback response is now built from nothing and written in full, so
  neither can happen. Three operator-visible consequences. First, the
  headers SBproxy itself owns are put back on the fallback rather than
  lost with the primary's, and this half applies to **both** triggers,
  so an origin running only `on_error` is affected too: those responses
  were built from nothing and carried none of these headers before
  either, and they will start carrying them on upgrade. The set is:
  CORS, HSTS, `security_headers` and Page Shield, the CSRF cookie, the
  debug request-id and correlation-id echo, `traceparent`/`tracestate`,
  RFC 9209 `Proxy-Status` carrying the *primary's* status, and the
  idempotency and retry-skip markers. `response_modifiers`,
  `Deprecation`/`Sunset`, `Content-Signal`, compression, the
  `Content-Type` rewrite, and response caching do not apply to a
  fallback;
  [routing.md](docs/routing.md#what-a-fallback-response-carries) lists
  both sides. Second, a fallback with `status_code: 204` or `304` now
  declares no `Content-Length`, matching the carve-out the `static` and
  `mock` actions already took, and a fallback answering a `HEAD`
  declares the length its `GET` would return and sends no bytes. Third,
  `bytes_out` in the access log and in the metering receipt now counts
  the fallback body: on the `on_error` path it was `0` and is now the
  body's length, so a `measured` unit rule on `bytes_out` will see
  billed quantities move on upgrade. The access log's `upstream_status`
  also starts working: it read the same field it was being compared
  against, so it was empty on every request the proxy has ever served,
  and it now carries the primary's status whenever a fallback, a
  `status` response modifier, or a metering refusal replaced the status
  the client sees.

- Classifier sidecar: a model id a validated manifest names but no
  `--model` loaded now fails with a typed status instead of answering
  `safe` at score 1.0 or a zero embedding, tenant ids are bounded and
  character-checked at registration, and normalization refuses past a 4
  MiB output ceiling, and a label pattern or normalization rule that
  compiles past its charged compiled-program budget (48 KiB per pattern,
  64 KiB per rule) is refused at registration with a message naming the
  budget.

- Classifier sidecar: the public TCP listener can no longer take the
  whole in-flight frame budget. 4 MiB of the 16 MiB budget is reserved
  for the admin listener, so unauthenticated sockets that pin their
  share cannot lock an operator out of `register`, `delete`, and `list`.

- Classifier sidecar: the public TCP listener now runs every CPU-bound
  command behind the same bounded executor and per-request budgets as
  the gRPC surface, carries whole-frame and whole-connection deadlines
  (`--tcp-frame-timeout-ms`, `--tcp-connection-timeout-ms`), and refuses
  a non-loopback bind unless `--tcp-allow-nonlocal` is set. The
  connection deadline is refreshed by every answered frame, so a pooled
  connection that stays busy is never cut mid-exchange.

- A buffered AI response the caller walked away from during the write
  now prices as `client_disconnected` rather than as a delivered sale or
  a provider 5xx, and declines the `on_error` fallback that would have
  made a second paid provider call for a caller who had already left.

- A cancelled request no longer orphans its idempotency key for the
  whole lease, a transient store read failure no longer hands out an
  unfenced claim during a failover, and the validated-GraphQL path takes
  its key off the proxy worker like every other path. Proxied requests
  now record their idempotency outcome, so the `result` metric means
  what the reference says it does.

- A client that disconnects mid-stream now settles on a
  `client_disconnected` receipt and ticks
  `sbproxy_ai_stream_post_commit_failures_total{cause="client_disconnected"}`,
  where the failed relay write previously priced as a delivered sale.

- A streamed AI response now settles its token usage through one
  finalizer on every way the stream can end, so a client that hangs up
  mid-stream is billed for what it received rather than refunded in
  full, and a clean stream with an exact `usage` frame reaches the
  access log, the usage sinks and the payment bridge instead of
  reporting zero.

- A streamed AI response whose provider never sends a `usage` frame is
  now billed from the assistant text it delivered, counted with the
  model tokenizer, instead of debiting nothing;
  `sbproxy_ai_usage_parse_miss_total` marks every stream priced that
  way.

- A usage-less non-streaming AI response now debits `max_usd` from the
  same catalog-priced estimate it already debited the token caps from,
  instead of reporting `PerCall` and moving no dollars.

- An abandoned streamed AI request now settles what it delivered. The
  settlement moved into a guard, so a shutdown that drops in-flight
  streams, an outer timeout, or a panic in the relay bills the tokens
  the provider already generated instead of refunding every reservation.

- An `ai_close` hook that blocks the stream close now publishes an
  `ai.close` decision record with a `deny` outcome, naming the hook's
  refusal code. Only a clean close published one before, so a refused
  close left the audit feed silent.

- An MCP OAuth broker whose `broker_signing_key` is a PEM with no
  `public_jwk` is refused at startup instead of serving an empty JWKS
  every verifier rejects, and a colocated resource server takes that key
  set in process instead of dialing the proxy own JWKS URL.

- **Prompt-cache affinity now stands aside for `fallback_chain`, as
  documented.** Four routing strategies own their candidate order
  outright and a cache lease must not jump the queue: `fallback_chain`
  sorts by declared priority, `cascade` walks tiers in cost order,
  `cost_quality` splits cheap against frontier, and a `routing_policy`
  plan names its providers. [docs/ai-gateway.md](docs/ai-gateway.md)
  says of all four that "on those origins no lease is read and none is
  recorded", and the dispatch site's own comment named all four. The
  condition beside it tested three. On a `fallback_chain` origin with
  `cache_affinity:` configured, a caller who had sent a
  `prompt_cache_key` therefore had the lease holder moved to the front
  of the operator's priority order, and a fresh lease was recorded on
  every success, so the chain drifted further from its declared order
  the longer it ran. The strategy half of the rule is now
  `Router::owns_candidate_order` and the whole rule is one named
  predicate with a test per arm, so the sentence in the docs and the
  expression in the code can be read against each other.

- **A `cel` transform's `headers:` rules now run exactly once, in a
  phase that can bind what they read.** The same rules were evaluated
  twice on a proxied response, once in the header phase against an empty
  body and again in the body phase against an empty header map with the
  headers already committed, and a `plugin` response evaluated them and
  drained nothing, so even a constant `set` vanished with no error, log,
  metric, or event. Each rule now evaluates once, in the phase the
  dispatched action settles in. A rule reaching for a binding no route
  on its origin can supply is refused when the config compiles, naming
  the origin, the rule, and the action: `response.body` where every
  route streams, `response.headers` where every route buffers, and any
  header rule at all on an action that never runs the transform chain. A
  rule some other route can serve is skipped on the route that cannot,
  counted on `sbproxy_errors_total` under a closed reason and logged,
  rather than resolved against an empty value. `op: append` now adds a
  value on every action type; on a `static` or `plugin` origin two
  `append` rules for one header used to leave only the second.

- **`sbproxy config print` and `sbproxy mcp lock` now resolve `${VAR}`
  through the config compiler's own pass rather than a near-copy of
  it.** The copy had drifted three ways: it substituted `$${VAR}`, which
  is the documented escape and has to stay literal; it substituted the
  MCP local-tool forms `${args.x}` and `${steps.x.y}`, which the tool
  executor owns at call time; and it had no `${VAR:-default}` support,
  so a config resolving to a default printed the raw placeholder
  instead.

- CoMP redeem is bound to the quote it names. An expired quote stays
  refusable after a later quote request, where the sweep used to remove
  the row that rejected it, and `accepted_quote_hash` is verified
  against the quote this publisher issued for that `quote_id`. A
  `quote_id` the process's ledger has never seen is still admitted,
  because that ledger is same-process and refusing would break every
  redeem across a restart; `docs/comp-marketplace.md` names that limit
  under Honest limits.

- `docs/extension-bundles.md` now describes `ai_close` accurately: it
  fires before the end-of-stream marker reaches the client, a `block`
  verdict is honored, and both outcomes publish an `ai.close` decision
  record; `ai_failure` remains the one event whose verdict is never
  consulted.

- `docs/policy.md` no longer says the Cedar compiler and policy store
  were removed; it separates the retired natural-language-to-Cedar path
  from the Cedar engine that ships for the MCP `tools/call` hook.

- Idempotency now caches a response whose upstream outlived the claim
  lease, and a waiter polling a key no longer deletes a successor's live
  claim. The claim lease and the overlap wait are config keys
  (`idempotency.claim_lease_secs`, `idempotency.claim_wait_ms`); waiting
  requests draw on their own pool so one key's retry storm cannot starve
  every other key.

- Idempotency now single-flights overlapping first requests. The
  middleware looked a key up and, after the response was final, stored
  it, with nothing in between: fifty parallel retries of one payment
  POST all missed, all reached the upstream, and all charged the card,
  which is the case the feature exists to prevent. A first request now
  claims its key atomically and every overlapping retry waits for that
  request's response and replays it, so the upstream is called once. A
  retry that outlives the three-second wait gets 409
  `ledger.idempotency_in_flight` with `x-sbproxy-idempotency: IN-FLIGHT`
  and `Retry-After: 1` rather than a second upstream call, and a retry
  carrying a different body still gets `ledger.idempotency_conflict`.
  The claim is a sixty-second lease, released the moment its holder
  finishes, fails, or is cancelled, so a crashed request bounds rather
  than wedges the key, and a superseded holder cannot overwrite the
  response its successor published. Single-flight across replicas needs
  an `l2_store` that can create a key atomically; redis can, and a store
  that cannot is warned about once and counted under
  `result="single_flight_unsupported"` instead of silently doing
  nothing.

- **A linked plugin returning the legacy `ActionOutcome::Responded` now
  gets a defined response on every transport.** The variant claims the
  handler already wrote a response through host state, and no host state
  a linked `ActionHandler` reaches writes one: HTTP/1.1 and HTTP/2
  marked the request served and sent zero bytes, so the client saw an
  empty exchange and the access log had no status, while HTTP/3 answered
  a `501`. All three now answer `501 Not Implemented` with the same
  `application/json` body carrying the stable
  `unsupported_action_outcome` reason, stamp the status onto the request
  context, tick
  `sbproxy_errors_total{error_type="unsupported_action_outcome"}`, and
  publish a `request_error` event naming the outcome, so the refusal is
  alertable and reaches the SIEM feed rather than living in a log line.

- **Two `${...}` placeholder forms were misclassified as environment
  references.** `${}`, which names nothing, lost its closing brace
  during interpolation and was reported as an unresolved environment
  reference, which a config-authority subscriber turns into a refusal of
  the whole bundle. `${request.header.NAME}` and `${attribution.KEY}`,
  the dotted half of the access-log `custom_fields` vocabulary
  documented in `docs/access-log.md`, were treated the same way even
  though `custom_log` resolves both per request and never from the
  environment. Both now round-trip as the literal text they are.

- **`resilience.circuit_breaker` and `resilience.outlier_detection` now
  see real request outcomes.** The AI dispatch path counted per-provider
  attempts but never fed the router's health axes, so neither the
  breaker nor the outlier detector learned that a provider had failed
  and a provider that failed every request was never ejected, on any
  routing strategy. Every settled attempt now records one outcome
  against the attempt metric, the breaker, the outlier detector, and the
  per-error-class cooldown policy together: a 5xx or a transport error
  is the provider's failure, a 4xx is the caller's and counts as a
  success, a managed-local engine that never started counts for load but
  is no health sample, and a raced leg the winner cancelled records
  nothing at all.

- Rotated access-log backups left behind by a change of the `compress`
  setting are made owner-only. The sweep followed the configured
  compression mode, so an operator who turned compression on after
  upgrading left the plain `access.log.1..N` files at whatever mode the
  older build gave them, holding the same request records as the
  compressed files beside them.

- **The admin console no longer triggers the browser's native credential
  dialog, and neither does a browser opening an admin URL directly.** A
  `401` answering a browser now comes back without `WWW-Authenticate:
  Basic`, so a session that lapses mid-use drops the operator on the
  console's own sign-in page instead of behind a popup whose Cancel
  button left the page unusable until a hard reload. The server tells a
  browser apart by `X-Requested-With: XMLHttpRequest`, which the
  console's fetch layer sends on every admin call, or by the presence of
  `Sec-Fetch-Dest`, which browsers send on every request and shell
  clients send on none. Both only choose that one response header;
  neither changes how credentials are resolved, so a marked request with
  no password is refused exactly as before. Two things to know before
  you upgrade. Opening an admin route in a browser tab now shows the
  JSON refusal rather than prompting for the top-level password, which
  is the point: that prompt was how a browser picked up the credential
  and began re-sending it invisibly, minting fresh sessions with no
  login. `Sec-Fetch-Dest` shipped in Chrome 80, Firefox 90, and Safari
  16.4, so a browser older than those still gets the prompt on a direct
  navigation; the console's own calls carry `X-Requested-With` and are
  covered on any browser. And a separately hosted console
  (`proxy.admin.cors_origins`) that sends `X-Requested-With` preflights
  every call, so the preflight's `Access-Control-Allow-Headers` now
  names it. Scripted and CLI callers send neither marker and still get
  the RFC 7235 challenge, so `curl -u` and `sbproxy admin` are
  unaffected. A 401 now carries `Vary: X-Requested-With, Sec-Fetch-Dest`
  for anything caching in front of the admin port. See
  [docs/admin-api-guide.md](docs/admin-api-guide.md).

- The emitted OpenAPI document now maps every auth type the gateway
  implements, including the three providers WOR-2667 ported. The
  `api_key` provider previously fell through to a generic placeholder
  that told clients to send `Authorization` when the origin wanted the
  header it had configured, and a `noop` origin published a credential
  requirement it does not have.

- **The Extensions admin page reserves its red load-evidence styling for
  a real failure.** Every poll of a Git-sourced bundle writes a refresh
  line into `load.detail`, so the page used to paint healthy bundles
  error-red on every refresh. Red now means the bundle failed: its hooks
  collided unresolved, or its refresh candidate was rejected. A rejected
  candidate moves that bundle to `load.status: degraded` on `GET
  /api/extensions` and holds it there until a poll reaches the source
  and succeeds, so a proxy serving a stale generation no longer reads as
  healthy. A collided hook now carries the reason in `hooks[].detail`
  instead of reporting a state with nothing to act on.

- The idempotency reference no longer claims a full waiter pool skips
  the cache: it answers 409 `ledger.idempotency_in_flight` immediately,
  and only the buffering pool produces `x-sbproxy-idempotency:
  SKIPPED-POOL-FULL`. `SKIPPED-MULTIPART` is documented as the seventh
  header value, and the outcome metric now says which requests it counts
  rather than claiming it sums to the origin request count.

- The MCP OAuth broker device-code consent page works when a branded
  verification URI is configured, and refuses to boot without a
  canonical origin. Naming `device_code_verification_uri` used to
  replace the expected origin rather than add to it, so the shipped
  consent page became cross-origin against itself; and
  `device_code_enabled` with DPoP off booted with no base URL at all,
  which made every consent POST a 403.

- The streaming usage estimate now covers every wire shape the
  `usage_parser` table documents. Vertex and Gemini
  `candidates[].content.parts[]` and Bedrock's base64 `bytes` envelope
  extracted to nothing before, so a delivered answer on either provider
  refunded in full; frames past 16 KiB and chunks that split a
  multi-byte character are no longer dropped either.

- Thirteen metric families the ported MCP OAuth broker, OpenID
  Federation, and IAB CoMP crates declare are now classified in the
  metric registry and appear in `docs/metrics-stability.md`.
  `sbproxy_mcp_gateway_sessions_active` also gained the writer it never
  had: the in-memory session store updates it on every put, take, and
  purge, so the dashboard panel reading it stops drawing a flat zero. A
  deployment on the storage-backed session store still reads zero there,
  and the catalog entry says so.

- Two MCP OAuth broker refusals now appear in the metric catalogue that
  always counted them: an unresolvable `client_id` metadata document on
  `/authorize` and on `/token`. Both answer a fixed string on the wire,
  because the detail would name the address a client-chosen URL resolved
  to, so `sbproxy_mcp_gateway_decisions_total` is the only place their
  rate is visible. A new guard pins every surface that writes that
  family against the catalogue entry in both directions, so a refusal
  cannot stop being counted, or start being counted undocumented,
  without a test going red.

- **A composed payload is screened where it composes.** A hand-written
  `origins:` entry on the aggregator node, and an `origin_sources`
  entry's `overrides:` block, both travel to every subscriber, and the
  config authority refuses any document that names a file on the
  publishing host or a host-backed secret reference. Those keys are
  legal on a node that owns its own filesystem, so an aggregator whose
  own origins validated against an OpenAPI document on disk had every
  round refused with nothing to see it coming. The check runs at
  composition now, which means `sbproxy aggregate`, `--out` and
  `--dry-run` all name the offending key rather than leaving it to the
  publish. Two more from the same round: the poll a compose takes before
  a fetch runs under the round's bounded pool and deadline like every
  other poll, so a handful of blackholing hosts cannot hold a
  composition open past its own deadline; and an edit to the runtime
  document that moves no repository now composes and publishes, so
  raising a floor in `origin_defaults` or rebinding an entry's hosts
  reaches the fleet instead of waiting for a repository to move.

- **A fully-qualified git ref now resolves.** `git clone --branch` takes
  a short name and refuses a full ref, so a `source:` or
  `origin_sources` entry pinned to `refs/tags/v1.4.2` failed with
  "Remote branch refs/tags/v1.4.2 not found in upstream origin". That is
  the spelling a production-tier `origin_sources` entry is required to
  use, because git does not tell a tag from a branch by spelling, so a
  production aggregator could not have resolved a single entry. A
  revision beginning with `refs/` now takes the same targeted `git init`
  plus shallow fetch that a bare commit sha takes, which accepts a full
  ref exactly as written. An annotated tag resolves to the commit a
  checkout reports rather than to the tag object.

- A git source or origin_sources entry pinned to a branch ref now checks
  out on a server that refuses a shallow targeted fetch. The full-fetch
  fallback checked out the pin as written, which finds nothing for a
  branch: a full fetch writes the head to refs/remotes/origin/<name>.
  Commit shas and tags were unaffected.

- A `pdf_markdown` transform configured with `extract_tables` now warns
  once at config load rather than on every decoded response, and a
  successful decode logs at debug rather than info.

- **A repository this proxy does not own cannot read a file it does not
  ship.** A `source:` checkout and an `origin_sources` profile are both
  read through one guard now: the configured path stays relative with no
  traversal, and the checkout itself has to yield a regular file, inside
  the checkout, under a 4 MiB cap checked before the read rather than
  after it. `git clone` materializes symlinks, so a project repository
  could previously commit its profile as a link at any file the
  composing process could reach, and a 2 GiB file could take down the
  one process the whole fleet composes in. The refusal now distinguishes
  missing, symlink, oversized and unreadable, because those send an
  operator to different places.

- **A tool call held by a streaming tool-call guard now reaches the
  client.** The gateway holds every tool-call frame back until the call
  is judged, and for a call that completes at the end of the turn that
  verdict arrives with the stop event, which is also the event the
  gateway turns into the stream terminator. The released frame was
  written after that terminator, so a client that stops reading at
  `data: [DONE]`, which the OpenAI Python and Node SDKs do, received an
  assistant turn carrying `finish_reason: tool_calls` and no tool call
  in it. Turning tool-call governance on is what deleted the tool call,
  and a hook that rewrote the call lost the rewrite the same way. This
  shipped in v1.6.0 through v1.13.0 for an `agent_alignment` guardrail
  in `mode: block`, and in v1.10.0 through v1.13.0 for an extension
  bundle with an `ai_tool_call` hook, on any streamed request whose turn
  ended with a tool call. The released frame now goes ahead of the
  terminator, frames released earlier in the stream keep their arrival
  order, and a stream with no held call is not reordered at all. A new
  counter, `sbproxy_ai_stream_tool_frames_discarded_total`, reports held
  frames that never reached the client at all, split into `blocked` (a
  guardrail ended the stream) and `unjudged` (the stream ended with the
  call never judged), with a panel on the AI gateway dashboard.

- **Aggregation is honest under load and under reload.** The poll phase
  runs under the same bounded pool and round deadline the fetch phase
  already used, so a handful of blackholing git hosts can no longer turn
  a two-minute poll interval into a continuous poll storm against the
  healthy repositories. The per-outcome entry gauges are written on
  every exit, including the two aborts an operator alerts on, so a
  partition that takes out every repository shows as `failed` climbing
  rather than as the last good round standing still. The runtime
  document is re-read every cycle, so a SIGHUP or a config-watcher
  reload reaches the aggregator instead of leaving it composing from the
  document it read at boot. `--dry-run` compares the whole text rather
  than a set of lines, so reordering two entries is reported as the
  change it is, and the printed diff is linear and bounded instead of
  quadratic. `--watch` refuses to combine with `--out`, `--dry-run` and
  `--explain` rather than silently dropping them. And a restart seeds
  its change detector from what the authority is already serving, so it
  does not republish a byte-identical revision and rebuild every
  subscriber pipeline for nothing.

- An `abtest` variant `url` carrying a path now sends the request to
  that path, matching what the same URL does on a `proxy` action,
  instead of dropping it.

- An `ai_schema` transform now refuses an unrecognized `on_failure`
  value at config load instead of treating it as "forward silently", so
  a typo can no longer downgrade a blocking schema check to a no-op.

- An automatic config revert now names the revision it is reverting, so
  a fix an operator pushed while the revert was in flight is no longer
  overwritten by a document older than it. A rollback onto the document
  already running no longer marks that revision as one this node rolled
  away from, which had been flipping the last known good to `reverted`
  on the history panel. A rollback whose blast radius cannot be measured
  now needs the same typed confirmation a restart-class one does, rather
  than applying straight through. A config revision a soak measured as
  bad stays the boot walk last resort after an automatic revert
  annotates it, instead of climbing back to the front. An armed node
  that decides not to revert now counts
  `sbproxy_config_apply_total{outcome="declined"}` and publishes a
  `config_rollback` event with the reason, so a fleet that declined
  everywhere is no longer indistinguishable from one where no soak
  failed.

- **Anonymous x402 callers no longer wait on another wallet's stuck
  payment.** After `/verify` succeeds, the facilitator `payer` is hashed
  onto the intent. Unidentified requests then match only unattributed
  rows. The first stall of a never-verified payer stays route-wide.

- **DLP documentation matches the live request path.** The policy scans
  the request URI and headers. `scan_body` defaults true and
  `body_max_bytes` defaults 16384, but the header-phase policy chain
  snapshots an empty body, so a secret that appears only in the POST
  body is not seen. There is no body rewrite. See
  [docs/configuration.md](docs/configuration.md#dlp) and
  [examples/dlp-catalog/](examples/dlp-catalog/).

- Every CoMP response now comes from the crate's shared body on both
  transports. The oversize refusal and the wrong-method refusal were
  answered by axum itself on the standalone router (`text/plain`, no
  `Cache-Control`, no counter, no decision event); both now return the
  same JSON shape, headers, counter, and event as every other refusal.
  `GET /admin/licensing` also reports `comp.enabled` on every origin
  rather than only on origins without a bridge, so one field answers
  whether a bridge is configured.

- **hmac_auth and bot_auth no longer record an allow when a later
  content-digest check refuses the body.** A signature that verified in
  the header phase used to emit
  `sbproxy_auth_results_total{result="allow"}` and an allowed SIEM
  decision, then answer 401 after the body proof failed. The auth record
  is now deferred until the body proof resolves, so a mismatch is one
  deny. GraphQL inbound binding and the idempotency short circuit take
  the same path.

- The `abtest` action now sets its sticky cookie on a first visit, so a
  client stays on the variant it was assigned instead of taking a fresh
  weighted roll on every request.

- The AI request path no longer overflows a Pingora worker's stack on an
  origin that runs context compression and an `ai_policy` expression
  together. The two relay futures are boxed, so the dispatch state
  machine no longer carries them inline, and a guard now measures the
  size rather than arguing about it.

- The CoMP oversize-body refusal now moves the quote and redeem counters
  and emits a decision event, from the same shared body every other CoMP
  response comes from. It was hand-rolled in both transports and wrote
  neither, so a client looping oversize bodies was indistinguishable
  from no traffic at all.

- The `geoip` policy now loads its database when the config compiles
  rather than on the first request that needs it, so a large database no
  longer stalls a worker thread, and a corrected `database_path` is
  picked up by a reload instead of needing a restart.

- A boot fallback pin reason is scrubbed of URL userinfo and of an
  inline literal echoed by the secret resolver, and flattened of control
  characters, before it reaches GET /admin/config/fallback or a
  Kubernetes condition. POST /admin/config-authority/rollback refuses a
  ?to_revision= query parameter instead of silently running the one-step
  rollback.

- A cascade that never dispatches (credential lock, connect error,
  posture refusal, emptied price-ceiling, or quota-pool reject) no
  longer reports a stale selected_provider on routing-decisions rows.

- A Rego policy whose load-time trial exceeds `budget_ms` no longer
  fails boot. The trial is inconclusive rather than a semantic fault;
  slow requests still deny per-request under the same budget.

- agent_budget now keys on coding-agent User-Agents such as Cursor
  because those entries are in the default agent-class catalog

- Config Validate + save no longer reports a missing `source:` block
  when the editor buffer is invalid YAML for any other reason. A syntax
  error is reported as a config parse failure, and the editor refuses to
  submit leftover `[REDACTED]` markers from the load-time secret mask.

- **Distroless runtime images now use `cc-debian13`.** Fetched
  mistral.rs prebuilts that need GLIBC_2.38 or newer can start.

- **Gateway, worker, and Cloud Build images now ship
  `/var/lib/sbproxy`.** Usage rollups and the keystore can open under
  the documented default path.

- POST /admin/config-authority/publish and rollback now report
  revision_consumed from where the failure happened rather than always
  false: a validation refusal costs nothing, while a failure past the
  reservation has spent a number the counter never reissues. The store
  code covers both sides of the reservation, so revision_consumed rather
  than the code is what says whether a number went. The Kubernetes
  operator bounds a fallback probe pass by wall clock as well as pod
  count, caps the response body it will read from a pod, and refreshes
  the ConfigFallbackActive condition before it refuses a config that
  arms auto_revert, so a cleared pin is no longer frozen True on the CR.

- Refuse ONNX models that keep their tensors in a separate file. An
  operator-supplied model could name any path in an `external_data`
  reference and have the proxy read it (GHSA-h668-6x6g-f8r5); every ONNX
  loader now refuses such a model before opening anything, and
  translates the parsed model with no directory for the runtime to
  resolve against.

- The admin Add/Edit deployment form now sends `cold_start` (default
  `wait`), numeric fields no longer crash submit after typing, and a
  text-selection drag that ends on the modal backdrop no longer
  dismisses the dialog.

- The config authority store writes owner-only files and directories.
  Every bundle it persists was created with the process umask, so a
  signed configuration document was world-readable to any local account
  on the authority host; files are now 0600 and the store's own
  directories 0700.

- The events webhook SSRF allowlist now honors
  `egress.usage_sinks.hosts` when that sub-block is `mode:
  deny_by_default` and `allow_private` is true, so a private collector
  listed there can boot and deliver. Without that trio the guard still
  refuses private addresses.

- The Kubernetes operator asks only pods its own workload created before
  it sends them the admin credential, behind the leader fence and with a
  bounded fan-out, and it re-bounds the reason a pod reports before
  putting it in a CR condition. The ConfigFallbackActive condition keeps
  its lastTransitionTime across passes and is written only when it
  changes, so an SBProxy no longer re-triggers its own reconcile loop,
  and the Service still reconciles while config delivery is suspended.
  sbproxy_operator_config_delivery_total and
  sbproxy_operator_fallback_probes_total make a stopped delivery
  visible.

- Workspace rate-limit AutoSuspend and resume transitions now append to
  the tamper-evident `audit.sink: chain` file. They previously only hit
  the `security_audit` tracing target and `/api/audit/recent`.

- Restarted mesh workers now refute stale leave announcements from their
  previous process, allowing peers to converge after rejoin. Graceful
  shutdown stops membership reception before publishing its final leave.

- NATS event ingestion no longer builds an unused HTTP client before
  connecting to its broker, avoiding TLS initialization and certificate
  loading delays on the first batch.

## [1.13.0] - 2026-08-18

### Security

- **h2 updated to 0.4.16.** RUSTSEC-2026-0258 (low severity): h2 0.4.15
  could queue empty DATA frames without bound on streams the peer never
  drains. The 0.4.16 patch bounds the queue. Lockfile-only change; no
  SBproxy behavior differs beyond the fix itself.

### Added

- **A `federated_servers[]` entry can be `type: local`: tools the
  gateway serves itself, declared entirely in config.** A local tool is
  one of three handlers: a fixed value, one HTTP call, or a
  dependency-ordered DAG of HTTP calls under `steps:`, connected by a
  `${args}` / `${steps}` interpolation language and shaped into one
  response with a `template`, JavaScript, or Lua script. DAG steps run
  in deterministic topological order with per-step CEL `condition`
  gating, per-step retry, `continue_on_error`, and a whole-tool-call
  budget (`steps.timeout`, default 30 seconds, capped at 5 minutes).
  Every outbound step dial goes through the server's own
  deny-by-default egress gate, and a failed step, a throwing script, or
  a template referencing a missing path fails the tool call closed
  through the normal JSON-RPC error path, never a partial result.
  Because local tools publish into the same registry federation does,
  the whole existing governance surface applies with no new wiring:
  RBAC, approval status (a `draft` local server is hidden and refused
  like any other), versioning, argument and result policies, content
  filters, session-flow enforcement, and evidence records.
  [mcp-compose.md](docs/mcp-compose.md) is the field reference;
  [`examples/mcp-local-tools`](examples/mcp-local-tools/),
  [`examples/mcp-compose`](examples/mcp-compose/), and
  [`examples/mcp-compose-js`](examples/mcp-compose-js/) are the
  runnable shapes.

- **`proxy.config_history` keeps a durable ring of every applied
  config, surfaced end to end.** Off by default. When enabled, every
  config this proxy applies (from disk, git, or the config authority)
  is recorded as a content-addressed, zstd-compressed entry holding the
  pre-resolution bytes: a `${VAR}` or `vault://` / `secret://`
  reference never resolves into a stored entry. `keep` bounds the ring,
  and eviction persists the shrunk index before unlinking any blob, so
  a crash mid-eviction can never leave an index naming a blob that is
  gone; a host crash that truncates `index.json`, all the way to zero
  bytes, is repaired on the next open rather than bricking the ring.
  Read it back with `GET /admin/config/history` and
  `GET /admin/config/history/{digest}`, with `sbproxy config history`
  and `sbproxy config show`, or in the admin console's config panel;
  `sbproxy_config_history_entries` and `sbproxy_config_revision_info`
  report the ring on the metrics surface. The admin route and CLI mask
  a literal secret an operator typed into the YAML as `[REDACTED]`, the
  same pass `GET /admin/config` applies; the ring file underneath keeps
  the original bytes, because a rollback needs them, and the
  owner-only directory permissions (`0700`/`0600`) are the real
  boundary on that file. Two honest limits: changing this block takes a
  restart, not a hot reload, and `keep_rejected` is accepted for
  forward compatibility but nothing writes rejected candidates yet in
  this release. See
  [configuration.md](docs/configuration.md#config_history) and the
  [config-history example](examples/config-history/).

- **Raw-body Lua transforms, and per-request context for WASM
  transforms.** A `type: lua` transform mirrors the JavaScript raw
  transform's contract: the body is a string in and a string out, never
  parsed as JSON, so a script can rewrite plain text, XML, CSV, or any
  non-JSON payload, the thing `lua_json` cannot do. It uses the same
  two-tier invocation as `lua_json`: a `transform(body, ctx)` function
  when defined, otherwise legacy top-level code with `body` bound as a
  global. Separately, a `type: wasm` transform can set
  `request_context: true` to receive the same `ctx` document Lua and
  JavaScript transforms get (principal, aipref, TLS fingerprint) as a
  JSON-encoded `SBPROXY_REQUEST_CONTEXT` WASI environment variable,
  scoped to that invocation; stdin is untouched either way. Both new
  shapes are request-dependent (WASM only when the flag is set), so the
  config compiler's existing refusal of a request-dependent transform
  on a response-cached origin covers them too, and a ctx-off WASM
  transform keeps its cacheability exactly as before. See
  [scripting.md](docs/scripting.md) and
  [wasm-development.md](docs/wasm-development.md).

- **PII and secret detections carry bounded position spans.** A
  detection record previously said only "email detected," with no way
  to say where or whether it was one match or a thousand. The PII
  guardrail's decision-audit records, the `dlp` policy's deny reason,
  and MCP `content_filters` logging now carry a bounded list of match
  spans plus a dropped count, using one shared capped span type across
  all three surfaces. Wiring the MCP spans also fixed a real ordering
  bug: `secrets` and `pii` were scanned in sequence against the same
  live document, so a `secrets: redact` hit shifted offsets before
  `pii` scanned; both categories now scan one snapshot taken before
  either mutates anything.

- **`policies: [{type: owasp_api_top10}]` expands into the OWASP API
  Security Top 10 controls the proxy can honestly cover.** A
  compile-time expander synthesizes concrete policy entries per item,
  backing off per piece when the origin already authors an overlapping
  policy, and surfaces a five-state manifest (`enforced`,
  `report_only`, `already_enforced`, `needs_operator_input`,
  `not_covered`) three ways: `GET /admin/owasp-api-pack`,
  `sbproxy plan`, and validation errors naming the knob that completes
  a parked item. The posture is safe by default: `report_only` unless
  `posture: enforce`, and api4's rate pieces synthesize only when the
  operator declares `per_item.api4.rps`, because blind IP-keyed budgets
  behind an undeclared load balancer collapse every client onto one
  budget. api2, api6, and api10 are named `not_covered` with reasons
  rather than pretended at. See
  [owasp-api-top10.md](docs/owasp-api-top10.md) and the
  `owasp-api-top10` and `owasp-api-selective` examples.

### Changed, and worth checking before you upgrade

- **The `dlp` policy now scans request bodies.** It documented body
  scanning and only ever saw the URI and headers; the enforcer received
  the buffered body and never read it. It now scans request bodies by
  default, capped at the first 16 KiB, the same bound the injection
  policy uses. An origin carrying a `dlp` policy starts matching on
  body content the moment you upgrade, so traffic that only ever
  tripped on a header can now trip on a payload: check what your
  patterns match before deploying. Response-side scanning is
  structurally out of the policy phase's reach and stays with
  transforms; [api-security.md](docs/api-security.md) now states
  exactly what each direction covers.

- **The AI PII guardrail's knobs all do something, or refuse.**
  `action: log` was a silent no-op; it now logs the detection (pattern
  type only, never the matched text) and allows the request.
  `action: mask` and `redact_response: true` cannot work under the
  current guardrail signature, so both are now refused at config load
  with an error naming the limitation, instead of being accepted and
  ignored. A config carrying either stops loading on upgrade; the
  refusal is the honest state until per-entity actions land.

- **Enumeration detection fires without `object_rules`.** The
  `object_authz` policy's `enumeration.enabled: true` never counted
  anything unless a declared ownership rule captured an object id,
  which contradicted its documentation as a standalone anomaly
  detector. With no `object_rules` configured it now falls back to a
  path heuristic: a request whose trailing path segment is id-shaped (a
  numeric run or a canonical UUID) counts the whole normalized path as
  the object, so a sweep across `/orders/1` through `/orders/500` trips
  while `/reports/2026/08/` browsing does not. The heuristic counts
  identified callers only (an anonymous flood is never attributed to a
  shared bucket), does constant bounded work per request under a capped
  tumbling window, and its hits are always detect-only: audited to the
  security log and `sbproxy_object_authz_violations_total`, never
  blocking, because both the id shape and the path-to-object mapping
  are guesses. Rule-scoped enumeration, BOLA, and BFLA are unchanged
  and stay fully enforceable, and any configured `object_rules` scope
  detection exactly as before. If you run with `enumeration.enabled`
  and no rules, expect violation records to start appearing on traffic
  that previously counted nothing. See
  [object-authz.md](docs/object-authz.md).

- **`$${...}` is now an escape everywhere the config's `${VAR}`
  environment interpolation runs.** The MCP composition docs define
  `$${VAR}` as rendering a literal `${VAR}`, but the pre-parse layer
  spliced the live environment value first, which could bake a secret
  into the compiled config. The escape is honored end to end now: an
  even run of dollars never substitutes. A config that relied on
  `$${VAR}` splicing a value (none of the shipped examples did) reads
  differently after upgrading.

- **Displayed credential masking covers more key names.** The pass that
  masks secrets in `GET /admin/config`, config-history views, and log
  output now recognizes session tokens, signing and client secrets, and
  the product's own key-name families (`master_key`, `signing_key`,
  `virtual_key`, and relatives), and masks only the value while
  preserving the surrounding structure, so JSON log lines survive
  redaction intact. Operators diffing displayed config against disk
  will see more `[REDACTED]` than 1.12 showed.

### Fixed

- **`codemode.ts` no longer advertises `draft` servers.** The
  TypeScript module served at `GET /.well-known/mcp/codemode.ts`
  rendered the full federation catalog with no approval-status
  filtering, so a `draft` server's tool names and descriptions leaked
  even though `tools/list` and `tools/call` already hid and refused it.
  It now uses the same visibility predicate as `tools/list`;
  `deprecated` servers are unaffected. One caveat is still true and now
  documented rather than conflated with this gap: the module is served
  ahead of per-caller authentication and cached per catalog, not per
  principal, so `rbac_policies` scoping does not reach it. See
  [cloudflare-code-mode.md](docs/cloudflare-code-mode.md).

- **The shipped examples demonstrate what they claim, on camera.** A
  live replay of the example cassettes against the release binary found
  recordings whose payoff commands printed nothing, and two examples
  that could never fire at all. The `sri` example hooked a policy that
  runs in the upstream response phase to a `type: static` origin that
  phase never reaches; it now proxies to a local fixture and the
  violation metric demonstrably increments. The `websocket-proxy`
  example's client could not read a frame over 125 bytes (no RFC 6455
  extended-length decoding); it now speaks full frame lengths and
  demonstrates the oversized-frame cap the README promised.
  `pii-redaction` recorded against a fixture that never echoed bodies,
  so there was nothing to redact; it records against a local echoing
  fixture now. The recording harness probes the admin port (admin bind
  failure is non-fatal, so a stale occupant silently blanked every
  admin payoff), starts each example's fixture itself, and parses the
  `admin:` block by its own indentation instead of grabbing the first
  `port:` anywhere in the file. All affected cassettes are re-recorded
  and frame-verified showing real output.

- **Trace and metric exporters answer to a reload, not just to boot.**
  The egress inventory's boot-time authorization never re-checked the
  boot-built OTLP exporters after a hot reload, so a config that newly
  denies the running telemetry endpoint silently kept exporting; and a
  denied telemetry endpoint stamped the sightings inventory but never
  reached the `egress_refused` counter or the event feed, unlike every
  other purpose. A reload whose config denies a running exporter's
  endpoint is now refused naming the conflict, and telemetry denials
  publish through the same refused-event bridge as everything else.

## [1.12.0] - 2026-08-17

### Added

- **The full MCP surface is governed: content filters, tenant-bound
  sessions, and registry approval status.** `content_filters` runs the
  shared secret and PII detector catalog over tool-call arguments and
  results, and over `resources/read` and `prompts/get` results, with
  `off | warn | redact | block` per category; MCP responses are written
  outside the HTTP `response_filter` phase, so this is the first time
  those detectors see MCP traffic at all. Sessions are tenant-bound: a
  session id presented by a different tenant is refused with the same
  generic error a stranger gets, and session establishment is capped
  (256 per tenant, 4096 globally, sixteen tenants at full sub-cap) with
  a fail-closed refusal of `initialize` at saturation rather than an
  untracked session. `federated_servers[].status` gates the registry:
  `draft` servers are invisible on every listing surface and refused at
  dispatch, `deprecated` serves but warns on every call. The peer
  registry behind downgrade detection carries the same caps; under
  `downgrade: block`, a peer it cannot track is refused rather than
  enforced against no baseline. `result_policies[]` runs the same
  CEL/Rego engine over the tool-call result document after dispatch.
  [mcp-security.md](docs/mcp-security.md) is the narrative;
  [mcp-security-coverage.md](docs/mcp-security-coverage.md) maps
  MCP01:2025 through MCP10:2025 row by row, each claim naming the test
  or example that proves it.

- **Every security decision reaches the SIEM.** A twelfth typed event,
  `egress_refused`, carries every purpose-scoped outbound-dial refusal
  (AI providers, MCP upstreams, token exchange, webhooks, artifact
  fetches) with the same bounded labels its Prometheus series already
  had. All six config-reload paths emit `config_audit` records for
  accepts and rejections, with rejection reasons bounded and scrubbed
  of the config path. mTLS handshake rejections write a
  `security_audit` record with the certificate CN control-stripped and
  bounded on every surface it reaches. Circuit-breaker state
  transitions emit one structured record alongside the existing
  counter. `budget_exceeded`, `guardrail_triggered`,
  `provider_selected`, `ai.failure`, and `ai.close` are wired at their
  decision points, and boot warns when `events.types:` names a type
  nothing publishes. [events.md](docs/events.md) is rewritten as the
  SIEM integration map: which channel carries what, the gapless
  sequence contract, and what deliberately stays off the lossy feed.

- **MCP tool calls emit a governance evidence event, with an optional
  fail-closed guarantee.** The `events:` type list grows to thirteen
  declared types, eleven of which publish today (see
  [events.md](docs/events.md)). The new one,
  `mcp_governance_decision`, carries OTel GenAI/MCP semantic-convention
  attribute names plus sbproxy's own `sbproxy.*` fields (verdict,
  redacted reason, a salted argument hash, and a per-tenant gapless
  sequence number a SIEM can use to detect a dropped record) for every
  dispatched `tools/call`. `events.fail_closed` names event types that
  must never be silently dropped; when `mcp_governance_decision` is
  listed there and the record cannot be queued, the tool call is
  refused with a JSON-RPC internal error rather than served
  un-evidenced, and `sbproxy_mcp_evidence_fail_closed_total{tenant}`
  counts every refusal. Everything else keeps the existing best-effort,
  drop-and-count contract.

- **`mcp_governance_decision` covers tool-definition and registry
  changes, plus an opt-in verbatim-arguments capture.** The
  version-lockfile gate now emits a `tool_definition_changed` record
  (verdict matching the gate's own `mode: block`/`warn` posture, old
  and new contract-digest prefixes, never the contract text) whenever
  a live tool contract moves without a matching declared version bump.
  A federated server's registry approval status transitioning across a
  config reload (`draft`, `approved`, `deprecated`) emits one
  `server_status_changed` record per transition, not one per call.
  New `mcp_audit.capture_arguments` (default `false`) opts a dispatched
  call's record into `gen_ai.tool.call.arguments`: the call's
  arguments, redacted and size-bounded the same way `mcp_audit`'s own
  content fields already are, alongside the salted digest every call
  already carries.

- **Federated MCP servers resist a silent protocol or auth downgrade.**
  `federated_servers[].protocol` pins one upstream to `2025-06-18`
  (the only era outbound federation speaks today; pinning `2026-07-28`
  is a config-compile error until outbound federation speaks it too);
  the default, `auto`, negotiates and remembers, per tenant, the best
  era and strictest auth posture that upstream has ever demonstrated.
  A later contact that looks weaker, a legacy-only answer after
  showing a stronger era, or a successful call needing no credentials
  after having required them (classified from the upstream's real HTTP
  response, a 401/407 for "required" and a clean unauthenticated
  success for "not required"), is a downgrade:
  `federated_servers[].downgrade: warn` (default) logs, counts, and
  emits an `mcp_governance_decision` evidence event with verdict
  `warn`; `block` refuses the call until the operator pins `protocol`
  explicitly or edits that server entry. A refusal emits the same
  event with verdict `deny`, and a `SecurityAuditEntry` policy
  violation; `rule_id` is `peer_downgrade` for an actual downgrade and
  `protocol_pin_mismatch` for a pinned peer answering the wrong era.
  `resources/read` and `prompts/get` reach the same downgrade check for
  the federated peer they contact, alongside `tools/call`.

- **The base MCP connect is gated and inventoried, and federated
  servers get a registry approval status.** `federated_servers[].egress`
  now applies to a plain `type: mcp` server's base connect
  (`streamable_http` or `sse`), not just a `type: openapi` server's REST
  calls; an unconfigured policy is stamped `ungated` rather than
  silently allowed, and every dial's outcome shows up at
  `GET /api/egress` under purpose `mcp_upstream`. A `type: openapi`
  server's egress denial, previously silent, is now recorded there too.
  `federated_servers[].status: draft | approved | deprecated` (absent
  means `approved`, so existing configs are unaffected) stages a
  Draft-to-Approved-to-Deprecated review lifecycle: `draft` hides a
  server's tools from `tools/list` and refuses every call against them,
  naming the status; `deprecated` keeps the server fully callable but
  emits a warn-level `mcp_governance_decision` event on every call.
  Optional `approved_by` / `approved_at` metadata is operator-attested
  and stored, not verified.

- **MCP tool calls can be authorized on their arguments, not just their
  name.** An `mcp` action's `argument_policies[]` evaluates a CEL or
  OPA-compatible Rego expression against the tool-call context
  (`mcp.tool.name`, `mcp.server`, `mcp.session.id`, `mcp.arguments`,
  `mcp.tenant`, `mcp.principal.{sub,team,project,user}`) after RBAC and
  JSON-Schema validation pass and before the call quotas and
  dispatches: a rule can only narrow an already-passed RBAC allow,
  never widen it. `mode: warn` (default) logs and emits a
  `mcp_governance_decision` event with verdict `warn`; `mode: block`
  refuses the call with a JSON-RPC error and verdict `deny`, naming the
  rule as `sbproxy.decision.rule_id`. A rule that cannot be evaluated,
  or whose engine panics, fails closed regardless of `mode`. Optional
  `principals[]` selectors scope a rule to a tenant, team, or project,
  the same shape as the RBAC `tool_access[].principals` rows. Legacy-era
  `tools/call` requests with a compiled contract now also get the
  JSON-Schema check modern-era calls already had.

- **Deterministic session-flow enforcement gates a session that read
  something untrusted and sensitive, then tries to leave (Meta's Rule of
  Two).** An `mcp` action's `flow` block tracks two session-scoped,
  most-restrictive-wins labels that never lower within a session:
  `integrity` (`trusted` -> `tainted`, leg 1) and `sensitive_touched`
  (`false` -> sticky `true`, leg 2). Leg 3 (an externally visible or
  state-changing action) is evaluated fresh at each `tools/call` against
  `flow.outbound_tools`, not stored. A `tools/call` result (or
  `resources/read`) from a server outside `flow.trusted_servers` taints
  the session (unlabeled upstream is untrusted, fail closed); one from a
  server in `flow.sensitive_servers`, or a `tools/call` for a tool
  matching `flow.sensitive_tools`, sets `sensitive_touched` (absent
  sensitivity config reads default-open, unlike `integrity`). The
  default rule, `flow.rule: two_of_three`, is Rule of Two itself: the
  violation is a session with both legs tripped attempting an outbound
  call; the explicit `flow.rule: taint_and_outbound` reproduces a
  strictly stricter pair rule (tainted + outbound, sensitivity not
  considered) for an operator who wants that instead.
  `flow.mode: warn` logs and emits a `mcp_governance_decision` event
  with verdict `warn`; `mode: block` refuses the call before dispatch
  with verdict `deny`; `mode: off` (the default) tracks nothing. Every
  transition and violation carries its own `sbproxy.decision.rule_id`:
  `flow_taint`, `flow_sensitive_touched`, `flow_exfil_block` (the
  default rule), or `flow_pair_block` (the explicit rule). Runs after
  RBAC, per-tool quota, and `argument_policies[]` have already allowed
  the call, and composes with (rather than replaces) `lethal_trifecta`
  and `dual_llm_quarantine`. Without `sessions.enabled: true`, this
  degrades to single-call scope, the same fallback `lethal_trifecta`
  uses. The labels are also exposed on the `mcp` CEL/Rego namespace as
  `mcp.session.integrity` and `mcp.session.sensitive_touched`, so a
  custom `argument_policies[]` rule can compose a policy the two
  built-in rules do not express.

- **A gate refuses Apache-2.0-only crates that NOTICE does not name.**
  `scripts/check-notice.sh` (local `scripts/check.sh` and the CI lint
  job) fails when an Apache-2.0-only dependency is missing a stanza,
  so the next swc-class crate cannot land unattributed.

- **Self-host certification writes a complete `record.json`.** Live Apple
  Metal and GitHub release macos-14 runs emit macOS version, chip, memory,
  engine version, artifact digest, time to ready, and first-token result in
  one file. The Metal probe is compiled by the named `apple_metal_probe`
  lane, and a live launch fails if engine RSS overshoots the planned
  memory envelope by more than 25%.

- **Bundles can make granted outbound HTTP calls.** A JavaScript hook
  may declare `net:outbound=<scheme>://<host>[:port]` destinations in
  its manifest `permissions`, the operator grants them per bundle under
  `extensions.grants`, and a declared destination without a grant
  refuses the candidate at load naming both sets. Granted hooks call
  the synchronous `sbproxy_fetch` host function; every call is
  authorized against the grant, resolution-pinned, redirect-free,
  bounded by the hook's remaining budget, and capped at the sandbox
  buffer limit. The wasm runtimes have no host-call surface and refuse
  declarations at parse.

- **`ai_tool_call` hooks can rewrite tool calls.** A bundle hook
  declaring `execution.mutates: true` on `ai_tool_call` may return a
  `mutate` decision whose rewritten call replaces the held argument
  fragments on the wire as one canonical frame. Rewrites that change
  the call's index, produce non-JSON arguments, or edit a call whose
  arguments were truncated at the stream buffer cap refuse instead of
  shipping approximately. `mutates` combined with
  `enforcement_mode: observe` now refuses at config load, since an
  observe hook's decisions are discarded.

- **`policy: rego` and the AI gateway's Rego routing engine can load a
  module from a file, and accept pre-OPA-1.0 syntax.** `module_path`
  reads a `.rego` file at config-compile time, the same convention
  `transforms[] type: wasm` already uses, and `rego_v0: true` runs
  Regorus's own compatibility switch so a module written before OPA
  1.0's `if`/`contains` requirement parses unchanged. A policy's
  `print()` calls are gathered per evaluation and logged through
  `tracing` at INFO under the `rego_print` target instead of reaching
  the process's stderr.

- **`sbproxy rego test` runs Rego fixtures offline, with line
  coverage.** Point the new subcommand at a fixture YAML file or a
  directory of `*_test.yaml` files and it compiles each module through
  the same engine construction a live policy uses, runs every named
  case, and reports per-module line coverage. `--min-coverage` gates
  the exit code on it, and `--format json` emits a structured result
  for a CI step to parse.

- **Request and response modifiers gained a Rego form.**
  `request_modifiers[]` and `response_modifiers[]` now accept
  `rego_module` / `rego_module_path` beside the existing `lua_script`
  and `js_script`, evaluating `data.sbproxy.modify_request` /
  `modify_response` against the same context document those two
  engines already receive and returning the same `set_headers` shape.
  `rego_budget_ms` bounds the evaluation, matching the `budget_ms`
  knob on `policy: rego`.

- **Signed extension bundles can ship a `.rego` policy module.**
  `runtime: rego` bundle hooks compile at candidate load on the same
  Regorus interpreter `policy: rego` uses, register into the same
  policy registry a config-inline module would, and evaluate the same
  wire-level envelope a JavaScript or WASM policy hook reads. A
  tampered or malformed `.rego` module fails verification like any
  other bundle asset, and the previous bundle keeps serving.

### Changed, and worth checking before you upgrade

- **`proxy.messenger_settings` refuse names the deleted bus defects.** The
  block was already refused. The error now says GCP Pub/Sub and SQS
  acknowledged before yield, treated errors as end-of-stream, and could
  not stop on drop, and that a replacement needs an async Stream with
  cancellation (WOR-2192). Remove the block; config distribution is
  `proxy.config_authority` and cache invalidation is
  `POST /admin/cache/purge`.

- **A broken `ai_policy.expression` now refuses the config instead of
  disabling itself.** A syntax error, or a reference to a binding
  outside the `ai` namespace, previously logged one error and booted
  the proxy with the policy silently absent; it now fails boot and
  reload with a message naming the expression, like every other CEL
  surface. If your config stops loading on upgrade, the expression was
  never running; fix the typo and the policy starts enforcing.
- **The response cache now stores the transform chain's output.** On an
  origin combining `response_cache` with `transforms`, entries hold the
  transformed body, hits serve what misses ship, a closed transform
  refusal blocks admission, and a request-dependent transform on a
  cached origin refuses at config load. All existing response-cache
  entries are retired on upgrade (one cold start per key), so an
  upgraded node can never replay a pre-transform body as a hit.
- **A configured origin now owns `/health` on the data plane.** Until
  now the proxy answered `GET /health` itself with a fixed
  `{"status":"ok"}` before any origin routing ran. It now proxies the
  path like any other when an origin or forward rule matches it. If a
  load balancer probes `/health` **with a configured origin's Host
  header**, that probe now reaches your upstream, and an upstream with
  no `/health` route answers 404, which a health checker reads as
  unhealthy. Point such probes at the admin listener's health route, or
  make sure the upstream serves the path. Probes against the pod IP or
  an unconfigured Host still get the built-in response.
- **`timeout_ms` on an AI provider is now enforced.** The key
  previously validated and did nothing. It bounds one dispatch attempt
  wall-clock from connect through the end of the response body, so a
  streaming completion that runs past it is severed mid-stream; each
  retry attempt gets a fresh window, so worst case is
  `(timeout_ms + backoff) x (max_retries + 1)` per provider. A config
  carrying a forgotten low value starts cutting requests off on
  upgrade: check yours before deploying.
- **The `outcome` label value `auth_denied` split in two.** Gateway-side
  refusals and upstream auth failures were one value and are now
  distinguishable; dashboards keyed on `outcome="auth_denied"` need
  updating. Usage rollups keep the legacy mapping.
- **Single-tenant traffic now reports workspace `__default__`, not
  `default`.** The rate-limit budget enforcer's workspace label on
  `sbproxy_rate_limit_total` and `sbproxy_rate_limit_decisions_total`,
  and the `target_id` on the matching rate-limit audit records, moved
  to the synthetic `__default__` tenant name used elsewhere in the
  multi-tenant work. Budget behavior is unchanged; only the label
  value moved. Dashboards or alerts matching `workspace="default"`
  need updating to `workspace="__default__"`.
- **Meter receipts now fold extra attempts under `billable.retry: collapse`.**
  Provider fallback and HTTP origin retries previously billed only the
  final attempt as `delivered`, so the `retry` outcome never ran. Extra
  attempts are recorded as `retry` and collapse; the receipt that bills
  remains `delivered`. Exhausted retries that still end in 4xx/5xx keep
  those outcomes.
- **The Kubernetes operator image builds inside Docker.**
  `crates/sbproxy-k8s-operator/Dockerfile.ci` compiled on the host and
  copied a `target/` binary that `.dockerignore` excluded (and that was
  the wrong platform on macOS/Windows). The documented
  `docker build -f crates/sbproxy-k8s-operator/Dockerfile.ci .` path now
  compiles in a Linux builder stage.

### Fixed

- **A prefix-namespaced MCP tool call now reaches its upstream.**
  Since the dual-revision release, the federation advertised namespaced
  tool names (`reports.hello`) but also forwarded that advertised name
  on `tools/call`, so an upstream serving the bare name refused every
  dispatch with "Unknown tool". Tools now keep the name the upstream
  advertised, the way prompts and resources always did, and dispatch
  forwards it; the governance-pack e2e's mock upstream now refuses
  prefixed names the way real upstreams do, so this cannot regress
  silently.

- **NOTICE names the 27 Apache-2.0-only crates it previously omitted.**
  Most of them are the swc TypeScript and JavaScript toolchain reached
  through `sbproxy-extension`, plus `unicode-general-category`. Apache
  2.0 section 4(d) requires those stanzas on every redistributed binary.

- **Anthropic multi-tool-call streams now close every content block.**
  The Messages SSE emitter opened a `content_block_start` per tool call
  but always emitted `content_block_stop` at `index: 0`, so a native
  Anthropic client watching a stream with two or more tool calls saw a
  mismatched block lifecycle.
- **Gemini empty generateContent bodies no longer look like successes.**
  A 2xx response with no `candidates` (typically a prompt-level safety
  block carried in `promptFeedback`) was translated into an OpenAI
  completion with empty content and `finish_reason: stop`. Those bodies
  now surface as an error envelope, keep the billed `usage` counts, and
  use the `content_filter` taxonomy when Gemini named a safety block.
  HTTP 4xx/5xx Gemini envelopes were already relayed unchanged.
- **llama.cpp and mistral.rs Model Host provisioning on the official
  Docker image.** Engine release extract shelled out to `tar`, which the
  distroless gateway image does not contain. Archives unpack in-process.
- **Jobs admin table overflow.** A long artifact digest pushed the
  Updated column past the content panel. Shared `.sb-table` styles now
  wrap long cells and the Jobs table scrolls inside the panel.

## [1.11.0] - 2026-08-10

### Added

- **A tamper-evident security audit trail, behind `audit.sink: chain`.**
  The security audit log was a tracing stream and an in-memory ring, which
  means it recorded what the proxy said rather than what happened: whoever
  could write the log file could edit a line, delete one out of the
  middle, and leave nothing behind that said so. Setting `audit.sink:
  chain` with a `path` and a `sign_with` now additionally appends every
  `security_audit` event to a SHA-256 hash-chained, Ed25519-signed file.
  Editing a record breaks its own digest and every link after it; deleting
  one leaves a gap in a contiguous sequence; rewriting the file wholesale
  produces a chain that no longer verifies against the published key.
  `sbproxy audit verify <path> [--signing-seed-hex ...]` re-derives the
  chain from genesis and exits 1 with the first broken record, reading the
  file and nothing else, so an auditor can check a trail the proxy that
  wrote it no longer has.

  None of this is new cryptography. It is the hash chain that already
  carried metering receipts and LLM spend, bound to a third payload; the
  signing identity is the proxy's existing `proxy.web_bot_auth` keypair,
  the same one `proxy.attestation.sign_with` names, so a deployment that
  already publishes that key does not acquire a second key-distribution
  problem by turning this on. The chained record is byte-for-byte the
  record the `security_audit` tracing target already ships, so a SIEM's
  copy and the chain's copy cannot disagree.

  A chain that will not open fails the boot rather than degrading, which
  is the opposite of what the metering chain does with an unopenable
  ledger and deliberately so: billing can be reconciled after the fact and
  an audit hole cannot. `config_audit`, `key_audit`, and the admin-action
  ring are not chained yet.

- **Trace spans on the ordinary proxied request, not only on the AI
  gateway.** A plain proxied HTTP request produced no span at all: it went
  through origin resolution, an auth provider, an enforcer chain, an
  upstream call, and a transform chain, and the only ways to see where the
  time went were a metric with no per-request identity and an access-log
  line with no phase breakdown. Meanwhile three of the
  `sbproxy.<pillar>.<verb>` names had been published as the span-naming
  convention for long enough that operators had built trace queries on
  them, and nothing emitted any of them. Four spans now cover the request:
  `sbproxy.intake.accept` over the whole inbound phase and parent of the
  rest, `sbproxy.intake.authenticate` per authentication check,
  `sbproxy.policy.enforce` per enforcer, and `sbproxy.transform.shape` per
  response-body transform. Their attributes are the HTTP method, the auth
  provider type, the policy type, and the transform type, all of which are
  already bounded metric labels; nothing caller-supplied and no part of the
  request target rides along. The upstream connect and send, and the
  response header filter, still have no span, because the pillar
  vocabulary names neither phase.

- **A top-level `request_events:` block, so the request events the proxy
  already builds can leave the process.** Every terminating request was
  populating a full event envelope (tenant, session, credential id,
  provider, model, token counts, cost, guardrail verdict, status, geo)
  and then handing it to an implicit no-op, because nothing in the boot
  path ever registered a sink. Three kinds ship: `none` (the default,
  and the behavior every earlier build had), `logging` (one JSON line
  per event on the `request_event` tracing target), and `file` (NDJSON
  appended to `path`). The file sink writes on its own thread behind a
  bounded queue, so a slow disk cannot add latency to the request that
  produced the event; a full queue discards the incoming event and
  increments
  `sbproxy_telemetry_dropped_total{kind="request_event",reason="queue_full"}`
  rather than losing it quietly. A `file` sink with a missing or
  unopenable `path` warns at startup and falls back to `logging`.

- **A ratchet on `.unwrap()`, `.expect(..)`, and `panic!` in production
  code.** Each ends the process on a path a caller cannot catch, which in a
  proxy means a dropped request rather than an error a client can act on. The
  count is allowed to fall and never to rise, so existing sites can be cleaned
  up opportunistically while no new ones land. `panic!` is tracked separately
  with a baseline of zero, since production code has none today and that is
  worth locking rather than trading against an unwrap someone removed.

- **Extension bundle manifests can declare `secret_vars` and
  `masked_vars` on a hook.** A `secret_vars` property is resolved
  through the same secret reference forms (`${VAR}`, `env:NAME`,
  `file:`, or a provider URI) any other secret-bearing field accepts,
  once, when the bundle candidate loads; a `masked_vars` property is
  never resolved but is still kept out of logs, errors, and
  diagnostics. Neither list can name a property `config_schema` does
  not declare, and a property cannot appear in both. Masked values
  render with their length and an HKDF-derived fingerprint rather than
  a bare placeholder, so an operator can tell two values apart without
  the value ever being logged.

- **`env:NAME` now resolves through the same secret resolver as every
  other secret-bearing field.** Three call sites (JWKS auth, a vault
  backend, and one CEL helper) hand-rolled their own `env:NAME` parsing
  outside `SecretResolver::resolve()`, so a field that accepted
  `${VAR}`, `file:`, and seven provider URIs still refused the bare
  `env:NAME` spelling everywhere else. It now resolves identically
  wherever any other secret reference does, with the same
  missing-variable error.

- **`localsecret://` replaces the overloaded `secret://` scheme name.**
  `secret://` reads as "any secret" but has only ever named one
  specific backend, the local-secret provider, which is exactly the
  kind of mismatch that led one deployment to misread
  `secret://env/NAME` as an env-variable alias. `secret://` keeps
  working, with a once-per-process deprecation warning identical to the
  existing `vault://<alias>` mechanism. The scheme-validation table in
  `sbproxy-config` also gains an entry for it; previously it wasn't
  recognized there at all and silently skipped validation against
  `proxy.secrets.backends`.

- **Forward rules can match on a field inside the JSON request body.**
  A rule now accepts an RFC 6901 JSON Pointer matcher, ANDed with the
  existing path, header, and query matchers. The motivating case is AI
  traffic, where the model name lives in the body on OpenAI, Anthropic,
  and Bedrock shapes: routing different models to different origins
  used to mean cramming everything into one `ai_proxy` action sharing
  one auth config, one policy chain, and one transform set. The cost is
  opt-in: an origin with no body matcher never buffers a body for this
  purpose, and a body that's too large or not JSON just falls through
  to header-only matching instead of failing the request.

- **`origins.*.timeouts` makes the five upstream deadlines configurable
  per origin.** Connect (5s), total-connect (10s), read/write (30s),
  and idle (90s) were hardcoded with no config path at all. They're now
  set via `connect_ms`, `total_connect_ms`, `read_ms`, `write_ms`, and
  `idle_ms`, resolved at config compile; a zero value is refused. The
  legacy, previously inert `connection_pool.idle_timeout_secs` now
  feeds the same resolved idle timeout and is promoted from
  config-only to stable, and authoring both spellings on one origin is
  a compile error. A forward rule's inline origin inherits its
  parent's timeouts.

- **The configured A2A agent card is now served at its well-known
  path.** `agent_card` has been storable on the `a2a` action, but
  nothing served it: a request to `/.well-known/agent-card.json` just
  proxied through like any other path. It's now served pre-auth
  (matching sbproxy's other discovery surfaces), GET-only, at the
  ratified A2A 1.0 path plus two legacy aliases. The card is validated
  as a typed `AgentCard` at config compile, so a malformed card is a
  boot error rather than a runtime surprise, and its URLs are rewritten
  to advertise the proxy host through the same mechanism the
  `a2a_agent_card_rewrite` transform uses.

- **Forward rules can match on HTTP method.** A rule that should route
  `POST /webhook` differently from `GET /webhook` had no way to say so.
  A `method:` field, single value or list, is normalized to uppercase
  and validated against `http::Method`, and it's evaluated first in the
  rule's match chain since it's the cheapest, non-capturing test to run
  before path, header, and body predicates.

- **Origin hostnames can start with `*.` for wildcard routing.**
  Hostnames could previously only match exactly, so a per-subdomain
  product (`*.tenant.example.com`) needed one origin block per literal
  hostname actually in use. A wildcard origin key now matches on the
  longest matching suffix after an exact match fails, Envoy-style,
  across both the request-path router and the admin snapshot lookup.
  Configs with no wildcards keep the existing bloom-filter fast-reject
  path unchanged, so this costs nothing for anyone not using it. Docs
  that already (incorrectly) claimed one-level wildcard support now
  match the code.

- **`sbproxy ai ledger report` reads the AI value ledger offline.** The
  local-versus-cloud spend and savings ledger was only queryable
  through the admin HTTP endpoint, and the docs had long promised a CLI
  subcommand that was never built (and has since been retracted from
  the docs it was promised in). The new subcommand reads the redb
  ledger file directly, the same pattern `ai ledger verify` already
  uses, and prints the identical report as text or JSON, with the JSON
  matching the admin endpoint's schema byte for byte. Useful for
  scripting, air-gapped nodes, or CI cost reporting where hitting the
  admin API isn't an option.

- **`algorithm: ring_hash` adds consistent hashing to the load
  balancer.** The existing hash-based algorithms used a plain modulus
  over the target list, so any pool resize, a scale-up, a scale-down,
  an unhealthy target dropping out, reshuffled most keys' target
  assignment and defeated session or cache affinity at exactly the
  moment it mattered. `ring_hash` implements ketama-style consistent
  hashing (160 virtual nodes per target by weight, FNV-1a plus a
  splitmix64 finisher), so only the keys owned by a target that joins
  or leaves the pool actually move. Health is applied at lookup time by
  walking the ring, so an unhealthy target doesn't require rebuilding
  it. The `sticky:` block, which parsed and produced a boot warning but
  never issued an affinity cookie, is now a hard config-compile refusal
  that points at `ring_hash` instead, and a dead `ConsistentHash`
  scaffold built on a non-deterministic per-process hasher, which would
  have disagreed across replicas had it ever been wired up, is deleted.

- **An `examples/admin-mcp` reference config lets an agent client
  manage a running proxy over MCP.** No MCP server exposed SBproxy's
  own admin API before this, so Claude Code, Cursor, or any other MCP
  client couldn't manage a proxy the way it could manage other
  infrastructure. It reuses the existing OpenAPI-to-MCP-tools converter
  against a curated, hand-written admin API spec (the live
  `/api/openapi.json` only describes the data plane, so no generated
  admin spec exists to point at). `openapi` federated MCP servers also
  gain a static `headers:` map for service credentials like HTTP Basic,
  since outbound MCP auth previously only supported per-caller
  run-as-user Bearer tokens and failed closed for anonymous callers; a
  minted per-call header always wins over the static one, so
  run-as-user auth can't be shadowed by it. `headers:` on a
  non-openapi server, or combined with `run_as_user_auth`, is a config
  error. The shipped example's tool surface is read-only by default,
  held there by three independent gates (the curated spec, RBAC, and
  `tool_allowlist`), so exposing any mutating admin action takes
  deliberately editing at least two of them.

- **The MCP gateway federates `prompts/list` and `prompts/get`.** Both
  previously returned JSON-RPC `-32601`, method not found, for every
  caller, so an agent client built around MCP prompts rather than tools
  got nothing through the gateway even when the upstream server it
  wanted supported them. They now federate the same way `tools/list`
  and `tools/call` already do: aggregated across upstream servers under
  the existing name-prefixing scheme, and routed back to the owning
  server by namespaced name. The `prompts` capability is only
  advertised in `initialize` when at least one upstream actually
  declares it, and access follows the server's existing
  `rbac_policies` entry rather than a new config key. Five other
  unimplemented MCP methods are unchanged and still return `-32601`.

- **`model_aliases` now actually does something.** The config key
  parsed and was silently ignored, since `ConfigFile` has no
  `deny_unknown_fields` to catch it, and the documented workaround,
  per-provider `model_map`, doesn't cover the same case: `map_model`
  only runs after a provider is already chosen, so it can rename a
  model on the way out but has no say in which provider gets picked,
  which is non-deterministic under round-robin routing. Aliases now
  resolve before provider selection on all three AI dispatch paths,
  with an optional provider pin that narrows candidates rather than
  falling through to a provider that can't serve the aliased model.
  Config load rejects an alias that shadows a served model, a
  `model_map` key, or the default model, plus duplicate aliases,
  self-reference, alias chains, and a pin at a provider that can't
  serve the target. A second bug closed in the same change: on the
  non-POST dispatch path, credential-level model gates were checked
  against the pre-alias name, so an alias could previously be used to
  reach a model a credential's block list was supposed to forbid.
  That's now closed and pinned by a regression test.

- **`digest_scope: bundle_v1` covers a whole extension bundle, not just
  its entry file.** An extension bundle's `sha256` previously covered
  only the JS or WASM entry artifact; `bundle.yaml`, which declares
  hook kinds, sandbox limits, `failure_posture`, and `permissions`, sat
  outside the digest and could be widened (`permissions: []` and
  beyond) without breaking verification. Under `bundle_v1`, the digest
  is computed over a sorted, path-plus-content-hash index of every
  regular file in the bundle directory, including `bundle.yaml` itself
  with its own `sha256:` line stripped first. Symlinks, non-UTF-8 or
  control-character filenames, and oversized bundles are refused
  outright. `digest_scope: entry`, the old whole-entry-file behavior,
  stays the default, so existing bundles load unchanged.
  `scripts/bundle-digest.sh` computes a `bundle_v1` digest for bundle
  authors.

- **The Kubernetes Gateway API controller ships in OSS for the first
  time.** It watches `Gateway`, `HTTPRoute`, and `GRPCRoute` resources
  and renders an `sb.yml` from them, in a new `sbproxy-k8s-controller`
  crate (`deploy/k8s/gateway-controller/`, `docs/gateway-api.md`). It
  also fixes a real bug carried over from the closed-source tree it's
  ported from: the generator emitted forward rules using a `path`
  field the config schema doesn't accept, so any `HTTPRoute` with a
  non-root `PathPrefix` produced a document sbproxy couldn't parse, and
  the data plane kept serving stale config while the controller logged
  success. Enterprise-only pieces, a non-Gateway-API custom CRD and a
  `bincode` dependency banned under RUSTSEC-2025-0141, were dropped
  rather than ported. Generated output is now deterministic, sorted,
  where it previously churned on hash-iteration order.

- **Seven more outbound helper call sites inject W3C trace context.**
  Only one of 49 production files making outbound HTTP calls injected
  `traceparent`, and the docs' own list of exceptions was wrong in both
  directions and missed the request mirror, webhooks, JWKS, and forward
  auth entirely. Ledger redeem, the Web Bot Auth directory fetch,
  webhooks, OAuth and OIDC token exchange, and forward auth now inject
  it too, with the trace context threaded explicitly through the
  `tokio::spawn` boundaries that would otherwise drop the ambient span.
  Two duplicate-header bugs came out of the same pass: the request
  mirror and forward auth were both copying the inbound `traceparent`
  verbatim, which would have put two headers on the wire the moment
  injection was added on top. Coverage across all outbound call sites
  is now enforced by a build-time guard.

- **RFC 9421 message-signature verification adds ECDSA-P256 and can now
  actually check a covered body.** Inbound signature verification only
  recognized `hmac-sha256` and `ed25519`; `ecdsa-p256-sha256` (RFC 9421
  section 3.3.5) is now supported too, through `ring`, so a caller or
  partner signing with ECDSA-P256 is no longer refused outright.
  Separately, and more seriously: a signature claiming to cover
  `content-digest` could never actually be checked against the body,
  because the verifier was always invoked with an empty body regardless
  of what the signature claimed to cover. It's now an explicit, typed
  decision through a new `BodyBinding` enum: `Enforce` checks a covered
  `content-digest` against the real bytes and fails the signature on a
  mismatch, `Defer` is for the one call site that verifies headers
  during auth and completes the body check later in the body filter,
  and a caller that claims body coverage with no body available is
  refused rather than marked verified. Before this fix, a forged or
  tampered body could pass signature verification whenever the
  signature covered the digest, because the digest itself was never
  checked.

### Changed

- **A payment stuck in reconciliation now withholds fresh 402 challenges
  from the payer it belongs to instead of from every payer of the route.**
  The guard that stops a second bill for content whose first payment may
  already have moved money was keyed on `(tenant, origin, route)` alone,
  because no column in the settlement store said anything about who was
  paying. One stranded payer therefore took a route's revenue to zero for
  everybody, and on x402 there is no status query to end it, so a
  facilitator outage could hold a hot route at 503 for its whole duration.
  Settlement intents now carry a payer scope key, and the guard matches on
  it. The key is a salted HKDF derivation, under its own purpose, of the
  caller identity the request already proved: an authenticated inbound key,
  or an agent identity from a verified Web Bot Auth `keyid` or a
  forward-confirmed reverse DNS match. A `User-Agent` match and the client
  IP are both excluded, the first because any client can assert one and the
  second because egress pools and NAT make it neither stable nor unique.
  The key never leaves the settlement database: it is not a metric label,
  not a log or tracing field, and not part of any response. Intents written
  by earlier builds carry no scope key and keep withholding route-wide, as
  does any intent minted for a caller this proxy could not identify, so an
  upgrade in flight cannot turn one of them into a double charge.

- **Boot and every SIGHUP reload now warn when `key_management.inbound.provider_hints`
  recognizes a native provider credential that no `inbound.native_key_policy`
  admits.** `provider_hints` ships non-empty by default and
  `native_key_policy` defaults to absent, so simply enabling
  `key_management` was enough to silently refuse every native provider key
  with a 403, with nothing at boot or in `sbproxy validate` to say so. The
  new WARN names the recognized providers so the gap is visible before a
  caller hits it.

- **`compression.level` is applied to the response encoders instead of being
  parsed and dropped.** The configured value is clamped into whichever
  algorithm the client negotiates (gzip 0-9, brotli 0-11, zstd 1-22), so one
  number stays meaningful across the three codecs. Leaving it unset keeps the
  previous behavior exactly: gzip and zstd library defaults, brotli
  quality 4.

- **`response_modifiers[].status.text` is emitted as the reason phrase on the
  HTTP/1.x status line instead of being parsed and dropped.** A modifier
  that sets `status: { code: 418, text: "I am a teapot" }` now puts that
  phrase on the wire for proxied, static, and plugin-action responses.
  HTTP/2 has no reason phrase on the wire, so the value is ignored there,
  and a `status` block without a `text` keeps the canonical phrase for its
  code.

- **Config compile now warns when `invalidate_on_mutation` is combined with
  the `file` or `memcached` response-cache store.** Both backends hash their
  cache keys, so the prefix scan behind mutation-driven invalidation has
  nothing to walk: a POST or DELETE evicted nothing and entries only fell
  out by TTL, silently. The warning names each affected origin and points at
  the `memory` and `redis` backends, which can purge by prefix, and at
  `invalidate_on_mutation: false` for deployments that accept TTL-based
  expiry.

- **`proxy.scripting.javascript.sandbox` now tunes the live QuickJS
  engines.** The block parsed and nothing read it, so every JavaScript
  surface ran the built-in 100 ms budget, 16 MiB heap cap, and 1 MiB stack
  cap however the operator authored it. It installs into a process-wide
  handle at boot now, the same mechanism the Lua half has used since the
  block was introduced, and refreshes on SIGHUP, admin reload, and the
  filesystem watcher. Every JavaScript engine is built per invocation, so a
  reload reaches the next script with no restart. The limits apply to
  response modifiers, `javascript` and `js_json` transforms, WAF custom
  rules, MCP adapters, and `engine: js` custom log fields alike.

- **`key_management.crypto.pepper`/`master_key` and
  `cluster.security.shared_key` can now resolve through any configured
  secrets backend.** These fields previously accepted `env:NAME`,
  `file:PATH`, or an inline literal, but refused a provider-URI
  reference like `vault://` or `awssm://` even when a secrets backend
  was already configured for everything else. They now delegate to the
  installed process resolver when one exists, so the crypto pepper,
  master key, and cluster shared key can come from any backend the rest
  of the config uses, not just env or file. MCP run-as-user credential
  lookups gain the same resolver support, keeping the existing
  bare-variable-name shorthand. `validate_shared_key_reference` also
  stops silently under-validating: it previously only recognized
  `vault://` by name and let the other six provider schemes fall
  through to a length check as if they were inline entropy. The runtime
  path already caught a bad value here, so this closes a validate-time
  message gap rather than a live bypass.

- **cert-manager is now the recommended path for TLS on Kubernetes, and
  the operator refuses the configurations that can't work.** Reconcile
  previously rolled out a multi-replica deployment with
  `proxy.acme.enabled: true` on a pod-local cert store without
  complaint, which doesn't work: every replica opens its own ACME order
  for the same hostname, risking Let's Encrypt's five-per-week
  duplicate-certificate limit, and a load-balanced HTTP-01 challenge
  fetch often lands on a replica that never opened the order. Reconcile
  now refuses that combination outright when `spec.replicas > 1` and
  ACME is enabled on a pod-local backend (`file`-backed and remote
  backends are unaffected), recording the error on `status.lastError`
  and requeuing rather than rolling out. The docs now lead with
  cert-manager plus Ingress-terminated TLS as the recommended
  Kubernetes path, with worked examples.

### Removed

- **Five config keys that parsed, warned, and governed nothing.**
  `origins.*.connection_pool.max_connections`,
  `origins.*.connection_pool.max_lifetime_secs`,
  `origins.*.traffic_capture`, `origins.*.sessions.ttl_seconds`, and
  `proxy.device_parser_file` were all accepted with a boot warning and
  then ignored for the life of the process. Each now fails config compile
  with a message naming the surface that does the job.

  The warning was the wrong response for these. It fits a key whose
  behavior is narrower than its name suggests, which is why
  `cors.enable` still gets one. Four of these five name a resource limit
  or a retention window, so a config that set one kept claiming a
  property the proxy did not have, and nobody rereads a boot log from
  three months ago.

  None of them was waiting on plumbing. The two pool limits have no
  primitive behind them: the upstream keepalive pool is sized once per
  connector rather than per origin, so `max_connections` had nowhere to
  go, and the pool has no age-based eviction at all, so
  `max_lifetime_secs` never retired anything. `traffic_capture` was
  accepted as a free-form value, so nothing read it and nothing
  validated it either. `sessions.ttl_seconds` described the retention of
  an index that does not exist; sessions age out of the admin
  recent-request ring on entry count. `proxy.device_parser_file` named a
  file no code path opens.

  Migration, in order: a `concurrent_limit` policy for
  `max_connections`, `timeouts.idle_ms` for `max_lifetime_secs`,
  `mirror` for `traffic_capture`, `sessions.budget` for
  `sessions.ttl_seconds`, and nothing for `device_parser_file`. Each key
  still parses, so the failure is an explanatory diagnostic rather than
  an unknown-key error.

  `origins.*.connection_pool.idle_timeout_secs` is unaffected. It is the
  legacy spelling of `timeouts.idle_ms` and is live.

- **`audit.sink: tracing`.** It never selected anything. Emission to the
  `config_audit`, `security_audit`, and `key_audit` targets has always been
  unconditional, so `tracing` and `memory` described the same proxy, and
  the key was documented as compatibility-only for exactly that reason.
  Now that `audit.sink` does select something, a value that selects nothing
  is the failure the rest of this entry is about. A config that still names
  it fails config compile with a message pointing at `memory` for the same
  behavior under an honest name, or `chain` for a trail that survives a
  restart. `audit.path` or `audit.sign_with` under any sink other than
  `chain` is refused on the same grounds: a path nothing writes to looks
  configured and is not.

- **The origin-level `rate_limit_headers:` block.** It parsed but was never
  consumed: `X-RateLimit-*` and `Retry-After` are emitted by the
  rate-limiting policy's own `headers` block, and were even while the
  origin-level key was accepted. A config that still carries the block now
  fails config compile with a pointer at the policy-level configuration
  instead of silently doing nothing.

- **`allowed_hosts:` on the `wasm` transform.** It parsed and was never
  enforced, and it could not have been: a module gets no sockets here at
  all, neither WASI networking nor a host callout function, so the
  allowlist named a boundary nothing checked. That is the worst shape a
  security key can have, because an operator who writes one believes the
  boundary exists. An authored key now fails config compile with an error
  saying so and pointing at the proxy-side alternatives. If host callouts
  ever land, the key returns as an enforced one that fails closed from its
  first day rather than an inert one already in circulation.

- **`on_request:` on the `cel` transform.** It was compiled at config load
  and then never evaluated, because there is nowhere for it to run:
  transforms in SBproxy are response-side, driven off the response body
  buffer. Accepting it read as a broken request-phase feature rather than
  an absent one. An authored key now fails config compile and names the CEL
  surfaces that do run at request time: an `expression` policy to gate the
  request, a rate-limit or WAF `key:` expression to key on it, or a forward
  rule to route on it.

- **The AI gateway's context-overflow decision layer, and the
  `context_overflow:` block the docs said it read.** The block was never a
  field on the AI handler, and the code behind it, a pair of functions
  returning an action of error, fall back to a larger model, or truncate,
  was never called from anywhere. The AI gateway guide described the key as
  parsed and ignored, which is an invitation to write it and wait. None of
  the three actions was worth wiring as written. Truncating an oversized
  prompt is the `window_fit` compression lever, which ships; the deleted
  code only named truncation as a recommendation and never trimmed a
  message. Erroring took an estimated token count as its input, so a prompt
  the provider would have accepted could be refused before it was ever sent.
  Rerouting to a model with a larger window needs a config surface nobody
  designed, since no key names the model to reroute to. An authored
  `context_overflow:` now fails config compile with an error naming the
  compression settings that do fit a prompt to the window. The window
  registry the module also held is untouched and still live: compression
  reads it to size a model's budget, and it now sits in `context_window`, a
  file named for the one thing left in it.

### Fixed

- **`proxy.observability.log.level` and `.format` now reach the process
  logger.** Both parsed, both validated, and neither was ever installed: the
  binary resolved the startup filter from `--log-level`, `SB_LOG_LEVEL`, and
  `RUST_LOG` and never opened the config file for it, so an operator who
  wrote `level: debug` in `sb.yml` got `info` with nothing anywhere saying
  why. They are now the rank below `RUST_LOG` in one documented order: the
  flag wins, then the environment variable, then YAML, then the built-in
  `info` and `compact`. A deployment that exports `RUST_LOG` today resolves
  to exactly what it resolved to before, and that override is pinned for the
  life of the process so a later config reload cannot demote it.

  `level` also picks up a config reload, through the same handle
  `PUT /admin/log-level` uses, so SIGHUP applies an edited filter without a
  restart. `format` does not and cannot: the output layer is built once at
  startup and only the filter sits behind a reload handle. Changing it still
  needs a restart, and an unrecognized value is now named on stderr and
  falls back to `compact` rather than being silently accepted. The
  precedence table, the reload split, and the admin-API interaction are in
  `docs/observability.md`.

  `proxy.observability.log.sampling` is not fixed and is now described
  accurately. Its note used to say the process logger runs fixed sampling
  defaults, which reads as though some rate applies. None does: the emitter
  has no sampling call site at all, so every level ships at 100% whatever
  the three rates are set to. Throttling request logs is
  `access_log.sample_rate`, which is a different key with a live consumer.
- **OCSP stapling asks the responder a real question, so it can work at all.**
  Refusing to staple a `malformedRequest` stopped the proxy sending bytes no
  client could verify, and it left stapling inactive rather than active and
  wrong: the fetch still built no OCSP request, so there was nothing a
  responder could usefully answer. It now sends the request RFC 6960 defines,
  a POST of `application/ocsp-request` carrying a `CertID` that names the
  certificate by its serial number and by hashes of its issuer's name and
  public key. The issuer is read out of `tls_cert_file`, matched by
  comparing the leaf's issuer name against each certificate's subject name
  rather than by position, so a chain written in an unusual order still
  produces the right question and a file holding only the leaf is refused
  with a message that says to configure the full chain.

  Two checks came with it, both of which a fetch can pass without and both
  of which decide whether the answer means anything. The HTTP status is
  checked before the body is read, because `reqwest` reports a 4xx as a
  completed transfer and an error page otherwise arrives as bytes like any
  other. And the `CertID` on the response is matched against the one that
  was sent, so a responder, or anything on the plaintext hop to it, cannot
  answer `good` about a different certificate and have that stapled to
  every handshake. Both refusals count as
  `sbproxy_ocsp_fetch_total{result="unknown_status"}`.

  The responder's own signature is still not verified. A client that reads
  the staple verifies it against the issuer itself, so a forged response
  cannot make a revoked certificate look good; what it can do is cost
  connections to clients that check. Stapling still covers the manual
  fallback certificate only.

- **A stapled OCSP response that no client could verify is no longer sent.**
  The fetch never built an OCSP request. It issued a plain GET against the
  responder URL in the certificate's Authority Information Access
  extension, and a responder told nothing about a certificate cannot answer
  for one, so it replied with `malformedRequest` or an HTTP error page.
  `reqwest` reports a 4xx as a completed transfer, so those bytes were
  cached and attached to the fallback certificate, and every handshake
  carried them. A client that checks the staple rejects a perfectly valid
  certificate on that basis, on every connection rather than
  intermittently, which is a worse outcome than sending no staple. A fetch
  now counts as successful only when what came back parses as a successful
  basic OCSP response per RFC 6960; anything else is refused and counted as
  `sbproxy_ocsp_fetch_total{result="unknown_status"}`, a label
  `docs/observability.md` already documented and nothing emitted.

- **The startup log now says which certificates OCSP stapling reaches.**
  Stapling covers the manual fallback certificate loaded from
  `tls_cert_file` and nothing else: the refresh task does not start without
  that file pair, and its update path writes the fallback slot rather than
  the SNI map every ACME-issued certificate lives in. Neither condition
  produced an error or a warning, so an operator who enabled HTTPS and read
  a clean log had no way to distinguish a stapled deployment from an
  unstapled one before a TLS scanner said so. Both paths through the boot
  hook now log `served`, `stapled`, and `covered`, and name the boundary.
  `docs/manual.md` section 7 documents it.

- **The in-process burn-rate rule now reads the hour it is named for, and
  reads only that hour.** The evaluator published three availability
  objectives, `-1H`, `-6H`, and `-24H`, and not one of them computed the
  window its name claimed. `-1H` had no window at all: it summed every
  sample in the ring, so it widened with process uptime until, against a
  full 1,440-minute ring, it returned the identical number as `-24H`. `-6H`
  was gated on 60 samples and read a 30-minute tail, so its name, its gate,
  and its window were three different durations. Only `-24H` was honest.

  In practice that meant a proxy that had been up for a day would page on an
  outage that ended hours ago while the hour actually in front of it was
  clean, and would stay quiet through a 20x burn in the last hour because
  the clean day behind it averaged the number down to under 1x.

  All three collapsed into one alert with one severity and one deduplication
  key, so they were never three paging decisions. There is one objective
  now: `SBPROXY-SUBSTRATE-AVAIL-INBOUND-1H`, the last 60 minutes at 14.4x,
  which is the window the rule's existing 60-sample floor fills exactly. The
  6x-over-6h and 3x-over-24h tiers are Prometheus rules in
  `deploy/alerts/alerting-rules.yml` and are not evaluated in process at
  all; both need history that outlives the process, and a 24-hour window
  read from a ring that empties on restart reports healthy for a full day
  every time the proxy comes back.

  What changes for an operator: a slow burn under 14.4x over the last hour
  no longer opens an in-process incident, and if you were paging off this
  rule rather than off Prometheus, that coverage has to come from
  `alerting-rules.yml`. A fast burn confined to the last hour now opens one
  that did not open before. Recovery takes a full window, because the
  failing minutes have to leave the hour rather than merely stop arriving.
  The alert's labels are now `scope`, `objective`, and `window` in place of
  `scope` and a joined `objectives` list, which changes the PagerDuty
  deduplication key: an incident open across the upgrade will not be closed
  by the new build's resolve event. The new key is at least stable, which
  the old one was not, since its value moved with the set of tiers firing.

- **A secret reference in `message_signatures.key` is now resolved instead
  of being used as the key itself.** Writing `key: vault://prod/signing-key`
  or `key: env:SIGNING_KEY` on an origin left the reference text standing in
  for the RFC 9421 signing key. The HMAC shared secret became the reference
  string itself, identical on every deployment that pasted the same line, so
  anyone who read the config could forge a signature the proxy accepted. The
  field now resolves through the same secret resolver every other
  secret-bearing field uses, and it resolves before the value is decoded, so
  a stored secret yields the same key bytes as that value written inline. A
  reference no declared backend can resolve fails the verifier build, and the
  origin then rejects every request with a 401. Inline keys behave exactly as
  before, and the `${VAR}` form was never affected, because config
  interpolation replaced it before this code ran.

- **A plain "not paid yet" read from a Lightning invoice no longer
  poisons the settlement intent.** The CLN/LND invoice-status check ran
  inside the same write gate as a real provider write, and since only
  `ProviderRejected` is on the authoritative-negative allowlist, an
  unpaid-but-not-rejected read resolved to `Ambiguous` and stamped the
  intent `NeedsReconciliation`, unreachable by the request path until a
  background worker swept it later. The status read now runs in the
  read-only query gate; only paid, expired, or unparseable outcomes
  touch the write gate. A client retrying against a still-unpaid
  invoice now gets a normal `RetryWait` and settles on the next request
  once it's actually paid, instead of waiting on the reconciliation
  worker.

- **An `ai_proxy` origin's `credentials:` block now does something even
  without `action.require_governed_key: true` set alongside it.**
  Before this fix, `credentials:` on its own enforced nothing:
  `/v1/chat/completions` accepted any Bearer token, or none, and
  dispatched to the real upstream regardless. Eight of the nine shipped
  examples, including the flagship `ai-virtual-keys` example, shipped
  this exact vulnerable shape. Config compile now fails loud when
  `credentials:` is present without `require_governed_key: true`,
  naming the origin and pointing at
  `docs/migration-credentials.md`, rather than silently turning the
  flag on and flipping an already-compiling, already-vulnerable config
  into one that starts rejecting traffic with no compile-time signal
  that anything changed. All eight examples and six e2e fixtures
  carrying the vulnerable shape were fixed in the same change.

- **The `a2a_agent_card_rewrite` transform now actually runs.** It was
  fully implemented, but `apply()` was a deliberate no-op with no call
  site, so a configured rewrite silently passed agent-card response
  bodies through unchanged. A client reading an unrewritten card
  learned the real upstream URL and could call it directly on later
  requests, going around the proxy entirely. It's now wired into
  `apply_transform_with_ctx`, covering both upstream-proxied and
  static-action agent cards, with a new `RequestContext::request_path`
  field feeding it: a configured `proxy_host` wins, and the inbound
  `Host` header is the fallback.

- **`require_mtls_bound: true` no longer rejects every request in
  production.** The RFC 8705 verifier itself was correct, but the
  production auth path hardcoded `None` for the client certificate's
  thumbprint; only test code ever passed a real one. Any origin
  actually enabling `require_mtls_bound` was rejecting all of its
  traffic. `request_filter` now derives the real `x5t#S256` thumbprint
  from the session's TLS digest and passes it through. A plaintext
  connection or a handshake with no client certificate still correctly
  yields `None`, so a bound token still fails closed there, and origins
  that don't use `require_mtls_bound` are unaffected.

- **`GET /admin/config` and `GET /admin/config/effective` no longer
  return inlined secrets in plaintext.** Both endpoints returned the
  raw or merged config verbatim, so a read-only admin credential could
  read back any secret written inline into the config. Both now pass
  through the same `redact_secrets` the log pipeline already uses. One
  side effect worth knowing about: a config with an inlined secret can
  no longer be round-tripped through a GET, edit, PUT cycle, since PUT
  now rejects the redacted placeholder with a 400. Moving those values
  to an `env:` or secrets-backend reference restores the round trip,
  which was already the documented way to hold a secret in config.

- **Four fixes from a security inventory of the auth path.** The JWKS
  unknown-`kid` refresh built a blocking `reqwest` client inside an
  async call chain, which could stall a Tokio worker for up to ten
  seconds against a slow identity provider; it's now async end to end,
  with the blocking variant kept only for the one caller that genuinely
  needs `spawn_blocking`. Seven hand-rolled constant-time comparators,
  not the two originally scoped, now delegate to
  `subtle::ConstantTimeEq`, closing a timing side-channel; two vault
  comparators are deliberately left as they were, since they need
  length-padding that `subtle`'s slice implementation short-circuits. A
  malformed CIDR in `parse_cidrs` now fails config compile instead of
  warning and dropping the entry, so a typo can no longer silently
  narrow a deny list. Two misleading code comments were also corrected.

- **A federated MCP server with no `rbac:` label of its own no longer
  defaults to allowing every tool on it.** A server declared under
  `federated_servers` with `rbac_policies` configured elsewhere in the
  config, but no `rbac:` label pointing at one of them, was treated as
  allow-all at all four dispatch sites, which quietly undoes
  default-deny for exactly the upstream an operator forgot to label.
  Config compile now rejects that combination outright, naming the
  offending server. An operator who genuinely wants allow-all for a
  server sets `rbac:` pointing at a policy with `default_allow: true`,
  an explicit choice instead of a silent default. Servers with no
  `rbac_policies` configured anywhere are unaffected. The dead
  `rest_to_mcp.rs` stub, a REST-execution path with zero call sites, is
  deleted in the same change.

- **`agent_budget`'s `tokens_per_hour` limit is now actually
  enforced.** The policy's request-rate half worked; the token half
  didn't, because `consume_tokens` had zero call sites.
  `tokens_per_hour` was checked for pre-flight headroom, so a 429 could
  still fire against a budget that had never once been decremented, but
  nothing ever charged usage after a response completed. Completion now
  charges the per-agent token sink at two points, the logging phase for
  buffered responses and end-of-stream aggregation for streamed ones,
  draining exactly once so neither seam double-counts. The streaming
  path previously never stamped `ctx.ai_tokens_*` at all, despite a
  comment claiming it did, so fixing only the logging phase would have
  silently missed every streamed AI response. Non-AI traffic and
  upstream errors consume nothing.

- **The Helm chart, the operator's own version, and the workspace
  version now agree.** `Chart.appVersion` claimed `2.0.0`, the operator
  crate was still versioned `0.1.0` and had never been bumped, and the
  workspace was at `1.10.0`; none of the three numbers matched anything
  real. The operator crate now inherits `version.workspace = true`, and
  the chart's deployment template defaults `image.tag` to
  `.Chart.AppVersion`, so the chart carries one true version instead of
  three that drift independently. Separately, the chart's operator
  image tag pointed at an image no CI workflow actually builds, so a
  stock `helm install` landed the operator pod in `ImagePullBackOff`;
  this is now called out explicitly in the docs and `values.yaml`, with
  a documented local-build workaround. Three docs and the sample
  manifest had also disagreed with each other on the proxy image tag;
  all now match what the release workflow actually publishes.

- **ACME HTTP-01 challenge validation now works behind a load
  balancer.** The per-hostname issuance lease was already shared across
  replicas, but the challenge token itself lived only in a
  process-local map on whichever replica won the lease. The CA's
  validation callback is load-balanced like any other request, so it
  frequently landed on a different replica with no record of the token
  and answered 404, meaning HTTP-01 validation couldn't complete at all
  in a multi-replica deployment. This failed silently: issuance errors
  are logged and swallowed, the proxy falls back to a self-signed
  certificate so the handshake still completes and the pod stays
  Ready, and nothing paged anyone for the roughly twelve-hour retry
  window in between. The token now lives in the same shared `KVStore`
  backing the cert store, keyed `acme:challenge:<token>`, so any
  replica can answer the CA. Its TTL is now derived from the CA's
  actual authorization-expiry field per RFC 8555 section 7.1.4, instead
  of a hardcoded, invented 600 seconds. In the same change,
  `storage_backend: sqlite` stopped silently downgrading to in-memory
  storage; an unrecognized backend value is now a hard error instead.

- **The served-quote nonce ledger for x402 payments is now durable.**
  Double-charge protection was already durable, backed by SQLite, but
  double-serve protection, stopping an already-settled quote token from
  being redeemed twice, used an in-memory set on the production path. A
  client re-presenting a settled quote token got served the paid
  content again, once per proxy restart. The ledger is now
  SQLite-backed over the settlement store's own connection, and a spend
  is a single atomic `BEGIN IMMEDIATE` plus
  `INSERT ... ON CONFLICT DO NOTHING`, so there's no read-then-write
  race across processes. Nonces prune themselves on the quote token's
  own expiry claim, and there's no longer a production code path that
  can construct the old in-memory version.

- **A stranded payment intent with no identifiable payer now stops
  withholding challenges after a bounded window.** When a payment
  intent lands in `NeedsReconciliation` and its payer can't be
  identified, the normal case for anonymous or crawler traffic, the
  route withheld fresh 402 challenges entirely and indefinitely; x402
  has no status-query endpoint, so a facilitator outage could zero a
  route's revenue for as long as the outage lasted. A separate fix
  already scoped withholding to a single payer when one could be
  identified; this covers the case where it can't. A new `Stranded`
  state now lifts the gate at the quote token's own challenge expiry
  plus a fixed fifteen-minute reconciliation grace window, past which
  point the stranded payer couldn't redeem the token anyway. The route
  resumes issuing challenges while the underlying provider attempt
  stays queued, so a late answer can still commit a real receipt.
  Operators get a documented query to pull stranded intent IDs for
  manual reconciliation, and a
  `sbproxy_payment_recovery_total{operation="strand_intent"}` metric to
  alert on.

- **A credential's `attrs.team` now reaches the request principal.**
  `project`, `user`, `tags`, `metadata`, and `cost_center` all flowed
  from a virtual key's attrs into the principal; `team` didn't, because
  `VirtualKeyConfig` had no field for it and
  `principal_for_resolved_virtual_key` hardcoded `team: None`. Any
  deployment attributing spend or metrics by team, across five metric
  families, the access log, spend rollups, the usage sink, CEL/Lua/JS
  contexts, and MCP RBAC, got every request bucketed under an empty
  team. `team` now follows the same origin, proxy, and tenant
  config-scope lowering path the other attribution fields already use.

- **The metering divergence sweep no longer alerts on every tenant with
  billable traffic.** `chain_contribution` only had a trait default
  returning `None`, so `note_chained` never ran, the chained-receipts
  map stayed permanently empty, and the sweep flagged a divergence for
  every tenant, every window, unconditionally. Once wired, a second
  problem surfaced: comparing raw per-window totals flagged any request
  whose count and its chain entry landed on opposite sides of a window
  boundary, and the false-positive rate rose with traffic. State is now
  a signed per-tenant balance carried across sweeps, along with its
  nearest-to-zero floor since the last sweep; a request straddling a
  window boundary nets to zero and stays quiet, while a genuinely lost
  receipt holds the balance up and reports once, at the cost of
  surfacing sixty to a hundred twenty seconds later than before. The
  `ledger` health component is also renamed `usage_ledger`, and
  `with_recency` is removed, since it would have marked a healthy but
  idle deployment, one with no paying traffic, Unhealthy and pulled it
  out of rotation.

- **A matched virtual key no longer erases the inbound principal's
  roles and claims.** `apply_resolved_virtual_key_context`
  wholesale-replaced `ctx.principal` on a match, so a JWT-authenticated
  request lost its `roles` and `claims` the moment a virtual key also
  matched. Under default-deny, that meant role-scoped MCP ACL rules and
  claim-based CEL policies could silently stop matching. The merge is
  now per field: attribution fields let the credential win, identity
  fields like `sub`, `source`, and `virtual_key` still replace
  outright, but `roles` and `claims` now carry forward from the inbound
  principal. Separately, five header-settable attribution tags reached
  Prometheus straight from caller headers with no cardinality limit; a
  documented constant, `MAX_DISTINCT_VALUES_PER_TAG`, existed but no
  call site read it, so an untrusted caller could mint unbounded label
  values across five metric families. Both are now routed through the
  existing cardinality limiter.

- **Every `config_only` key now has a real disposition instead of a
  boot warning pointing at a closed ticket.** The most visible fix
  among 32: `cors.enable: false` was silently ignored, since the
  runtime enabled CORS on the block's presence, never on the boolean's
  value, so an operator writing `false` to disable CORS actually left
  it enabled. Config compile now refuses that combination, naming the
  fix. Eleven other config-only keys are now refused outright instead
  of silently accepted: five legacy `proxy.secrets` keys superseded by
  `backends`, three dead `forward_rules[].origin` metadata fields, and
  `key_introspection` and `redis_source_of_truth` on the one value that
  never worked. Two keys, `proxy.secrets.map` and
  `proxy.http3.idle_timeout_secs`/`.max_streams`, turn out to have been
  live all along and are reclassified from config-only to stable.

- **`request_modifiers[].js_script` now runs.** It parsed, compiled,
  and was pinned `stable` in the key registry, so it never triggered a
  boot warning, but no code path ever executed it: only its Lua twin,
  `lua_request_modifier`, actually ran at the request phase, despite
  docs and the glossary describing both as supported symmetrically. A
  second, independently found instance of the same class of bug: a
  forward rule's modifier loop only read `headers`, so a `lua_script`
  or `js_script` attached to a forward rule was compiled and silently
  never run, for either engine. Both are now wired to execute; on the
  origin path, JS runs after Lua, and both now run on forward rules
  too.

- **ACME issuance now retries a `badNonce` rejection with the nonce the
  server actually offered.** On a `badNonce` response, the retry
  previously discarded the fresh nonce the server returned in
  `Replay-Nonce`, because the body was read before the headers, making
  the header unreachable, and instead re-fetched a nonce with a second
  `HEAD newNonce` call that could itself be rejected with no further
  retry. A failed second attempt then surfaced only as a bare "returned
  400," with the real cause lost. `post_jws` is now a bounded loop,
  three attempts, that reads `Replay-Nonce` off the 400 before
  consuming the body and signs the retry with it, falling back to
  `newNonce` only when the header is absent. Non-badNonce errors are
  unaffected. This makes certificate issuance resilient to a
  nonce-rejection race against a real CA, per RFC 8555 section 6.5,
  instead of failing outright.

- **A `sbproxy_ai_multipart_inspection_skipped_total` counter makes the
  multipart guardrail gap visible.** The AI gateway's dispatch gate
  branches on the inbound `Content-Type`, and every exit of the
  multipart branch returns early, so input guardrails, `pii:` request
  redaction, and `prompt_injection_v2` never run against a multipart
  request. A caller can still send `multipart/form-data` to
  `/v1/chat/completions` and route around every configured guardrail
  with no metric or log to show it happened, until now: a nonzero rate
  on a surface where multipart isn't legitimate, like
  `chat_completions`, is now a dashboard signal. Enforcement itself is
  unchanged here, only the visibility; the docs are also corrected,
  since they previously understated how narrow the bypass was and
  overstated what the `dlp` policy covers (it reads URIs and headers,
  not body content).

- **A multipart AI request's `prompt` field now goes through input
  guardrails.** A multipart request, an image edit or a transcription,
  short-circuited before the JSON parse, so the guardrail pipeline,
  including prompt-injection scanning, never ran on its `prompt` text
  field at all. That was a documented way to bypass scanning entirely:
  send the same text as a multipart part instead of JSON. The `prompt`
  part is now extracted and run through the same
  `evaluate_ai_input_guardrails` evaluator the JSON path uses, covering
  both built-in and external guardrails. Image and audio bytes still
  aren't scanned, since no classifier reads them, and PII redaction
  still deliberately skips multipart, since rewriting it would break
  the multipart framing, but a credential that requires redaction now
  gets a 403 instead of an unredacted forward.

## [1.10.0] - 2026-08-04

### Added

- **Extension bundles: install TypeScript, JavaScript, or WebAssembly
  behavior from a directory and attach it in `sb.yml`.** The plugin trait
  surface and its registry already existed, but only `AuthProvider` was
  reachable from configuration: `compile_policy`, `compile_transform`,
  and `compile_action` never fell back to the registry for an unknown
  `type:`, so `Transform::Plugin` had full timeout- and panic-guarded
  dispatch machinery that no config could reach. A bundle is a directory
  holding a `bundle.yaml` manifest and one entry artifact. TypeScript is
  stripped to ES2020 once while the candidate loads; JavaScript loads
  directly; dependencies must arrive as one prebuilt flat `.js` file,
  because nothing here installs packages or resolves modules at runtime.
  Four runtimes are available: `javascript`, `wasm` on sbproxy's own
  envelope ABI, and `proxy_wasm` against the real Proxy-Wasm 0.2.1 host
  ABI, which is the one Envoy, Kong, and APISIX SDKs already target.
  Hooks cover `policy`, `transform`, and `action` on the HTTP path, the
  AI seams (`ai_tool_call`, input and output guardrails, stream events,
  and close), and a rail-neutral payment lifecycle whose first complete
  adapter is x402. The manifest bounds wall time, memory, stack,
  buffered input, output, and WASM fuel, and `permissions` must stay
  empty: bundle code gets no filesystem or network capability. `sha256`
  pins the exact bytes of the entry artifact, and a mismatch refuses
  startup, validation, doctor, or reload before the candidate can become
  active. Reload swaps bundles as one pipeline generation, so a rejected
  candidate never leaves half its hooks attached. `GET
  /api/extensions` and `sbproxy doctor` both report what is installed,
  what is attached, and where each hook sits in its chain. Worked
  examples are in [examples/extension-bundles](examples/extension-bundles/),
  and the reference is section 12 of [docs/scripting.md](docs/scripting.md).

- **A configured usage reporter now receives live proxy traffic.**
  `proxy.payments.usage_reporters.stripe_meter` shipped with a reporter,
  a durable queue, and a worker that drains it, and with nothing that
  produced an event. An operator could configure the block, pass
  validation, pass startup, serve traffic, and bill nothing. The request
  path now enqueues each billable unit immediately after the meter
  settles the request receipt, billing from that settlement rather than
  re-deriving it, so a cache hit or a policy block is charged or not
  charged according to the same outcome table the signed receipt used.
  The HTTP call to the provider stays in the background worker: a served
  request writes one durable row and stops, so no request ever waits on
  Stripe. Two counters describe it, `sbproxy_usage_bridge_enqueued_total`
  and `sbproxy_usage_bridge_gap_total`, both labeled by tenant. See
  [`docs/payment-settlement.md`](docs/payment-settlement.md).

  **`usage_reporters.stripe_meter` gains two required fields, `source`
  and `unit` [BREAKING].** A config with a `stripe_meter` block and no
  `source` no longer parses. There is deliberately no default: one
  request can produce a request receipt, an AI usage record, and a
  record per MCP tool call, and two of those can describe the same sale,
  so billing both against one meter charges the customer twice. An
  unstated answer there *is* the double charge, and a default would be
  this proxy picking a side of a commercial argument on the operator's
  behalf. Set `source` to `http`, `ai`, or `mcp`, and `unit` to the unit
  that meter bills. An operator who wants both dimensions configures two
  meter events. The block shipped one day before this change, so the
  affected population should be close to nobody.

- **mistral.rs is a subprocess engine kind.** `engine: mistralrs` drives the
  upstream v0.9 `mistralrs` CLI as a supervised subprocess over its
  OpenAI-compatible surface, acquired exactly like llama.cpp: PATH-first,
  then the pinned upstream prebuilt release (Metal on Apple Silicon; CPU
  and per-compute-capability CUDA builds on Linux x86-64), sha256-verified
  against checked-in digests. The lane serves safetensors weights with
  native tool calls, appears in `sbproxy doctor` and `models list`, and is
  an explicit opt-in: `auto` never resolves to it and placement ranks it
  behind the certified lanes. See
  [`docs/model-host.md`](docs/model-host.md).
- **A managed worker refuses to boot into a configuration it cannot
  serve.** `sbproxy doctor --strict <config>` runs six named startup checks
  (NVIDIA driver, visible accelerators, per-entry engine compatibility,
  `/dev/shm` against the size an engine asked for, the weight-cache mount
  against `cache_budget_gib`, and `proxy.cluster` identity material) and
  exits 3 when any of them blocks. Each check compares the config's own
  demands against the host, reads both the provider-level `serve:` form and
  the canonical `proxy.model_host` form, and reports `skip` rather than a
  hollow pass when it does not apply. The worker image and the generic VM
  bootstrap now boot behind it, so a box handed no GPU devices, a too-small
  `/dev/shm`, an undersized cache mount, or unreadable model-plane identity
  fails at boot with a named blocker instead of joining the cluster,
  advertising itself as eligible, and failing every dispatch. See
  [`docs/manual.md`](docs/manual.md).
- **The self-host matrix has a runner and an evidence ledger.**
  `scripts/certify-selfhost.sh` gives every lane in the certification table
  one reproducible command, a recorded expected result, captured host and
  version metadata, and a retained log. A lane passes only when its command
  ran on this host and succeeded; a host that cannot provide what a lane
  needs is recorded `unsupported` with the reason, never as a pass. Apple
  Silicon and NVIDIA single-GPU CUDA now have live evidence dated
  2026-07-30, including a real vLLM container completion on an L4. See
  [`docs/model-host-certification.md`](docs/model-host-certification.md).
- **The macOS launchd agent has an environment file.**
  `sbproxy service install` creates
  `~/Library/Application Support/sbproxy/service/env` (mode 0600) once and
  never overwrites it, so an `HF_TOKEN` a gated model needs survives
  reinstalling to change the model or the port. A launchd agent inherits
  almost nothing from the shell that installed it, so a token exported in a
  terminal was previously invisible to the agent. `service status` now also
  reports the config, log, and environment-file paths.
- **Rate limits converge across a gossip mesh with no Redis.** A clustered
  deployment previously enforced `requests_per_minute` once per node, so 600 rpm
  on three nodes admitted roughly 1800. Each node now admits against its own
  count plus a view of its peers refreshed every 3 seconds, which bounds the
  overshoot at `(nodes - 1) x rate_per_second x 3`: about 660 for that same
  configuration. An L2 Redis store still enforces exactly and takes precedence
  when configured. `requests_per_second` is unchanged and still per-node, since a
  one second window closes before a peer count can arrive, and it now warns at
  boot on a mesh cluster instead of silently enforcing N times the limit.
  `sbproxy_rate_limit_cluster_peer_denials_total` makes the approximation
  observable. See [`docs/configuration.md`](docs/configuration.md).

- **External AI guardrails now use hardened vendor contracts.** Generic
  webhooks and Presidio remain compatible, while Lakera, Aporia, Azure AI
  Content Safety, Amazon Bedrock Guardrails, CrowdStrike AIDR, Mistral
  moderation, Pangea AI Guard, and Patronus have typed adapters. Credentials
  resolve through the existing secret providers; outbound URLs are validated
  and DNS-pinned; redirects are disabled; and responses have a timeout and a
  64 KiB limit. Fail policy now covers malformed responses, replayed output,
  streaming, and uninspectable multipart content before bytes can leave the
  gateway. See [`docs/guardrails.md`](docs/guardrails.md).
- **AI routing learns live locality and shares caller quota across the
  fleet.** Prefix affinity records bounded, expiring provider holders and
  falls back by recent token load; outcome-aware routing blends learned
  feedback during warm-up and keeps that feedback across config reloads;
  and weighted request pools support local, approximate mesh, and strict
  Redis accounting keyed by immutable credential ids. Each external
  provider attempt reserves independently and settles only at its outbound
  send boundary, with explicit closed or `allow_unreserved` backend failure
  behavior.

### Changed

- **`sbproxy-plugin` is 0.3.0, and `ActionOutcome` is the reason.** The
  enum gained a data-bearing `Response { status, headers, body }` variant
  so a handler can hand the host a complete response as data rather than
  writing one through host state, which is what lets ordinary response
  middleware and the bundle action contract see it. That drops the enum's
  `Copy` impl and makes any exhaustive match on the 0.2 variants
  non-exhaustive. The crate stayed at 0.2.0 through that change, so an
  out-of-tree plugin hit a breaking change with no version to notice it
  by; 0.x breaking changes bump the minor, and this one now does. Both
  0.2 variants still exist and still mean what they meant, so migrating
  is adding a `Response { .. }` arm and replacing any implicit copy with
  a clone or a move. The migration note is on `ActionOutcome`'s rustdoc,
  and a test now pins which traits the enum carries so a later change
  cannot move the contract silently again.

### Removed

- **The in-process embedded engine (`engine: embedded`).**
  Never on by default (it required a build with `--features embedded`) and
  never certified: no dedicated tests, no CI lane, and no capability-ledger
  entry. llama.cpp already covers the CPU/Metal, zero-external-binary case
  it existed for, and the new `mistralrs` subprocess engine (see above)
  covers safetensors mistral.rs serving without the large in-process
  dependency tree. A config that still sets `engine: embedded` now fails
  to parse.

### Fixed

- **A bundle hook can no longer end a request with a status that is not
  final, or attach a body to one that forbids it.** Extension-produced
  responses accepted anything from 100 through 599. A 1xx is
  informational, so it asks the host to keep going, but both surfaces
  that can return one (a dynamic action's result and Proxy-Wasm's
  `proxy_send_local_response`) have already stopped dispatch by the time
  they see it, which left the caller waiting on a final status that could
  never arrive. A 204 or 304 could also carry a guest body, which
  desynchronizes an HTTP/1 connection and is a protocol error on HTTP/2.
  Both surfaces now share one rule applied before any byte reaches the
  wire, and a rejected body is refused rather than silently dropped, so a
  bundle that believes it is returning content cannot look like it works.
  Every rejection message is a fixed string plus the status, so no
  guest-supplied bytes reach host logs.

- **A bundle's declared `failure_posture` is now the posture the pipeline
  applies.** The manifest accepted the key for policy, transform, and
  action hooks, and compilation dropped it. A buffered dynamic policy
  that failed was denied regardless of what its manifest said, and a
  transform never received the value at all, because `Transform::Plugin`
  carried no bundle metadata the way the action and policy wrappers
  already did. Resolution now follows one precedence: an explicit
  `failure_posture` or `fail_on_error` on the attachment, then the
  manifest, then the attachment default. Silence on the attachment is
  distinguished from an explicit `open`, which is the whole fix, because
  `TransformConfig::failure_posture()` returns `Open` for both. A genuine
  host invariant violation is still a 500 whatever the posture says.
  Action hooks are unchanged and still fail closed: the manifest already
  refuses any other posture for them, since they are terminal.

- **Extension inventory reports the chain order the proxy runs, not an
  alphabetical one.** Positions were derived by sorting hook identities
  and counting, so two Proxy-Wasm filters listed `zeta` then `alpha` came
  back as `alpha` at position 0 and `zeta` at 1, the reverse of their
  execution order, and ordered AI and payment chains could all report as
  position 0. Positions now come from the same enumeration the compiler
  walks and from each chain's real dispatch order. A hook attached at
  more than one site deterministically reports the earliest one in
  document order. Attachment and position are also separate facts now: a
  hook the chain cannot name stays attached and reports no position,
  rather than being given one that is wrong.

- **The AI gateway's circuit breaker and outlier detection now run.**
  `resilience.circuit_breaker` and `resilience.outlier_detection` parsed,
  validated, and were documented and exampled, and nothing ever attached
  them to a router. The constructor that would have done it had no
  callers anywhere in the tree, so the breaker list was empty and the detector
  absent on every router the proxy has ever built, both arms of the
  eligibility check passed unconditionally, and the ejection sweep the
  request path ran on every provider failure evaluated state nothing
  populated.
  A deployment that configured circuit breaking against a flaky provider
  had none. Both blocks are now attached where the router is built, each
  by its own config block, so configuring one does not arm the other on
  thresholds nobody chose.

  **If you have either block configured, providers will now start
  leaving the routing pool.** On the shipped defaults a provider leaves
  after five consecutive request failures, or after a 50% failure rate
  over at least five requests in a 60-second window, and only a 5xx or a
  transport error counts; a 4xx, including a 429, does not. Each signal
  clears on its own terms without help from the others: a breaker admits
  a probe after `open_duration_secs` and closes on `success_threshold`
  successes, an ejection lapses after `ejection_duration_secs`, and a
  probe verdict flips back after `healthy_threshold` consecutive passes.
  A provider that failed on two signals returns when both have cleared.
  Breaker transitions and outlier ejections are logged.

  With every provider ejected, dispatch routes to the full permitted set
  rather than refusing the request, which is what `resilience` has always
  documented and what the load balancer's identical filter does. Three
  advisory signals should not combine into an outage none of them can
  cause alone. Credential policy, model eligibility, and `enabled` stay
  hard filters and are never revived. An `outlier_detection.threshold` of
  zero or a `min_requests` of zero, which together would eject a provider
  that had never failed, are refused with a warning and the default is
  used instead.
- **`routing.strategy: token_rate` is refused at config load instead of
  silently behaving as a different strategy.** It ranks providers by
  remaining tokens-per-minute headroom against a declared per-provider
  limit, and no configuration field declares one, so every limit was zero
  and the score reduced to observed usage alone: `least_token_usage`
  under another name, with no error and no warning. **If you have
  `token_rate` set, the proxy will now refuse the config.** Change it to
  `least_token_usage`, which is what you have been running, or to
  `headroom` or `reset_aware`, which score the rate-limit headers
  providers actually return. See
  [`docs/ai-gateway.md`](docs/ai-gateway.md#token_rate-refused).
- **`sbproxy run` and `sbproxy service install` no longer publish the
  local model gateway to the network.** Both generate a config the code
  calls secure defaults, and the admin half was: loopback bind, random
  port, a 32-byte `OsRng` password written at mode 0600. The public
  listener was hardcoded to `0.0.0.0` in the server, with no schema
  field able to express anything else and no authentication in front of
  it, while the ready banner printed `http://127.0.0.1:<port>` and
  handed you an `OPENAI_BASE_URL` built from it. On a laptop on a shared
  network that was an open inference endpoint, described as local. The
  generated `origins:` map restricting to `127.0.0.1` and `localhost`
  was not a defense, because that matches on the `Host` header, which
  the caller sets.

  Both commands now generate `bind_address: 127.0.0.1`, so the banner's
  URL is true. **If you relied on `sbproxy run` being reachable from
  another machine, it no longer is.** Write a config and set
  `proxy.bind_address` to `0.0.0.0` or a specific interface, and put
  authentication in front of it.
- **`proxy.bind_address` makes the public listener's interface
  configurable at all.** It applies to `http_bind_port` and
  `https_bind_port` together, because two fields would let an operator
  lock down HTTP, leave HTTPS open, and believe the box was closed. It
  defaults to `0.0.0.0`, so every existing config keeps the reach it
  has. The value must be an IP literal: hostnames are refused because a
  name can resolve to more than one address, and a malformed address is
  refused at config load rather than falling back to a default, since
  falling back is precisely the failure the field exists to prevent. See
  [`docs/configuration.md`](docs/configuration.md#choosing-a-bind-address).
- **The `a2a` policy no longer decides on inputs the caller controls.**
  Chain depth, chain membership, and caller and callee identity were read
  from `X-A2A-*` request headers with no verification and no ingress
  stripping, so a caller could send `X-A2A-Chain-Depth: 1` with no chain
  and clear `max_chain_depth` and cycle detection together, or rename
  itself off `caller_denylist`. The envelope now comes from the RFC 8693
  `act` claim chain on the verified principal, which a caller cannot
  flatten, and the `X-A2A-*` headers are honored only from a peer in
  `proxy.trusted_proxies` and stripped from everyone else. Operators
  relying on the header transport must now list the peer that stamps it;
  `examples/a2a-protocol/` shows the shape. The policy's `route_glob` is
  also consulted for the first time: it was parsed, validated, and never
  read, so the one detection signal a caller could not opt out of did
  nothing. See [A2A gateway](docs/a2a-gateway.md).

- **`sbproxy_a2a_hops_total` distinguishes verified allows from
  unverified ones.** The `decision` label emitted a bare `allow` whether
  the policy had checked a verified delegation chain or waved through an
  envelope it could not trust, so a fully bypassed policy produced the
  same green dashboard as a working one. Allows are now
  `allow:verified` or `allow:unverified`, and a request the policy never
  engaged on records `skip:undetected` rather than nothing at all.
  Denials are unchanged. This relabels a `beta`-compatibility metric; no
  dashboard or alert in this repository reads it.

- **Ollama streaming keeps its stream and its usage accounting.** The
  buffered-relay fallback for streaming requests keyed on `text/event-stream`
  alone, so Ollama's NDJSON (`application/x-ndjson`) success responses were
  buffered whole and their token counts never reached budget recording: a
  workspace past its cap kept getting 200s. NDJSON responses now stay on the
  streaming relay, where the Ollama usage parser reads them line by line.
- **A bulk credential purge now reaches every node.** `invalidate_all` cleared
  only the local shard, so peers kept serving stale resolved credentials until
  TTL. It now fans out to every peer. The same change fixes the opposite problem
  on the node running it: because a clustered node's key-plane cache is the
  node-wide distributed cache, the old blanket purge also discarded unrelated
  entries such as compression sessions. The purge is now scoped to the key-plane
  prefixes.
- **A clustered node now says what its node-local keystore does and does not
  guarantee.** The `embedded` redb store is per-node, so a key minted on one node
  is not durably resolvable by its peers and a revocation may not deny on all of
  them. A node declaring `proxy.cluster.seeds` with `key_management.enabled: true`
  and `store.backend: embedded` now warns at boot when a `mesh` or `redis`
  `cache.tier` propagates records (resolution works while cached, but does not
  survive expiry or a restart), and fails to start when `cache.tier: none` leaves
  nothing to propagate through. A single node with no seeds keeps the embedded
  default. See [`docs/key-management.md`](docs/key-management.md).
- **The legacy `serve:` fit path books the KV cost the engine will run.** The
  1.9.0 fix that made the fit planner and the engine drivers share one KV
  table missed the single-node runtime behind a legacy `serve:` block, which
  still sized its KV term from the requested `kv_quant`: `int4` on vLLM
  booked 0.5 bytes per element while the engine allocated fp8 at 1.0,
  halving the planned cache. That path now sizes from the shared table and
  logs the same substitution warning, the single-replica managed activation
  path warns too instead of substituting silently, and the llama.cpp
  driver's own dtype mapping now derives from the table instead of
  restating it. See [`docs/gpu-fit-planning.md`](docs/gpu-fit-planning.md).

## [1.9.0] - 2026-07-28

### Added

- **AI routing and state now carry production authority end to end.** Peak
  EWMA routing tracks complete provider attempts with configurable decay;
  Realtime WebSocket upgrades replace caller credentials with one trusted
  provider credential and apply governed-key budget admission; stateful
  context compression defaults to a private, restart-durable Local redb store
  while retaining explicit Redis and mesh choices; and verified crawler CAPs
  enforce bounded per-subject request rates before policy evaluation while
  exempting approved traffic from ledger pricing.
- **Classifier safety guardrails now ship calibrated default centroids.**
  `toxicity`, `jailbreak`, and `content_safety` classifier mode no longer
  requires operator examples. Optional examples extend the versioned
  defaults. The artifact pins the exact `all-MiniLM-L6-v2` revision, model,
  tokenizer, and artifact digests, and incompatible bytes fail closed.
  Repo-authored held-out fixtures, measured class precision and recall, and
  deterministic regeneration live in
  [`docs/ai-default-centroids-evaluation.md`](docs/ai-default-centroids-evaluation.md).
- **Outbound credentials can use DPoP-bound tokens.** `client_credentials`,
  token exchange, and vault-backed credentials can load an existing private
  key from the secret-provider surface and mint fresh RFC 9449 proofs for
  token and resource requests. Method and URI binding, access-token hashes,
  nonce challenges, retry bounds, and proof-header redaction are enforced.
  See [`docs/outbound-dpop.md`](docs/outbound-dpop.md).
- **The admin API exposes model-host lifecycle jobs.** `GET
  /admin/model-host/jobs` and `GET /admin/model-host/jobs/{id}` list and read
  durable load/evict operations. `GET /admin/model-host/jobs/{id}/stream`
  tails one job's progress as `text/event-stream`, with `Last-Event-ID`
  reconnect replay. `POST /admin/model-host/load` and `/evict` now answer
  `202` with a `job_id` and `poll_url` when a durable job store is
  configured, instead of blocking the request until the engine finishes;
  with no job store configured they keep the previous synchronous `200`
  contract. See [`docs/admin-api-guide.md`](docs/admin-api-guide.md).
- **The admin console playground dispatches through the real request
  pipeline.** `POST /admin/api/playground/dispatch` impersonates a chosen
  virtual key with a short-lived, single-use ticket and makes a genuine
  loopback call into the server's own data-plane listener, so key policy,
  governance, routing, and guardrails run exactly as they would for that
  key's real traffic. Plain-HTTP AI origins only; an origin with
  `force_ssl` set answers `501`. The existing `POST
  /admin/api/playground/chat` (calls the AI client directly, bypassing the
  data plane) is unchanged.
- **A data-plane route reports a caller's own usage.** `GET /v1/key/usage`
  returns the resolved caller's governance snapshot (requests, tokens,
  spend, remaining budget), scoped strictly to its own key id. There is no
  key-id parameter, so a key can never read another key's usage.
- **Fleet VRAM aggregation and new admin console views.** `GET
  /admin/cluster/vram` sums VRAM totals across every currently eligible
  cluster node. The admin console adds a Get Started onboarding view, a
  Jobs view backed by the new job API, four axes per deployment on the
  Model host view instead of two (desired / runtime / assignment /
  live-replica state), and a per-replica disclosure in the cluster node
  roster.
- **`sbproxy service install|uninstall|status` runs a model as a background
  launchd agent on macOS.** `install` generates the same secure loopback
  config `sbproxy run` would, persists it under `~/Library/Application
  Support/sbproxy/service/`, and registers a per-user `launchd` agent that
  restarts on failure; `uninstall` unloads and removes it; `status` reports
  whether it is registered and running. See
  [`docs/manual.md`](docs/manual.md).
- **Recommended-model catalog entries are pinned.** Six of the seven
  built-in `models.yaml` recommended entries now carry exact `variants:`
  blocks (sha256, size, revision) instead of resolving loosely at pull
  time.
- **Worker and gateway container images are split, with a generic cloud
  bootstrap script.** `Dockerfile.worker` (CUDA + vLLM) and
  `Dockerfile.gateway` (lightweight, no GPU stack) replace one combined
  image. `deploy/terraform/l4-demo/bootstrap-generic.sh` is a
  cloud-agnostic install/validate/start script driven entirely by
  environment variables, used by both the GCP Terraform path and
  `cloud-init.yaml`. See [`docs/build.md`](docs/build.md).
- **vLLM prefix caching is a config flag.** `enable_prefix_caching` on a
  managed vLLM deployment emits `--enable-prefix-caching`. See
  [`docs/model-host.md`](docs/model-host.md).
- **An opt-in Xet-aware weight transport is available behind a feature
  flag.** The new `hf-xet-transport` Cargo feature (off by default) adds a
  second artifact transport built on `hf-hub` 1.0's managed, Xet-aware
  client. It is not wired into the default build or either production
  transport call site yet; this ships the transport for a follow-up to
  adopt.
- **Six new AI providers.** AI21 Labs (Jamba), Clarifai, Inception Labs
  (Mercury), Azure AI Foundry Models, Snowflake Cortex, and Sarvam AI,
  bringing the native provider catalog to 72. See
  [`docs/providers.md`](docs/providers.md).
- **OTLP metrics export actually exports.** `telemetry.export_metrics:
  true` previously did nothing; boot now wires the metrics pipeline, and
  fails loud if `export_metrics: true` is set without `enabled: true`.
- **Six new self-host observability metrics, with alerts and dashboard
  panels.** The previously dead `sbproxy_model_host_load_queue_depth` gauge
  is now wired to a real signal, and five new counters cover artifact
  acquisition failures (`sbproxy_model_host_artifact_errors_total`),
  model-directory exclusions
  (`sbproxy_ai_model_directory_exclusions_total`), replica-selection
  exclusions (`sbproxy_ai_replica_selection_excluded_total`), placement
  rejections (`sbproxy_model_host_placement_rejections_total`), and the
  key-policy budget fail-closed path
  (`sbproxy_key_policy_stored_rejections_total`). See
  [`docs/metrics-stability.md`](docs/metrics-stability.md).
- **CI gates on the admin UI's typecheck and tests.** Previously nothing in
  CI ran `npm run typecheck` or `npm run test` for the admin console.

### Removed

- **Superseded `sbproxy-ai` library modules.** Removed unreachable local
  emulation, prompt-cache, response-deduplication, context-relay,
  structured-output, and streaming-tracker code. Provider passthrough
  surfaces, semantic caching, idempotency, live streaming metrics, and the
  shipped context-compression pipeline are unchanged.
- **Unreachable policy prototypes no longer look supported.** The
  `peer_pricing_preflight` policy and the inactive NL-to-Cedar compiler,
  linter, and compiled-policy store had no production request-path caller
  and have been removed. Delete `peer_pricing_preflight` entries from
  configuration; there is no outbound peer-pricing replacement today.
  Existing `semantic_constraint` policies remain supported, but must drop
  the inert `policy_id` field and continue to configure their judge
  directly. AI crawl payment negotiation keeps its live
  `Accept-Payment` parser.
- **Dead model-host residency prototypes.** Removed the unwired vLLM sleep/wake
  client and policy-only KV tiering abstraction. Neither was a supported
  capability, and vLLM development endpoints are no longer enabled by default.
  The engine-native `swap_space_gib` and `cpu_offload_gib` settings remain.
  Safe future sleep/wake wiring needs bounded asynchronous transition polling,
  retained process ownership and accounting after cleanup failures, a bounded
  host-RAM policy, isolated container development endpoints, and end-to-end
  fake-engine coverage.

### Changed

- **A CEL syntax error is now a config error, everywhere CEL comes from
  config.** `assertion` policies, `cel` transform bodies and header
  rules, rate-limit `key:` expressions, WAF `persistent_block.key`, and
  `engine: cel` custom log fields all compile while the config compiles,
  the same way `expression` policies already did. A malformed expression
  refuses the config at boot, and a reload carrying one is rejected with
  the previously active config still serving. Before, each of these
  parsed again on every request or response and swallowed the parse
  error at that point, so a typo booted fine and then silently disabled
  the thing the operator wrote: an assertion that never ran, a header
  rule that never fired, a log field that never appeared. **A config
  with a CEL typo that used to start will now refuse to start.** That is
  the point, but it is a startup-behavior change, so run `sbproxy
  validate` against your config before upgrading; it reports the same
  errors with the owning origin, policy, and field named.

  Turning the check on immediately found two expressions that had never
  worked, both of them ours. `docs/access-log.md` and
  `examples/custom-log-fields/sb.yml` both used
  `has(request.headers["x-tier"])` to test for a header. CEL's `has()`
  macro takes a field selection, not an index, so that expression has
  never parsed, and the log field it guarded has never once appeared in
  an access line. The working form for a hyphenated header name is
  `"x-tier" in request.headers`, and both pages now use it. Separately,
  `examples/rate-limiting/sb.yml` wrote `key: ip` as though `key` took a
  keyword; it is a CEL expression, so `ip` was an undefined identifier
  that failed every request and dropped the policy into the default
  bucket, which happens to be keyed by client IP. It looked like it
  worked because the fallback did. It is now
  `key: 'connection.remote_ip'`, which is the same partitioning, said in
  the language the field actually speaks.
- **A rate-limit `key:` expression that fails to evaluate no longer
  drops the request into the default bucket.** It buckets under a
  `__cel_key_error__:` prefix on the default client key instead. The old
  fallback was a rate-limit bypass: the default key is the client IP, or
  the hostname when no client IP is known, so a caller that could force
  the expression to fail left its own identity bucket, and its
  accumulated count, behind. Rate limiting stays on either way, and
  error traffic no longer shares a bucket with correctly keyed traffic.
  An expression that evaluates cleanly to null or an empty string still
  means "no key for this request" and still falls back to the default
  client key, because that is the operator's own logic talking.
- **Outbound HTTP no longer follows a redirect without re-authorizing it,
  and the AI provider client no longer follows one at all.** The AI
  client, the webhook, Langfuse, and Datadog usage sinks, the MCP token
  exchange, and engine artifact downloads all followed redirects inside
  `reqwest` with no second look, so a host allowlist only ever covered
  hop one. Each of them now runs an explicit hop loop: every hop is
  authorized from scratch, an off-allowlist target is reported
  separately from a hop-one refusal, and the chain is capped at ten.
  Credentials are stripped when a hop leaves its origin, keyed on
  whether the header is marked sensitive, which matters because
  `reqwest` strips `Authorization` and nothing else: `x-api-key`,
  `api-key`, and `DD-API-KEY` were riding along. **A provider base URL
  that depended on a 301 to add a trailing slash will now fail instead
  of silently working.** Point the config at the URL the provider
  actually serves.
- **Egress authorization resolves DNS for real.** These same consumers
  ran their egress gate against a fixed synthetic resolver that always
  answered `93.184.216.34`. Because that address is public and always
  resolves, the private-address rule and the resolution-failure rule
  were unreachable: an allowlisted hostname pointing at
  `169.254.169.254` passed the gate. Resolution now goes through a
  cached system resolver with a 30 second TTL, shared between the
  authorize step and the verify step so a mismatch means the answer
  genuinely changed. Refusals are counted by
  `sbproxy_egress_refused_total{purpose, reason, tenant, origin}`.
  Dial-time pinning on the shared long-lived clients is deliberately
  still open; `docs/threat-model.md` records that exemption, its
  residual risk, and the two ways to close it.
- **Admin operator passwords are now hashed at rest [BREAKING].**
  `proxy.admin.operators[].password` is replaced by `password_hash`, an
  HMAC-SHA256 hash (hex-encoded) using the same pepper the inbound key
  plane hashes virtual keys with. A plaintext `password` field under
  `operators:` no longer parses. Compute the hash with the new `sbproxy
  admin hash-password` CLI helper (`--password` or `--password-stdin`),
  which resolves `key_management.crypto.pepper` from config when set and
  falls back to a fixed default otherwise, so hashing works with no
  `key_management:` block configured. That default is a fixed public
  constant, the same in every install, so a leaked `password_hash` is
  offline-crackable unless `key_management.crypto.pepper` is pinned; pin
  it in production. The admin console gains a read-only Operators page
  (`GET /api/operators`) listing configured operator usernames and roles;
  operators stay config-only, with no admin API to add, remove, or
  re-role one.
- **Unsupported `telemetry.propagation` values now fail boot.** Previously
  any value other than `w3c` parsed successfully and was silently ignored,
  since the installed propagator was always W3C regardless of what
  `proxy.observability.telemetry.propagation` said. Boot now rejects it,
  naming the unsupported value and the one supported value.
- **Speculative decoding config is validated instead of silently dropped.**
  A `speculative` block on a deployment pinned to a non-vLLM engine now
  fails validation; previously it parsed and did nothing, since only vLLM
  emits the corresponding engine flags. n-gram speculation on vLLM is
  newly accepted. Draft-model speculation stays rejected, pending a
  VRAM-headroom check at a real prepare-time call site.
- **The HTTP OTLP transport's default endpoint is corrected.** With
  `transport: http` and no explicit `endpoint`, sbproxy now defaults to
  `http://localhost:4318/v1/traces` instead of the gRPC-oriented default
  with no path suffix appended.

### Fixed

- **`kv_quant: int4` no longer under-sizes the KV cache on vLLM and SGLang.**
  The fit planner sized the requested mode (int4 at 0.5 bytes per element)
  while both CUDA engine drivers substituted fp8 at 1.0, because neither
  exposes an integer KV kernel. The plan booked half the cache the engine
  would allocate, and the plan is what derives `--gpu-memory-utilization`,
  so a tight long-context config could fail at first-token graph capture.
  The dtype passed to the engine and the bytes the planner books now come
  from one table, so they cannot drift apart, and a substitution is logged
  rather than silent. llama.cpp is unaffected: its `q8_0` and `q4_0` caches
  are real. The legacy SGLang launch template also dropped the KV flag
  entirely and now emits it. See
  [`docs/gpu-fit-planning.md`](docs/gpu-fit-planning.md).
- **The worker image pins vLLM.** `Dockerfile.worker` installed vLLM with a
  bare `pip3 install vllm`, so every rebuild resolved to whatever version was
  newest and drifted the image off `DEFAULT_VLLM_VERSION`, which the fit
  planner, the argv builder, and the recorded NVIDIA certification all target.
  It is now pinned through a `VLLM_VERSION` build arg. See
  [`docs/build.md`](docs/build.md).
- **The launchd agent gives a shutdown drain room to finish.** launchd's
  default `ExitTimeOut` is 20 seconds, shorter than the proxy's 30-second
  default shutdown grace, so an agent still draining in-flight requests was
  SIGKILLed part-way through. The plist now sets it above the grace period.

- **OTLP spans are flushed on graceful shutdown.** A
  `shutdown_otlp_pipeline` call existed but nothing in the binary invoked
  it; spans still in flight at shutdown could be dropped.
- **Exported spans join the caller's trace.** An inbound `traceparent`
  header is now honored when seeding an exported span's parent context.
  Previously every exported span got a fresh random root trace ID
  regardless of the caller's own trace.
- **A latent boot panic in the gRPC OTLP exporter is fixed.** Building the
  gRPC trace or metrics exporter synchronously spawned a background task
  with no ambient Tokio runtime present at that point in boot, which
  panicked with `telemetry.enabled: true` and the (default) gRPC
  transport. Masked previously because the only test coverage of this path
  ran inside `#[tokio::test]`, which supplies a runtime.
- **Killed engines auto-recover on the next request.** A managed
  deployment whose engine process died after reaching `ready` (for
  example, `kill -9`, not a crash loop) previously stayed failed until an
  operator called `POST /admin/model-host/reset`. It now retries the same
  relaunch a fresh deployment uses; a deployment that is genuinely
  crash-looping still fails closed.
- **Stale cluster nodes no longer inflate fleet VRAM totals.** The cluster
  VRAM aggregator counted a node's last-known VRAM forever, even after it
  dropped out of eligibility. It now excludes any node that is not
  currently model-eligible.

## [1.8.0] - 2026-07-27

Trust tier becomes live policy input, config authority grows a command
line, and the admin console gains the pages it was missing. This release
also moves the vendored Pingora fork onto upstream 0.8.1, which carries
security fixes; see Security below.

### Security

- **Pingora updated to upstream 0.8.1.** The vendored fork was based on
  0.8.0 and has been rebased onto 0.8.1, picking up an HTTP/2 server
  limit bound that mitigates a memory-exhaustion vector, plus the fixes
  for `RUSTSEC-2026-0098` and `RUSTSEC-2026-0099`. Every deployment
  terminating HTTP/2 should take this release. SBproxy's three local
  patches (dynamic rustls cert resolver, the
  `upstream_response_decision` retry hook, and the refusal to retry once
  response bytes have reached the client) are unchanged.

### Added

- **The admin console reports context compression.** A Compression page
  lists the sessions whose history has been externalized to a summary,
  with tokens covered, summary size, and the resulting ratio. Summary
  text is never listed, only its size and provenance.
- **The admin console reports who can sign in.** A Users page lists each
  account and its role over a new read-only `GET /api/admin/users`.
  Accounts remain config (`admin.username`, `admin.operators`), so the
  route reports and does not mutate, and passwords are never included in
  the response.
- **Spend links through to the requests behind it.** Origin rows in the
  spend breakdown open the request log filtered to that origin.
- **Trust tier is now live policy input.** The request path combines
  authentication and agent-detection evidence into `suspicious`, `strong`,
  `named`, or `anonymous`; CEL expression and assertion policies can read
  `request.trust_tier`, and `sbproxy_trust_tier_requests_total` reports the
  closed-set distribution. Verified Web Bot Auth resolves to `strong`.
- **Operate a config authority from the command line.** Running one used
  to mean hand-rolled `curl`. `sbproxy config authority init` generates
  the Ed25519 signing key owner-only, writes the verifying-key file
  subscribers install, and prints what to copy where; it refuses to
  overwrite an existing key, and `--force` rotates by adding the new
  verifying key beside the old one so subscribers keep verifying while
  they are updated. `publish` runs the same three validation steps the
  authority runs, through the same code, so a payload that would be
  refused is refused locally before a revision number is spent on it.
  `status` shows the current revision, the key id, and every subscriber's
  last-seen revision, which is fleet drift visible from a terminal.
  `rollback` republishes the previous revision's payload under a new
  revision number, because a subscriber's anti-replay cursor refuses
  anything that does not move forward. `subscriber add | list | revoke`
  manages credentials, and `add` prints the credential exactly once and
  says so. Every command that changes what the fleet sees goes over the
  admin API and reports what the server returned, and an unreachable
  authority is a distinct non-zero exit rather than something local that
  looks like success. New admin route:
  `POST /admin/config-authority/rollback`.
- **Preview the configuration an authority would push, before it lands.**
  `sbproxy config pull --dry-run` runs a real subscriber cycle up to the
  point of applying: conditional fetch, signature and digest and replay
  verification, the merge over the local document, and the
  unresolved-`${VAR}` screen. Then it prints the plan diff and stops. The
  bundle cache is not written, the replay cursor is not advanced, and
  nothing reloads.
- **Subscribe to signed configuration from an upstream authority.** A new
  `proxy.config_authority.upstream` block points a node at an authority
  that publishes signed configuration bundles. The node polls, verifies
  the signature against the keys it trusts, merges the payload over its
  own file, and applies the result through the same reload transaction a
  SIGHUP takes, so a bad bundle is rejected before anything is published
  and the previously applied configuration keeps serving. Paths that
  describe the box rather than the fleet are refused outright: listeners,
  TLS material, the admin surface, secret backends, cluster identity, and
  the authority block itself. A monotonic cursor refuses a replayed or
  rolled-back revision, including across a restart, and the verified
  bundle is cached so an unreachable authority costs nothing but a
  climbing staleness gauge. `mode: overlay` merges over the local file;
  `mode: replace` treats the bundle as the configuration and will not
  start without one. Bundles that still reference an environment
  variable the node does not set are refused rather than applied as
  literal text, because nobody is reading the log on a hundred machines
  at once. New metrics: `sbproxy_config_bundle_revision`,
  `sbproxy_config_bundle_age_seconds`,
  `sbproxy_config_bundle_fetch_total`,
  `sbproxy_config_bundle_applied_total`, and
  `sbproxy_config_bundle_applied_degraded_total`.
- **A response-cache store you can pick.** The response cache has had
  four storage backends for a while, but only one of them was reachable:
  nothing in the pipeline built the others, so no config could ask for
  them. The new top-level `proxy.response_cache_store` block selects
  `memory`, `file`, `memcached`, or `redis` and the pipeline builds what
  it names. `file` gives you a cache that survives a restart and can be
  shared by replicas pointed at one directory; `memcached` gives you a
  shared cache without standing up Redis. The block sits under `proxy`
  rather than on an origin because one store serves the whole process,
  and every origin with `response_cache.enabled` shares it. Leave it out
  and nothing moves: the store is still Redis when `l2_cache_settings`
  is configured and an in-process map otherwise. See
  [`docs/configuration.md`](docs/configuration.md#choosing-the-backing-store).
- **Encryption at rest for cached responses.** An `encryption` block
  under `proxy.response_cache_store` seals cached headers and bodies
  with AES-256-GCM on the way to whichever backend you chose, so a
  cache directory or a shared memcached is no longer a plaintext copy
  of everything your upstreams returned. The key is a secret reference
  like any other in the config, so it stays out of the config file, and
  it should be 32 random bytes rather than a passphrase. `previous_keys`
  covers rotation: new writes seal under the active key while retired
  keys keep opening older entries. There is no plaintext fallback. A key
  that cannot be resolved stops startup instead of quietly caching in
  the clear, and an entry that fails its integrity check is evicted
  rather than served. Runnable example in
  [`examples/response-cache-encrypted/`](examples/response-cache-encrypted/).
- **Local classifier-based routing.** A `type: classifier` input guardrail
  embeds a prompt with a verified local ONNX model, chooses the nearest
  configured class centroid, and publishes the label to
  `ai.guardrails.labels`. CEL can turn that label into
  `route_to:<model>`, so the gateway routes on request intent without
  sending the prompt to a classifier service. Invalid or unresolved
  classifier artifacts remain inert, and score and margin thresholds prevent
  ambiguous labels. See
  [`docs/ai-gateway.md`](docs/ai-gateway.md#embedding-classifier) and the
  runnable
  [`examples/ai-classifier-routing/`](examples/ai-classifier-routing/).

### Changed

- **A reload that fails now really does change nothing.** Reloading a
  config installed a dozen pieces of process state (log redaction,
  cardinality caps, log sinks, the AI provider catalog, the key plane,
  detection singletons, Lua sandbox limits) *before* it got to the two
  steps most likely to reject the config. So a config that parsed but
  failed to build left the box running the new redaction rules and the
  new AI catalog against the old pipeline, while the log line said the
  previous config was still serving. Everything that can refuse a config
  now runs first, and nothing installs until every one of those checks
  has passed. `POST /admin/reload` also reports what happened rather
  than only whether it worked: the response carries `fully_applied` and,
  when a subsystem loaded with stale state, a `degraded` list naming it.
  A handful of subsystems are still allowed to fail without refusing the
  reload, because a stale AI catalog beats a proxy pinned on an old
  config, but they can no longer fail silently.
- **Changing `proxy.secrets` is refused instead of ignored.** The secret
  resolver owns live connections to Vault, AWS, GCP, or Kubernetes and
  is built once at startup, so a reload never actually rebuilt it. The
  change was dropped on the floor and the first reference to a
  newly-declared backend then failed at handler construction with an
  error naming the reference rather than the cause, long after the
  reload had reported success. Such a reload is now rejected outright
  with a message saying a restart is required, the way a cluster
  identity change already was. Rotating a secret inside your vault still
  needs no restart; only changing where SBproxy looks does. See
  [`docs/secrets.md`](docs/secrets.md).
- **The admin server no longer boots wide open on default credentials.**
  `admin` / `changeme` exists so a first run works, but nothing stopped
  it from being the credential on an admin API bound to `0.0.0.0` with a
  private-range allowlist and no TLS, which is a published password in
  front of key minting and config writes. Validation now refuses the
  default password when the surface is reachable from another host,
  meaning `bind` is not a loopback address or `allow_ips` contains an
  entry outside loopback, and the error names which of the two tripped.
  Loopback with the defaults is untouched, since that is the local
  development path. Three related soft spots went with it: an empty
  `allow_ips` denied nothing at the type level (the safe loopback-only
  default lived in an `if` at the one call site, so the filter itself
  was fail-open), loopback was matched by comparing text so an
  IPv4-mapped peer such as `::ffff:127.0.0.1` was turned away from a
  loopback-only server, and an unparseable `bind` silently fell back to
  `127.0.0.1` rather than failing, which made a typo in a wide bind look
  like it had worked. `sbproxy plan` also stops describing
  `proxy.admin.**` as a reload: `AdminConfig` is read once at startup, so
  a rotated admin password or a swapped certificate needs a restart, and
  the plan now says so. See [`docs/admin.md`](docs/admin.md).
- **Accepted configuration now has an accountable runtime owner.** GraphQL
  depth, introspection, and syntax controls are enforced before upstream
  dispatch; configured CEL feature flags publish atomically across reloads;
  concurrent limits can be keyed by client, API key, header, or route; and AI
  shadow requests run through a bounded, drop-on-saturation lane that cannot
  delay the primary response. Enabling the reserved HTTP/3 listener now fails
  configuration compilation instead of logging and continuing without QUIC.
  A build-time schema audit rejects future keys that have neither a production
  reader nor an exact reviewed `ConfigOnly` justification.
- **Workspace rate-budget behavior now has one owner.** The
  `rate_limit_budget` policy module owns the soft, throttle, and auto-suspend
  state machine and its tests. The previously ignored `per_route_rps` field is
  now a config error; use `rate_limiting` for a per-route ceiling. The
  `headers.include_ratelimit_policy` switch now controls the corresponding
  response header.

### Fixed

- **`GET /admin/drift` no longer invents drift after a hot reload.** The
  baseline it compares against was recorded at startup and by
  `POST /admin/reload`, but not by the file watcher or by `SIGHUP`. So
  editing the config file and letting the watcher pick it up left the
  running config correct and the baseline stale, and drift reported a
  difference that did not exist until the next admin reload or restart.
  Every path that loads a config now records the baseline.
- **Saving config from the admin console no longer leaks health probes.**
  Validating a config meant building the whole pipeline to see whether
  every module would construct, and that construction spawned the active
  health-check probes for any load-balancer target configured with
  `health_check`. The pipeline was then thrown away, but the probes were
  not: each one held the discarded pipeline alive and kept issuing real
  requests at the upstream on its own timer, forever. Every save in the
  admin console's config editor started another full set. An operator
  iterating on a config could leave a target being probed by a dozen
  generations of dead pipelines at once. Validation now constructs
  without starting anything that outlives the check, and the admin write
  path asks for a validation pipeline rather than a live one. The
  `validate` and `plan` subcommands were never affected, because they
  run outside an async runtime where the spawn was already a no-op.
- **Memcached cache keys are hashed.** Memcached rejects a key longer
  than 250 bytes outright, and a response-cache key carries the
  hostname, path, query, and Vary fingerprint, so any reasonably long
  URL produced a key the server refused. Those requests missed on every
  single read. Keys are now hashed before they go on the wire.
- **Memcached TTLs are clamped at 30 days.** The protocol reads any
  expiry above 30 days as an absolute Unix timestamp rather than an
  offset, so a longer configured TTL was stored as a moment in 1970 and
  the entry was dead the instant it was written. Relative TTLs are now
  capped at the protocol ceiling.
- **The file cache no longer discards entries it was asked to keep.** A
  stale-while-revalidate read deleted the entry it had just fetched, so
  the grace window it existed to serve was gone after one request.
- **Concurrent file-cache writes no longer tear.** Two threads writing
  the same key shared one staging file and could interleave their bytes
  into it, and the atomic rename then published the mixture. Each write
  now stages in its own file.

## [1.7.0] - 2026-07-22

The admin release. The console is rebuilt around the editorial brand
system, gains live sampled charts, and, most importantly, stops hiding
data the proxy was already collecting: request sessions, custom
properties, and the gateway's own decisions now reach the operator,
and the alerting engine finally has a face. Per-origin scoping runs
across the estate so a multi-tenant gateway reports per tenant.

### Added

- **Sessions.** Requests carrying `X-Sb-Session-Id` (and optionally
  `X-Sb-Parent-Session-Id`) are reconstructed into logical
  interactions. A session index ranks recent work by requests, tokens,
  cost, wall-clock duration, and worst status, indenting child
  sessions under their parent; a detail page reads one session's call
  chain oldest first with each call's gateway decisions, identifiers,
  AI route, tokens, cost, and properties. This is a view over the
  in-memory request ring, not durable trace storage.
- **Custom properties as first-class dimensions.** Bounded
  `X-Sb-Property-*` headers are captured, redacted per configuration,
  and carried on the request log, where they become filter and column
  choices. Properties named in an origin's `properties.rollup_keys`
  are promoted to durable spend dimensions, so the Spend page can
  group a window by a business dimension the caller supplied.
- **Gateway decisions on every request row.** The log now records what
  the gateway actually did: cache result, retry count, whether
  failover engaged and between which providers, the load-balancer
  strategy and target, and the guardrail outcome. The console reads
  them as one causal rail per row, answering whether the resilience
  configuration fired without opening a body.
- **Alerts page.** The alerting runtime is visible for the first time:
  rule thresholds, current reading, sample floor, and evaluation
  state; sanitized channel targets with delivery health and bounded
  errors; and recent fired, resolved, and test events. A targeted
  channel test exercises delivery without changing configuration.
  `sb.yml` remains authoritative and the page is read-only.
- **Live metrics.** The Metrics page samples the Prometheus endpoint
  and charts what happened between samples: request rate, error rate,
  latency percentiles from histogram bucket deltas, and AI token
  throughput, with numeric tiles and trend sparklines.
- **Per-origin scoping.** The attributed AI counters and the durable
  usage rollups carry the origin the request arrived on, and Metrics,
  Spend, Cache, and Logs can scope to one origin. Panels whose series
  have no origin dimension say so rather than showing unscoped numbers
  under a filter.
- **Context-compression reporting.** The compression policies report
  compressed requests, tokens and cost saved, per-lever savings,
  outcomes, and average ratio per lever.

### Changed

- **`sbproxy apply` now actually applies to the running proxy.** It used
  to compile the config into its own short-lived process, swap that
  process's pipeline, print `apply: reloaded config from ...`, and exit
  without ever contacting the proxy. A running server picked the change
  up only if its file watcher happened to notice the file, so exit 0 was
  not evidence that the config had been accepted, or even seen. A config
  the server would have rejected still exited 0. Apply now pushes the
  config over the admin API and reports what the server did with it, so
  the exit code means something: 4 if the proxy refused the config, 7 if
  no proxy answered, 8 if it loaded but a subsystem kept stale state.
  The admin endpoint defaults to `http://127.0.0.1:9090` and is
  overridable with `--admin-url` or `SB_ADMIN_URL`.

  **This changes the contract.** Apply previously needed no running proxy
  and always exited 0; it now needs to reach one. If you call `apply` in
  CI as a validation step, switch it to the new `--validate-only`, which
  runs every check and stops without contacting anything. That flag is
  the honest name for what the old behavior was actually doing.


- **The admin console follows the sbproxy.dev editorial system.**
  Paper and ink surfaces, a persistent top bar carrying the admin
  host, a live health dot, and the cluster node count, mono
  microcopy, and square corners. Every mutation confirms or fails
  through a toast; validation detail and revision conflicts stay
  inline next to the form that caused them.
- **The admin rate-limit default is 240 requests per minute per
  client IP**, up from 60, with the global cap still ten times that.
  A busy console no longer trips its own limiter.

### Fixed

- **Cache hit and miss counts are no longer always zero.** The Cache
  page read a metric name the server never emitted.
- **The playground reaches locally served models.** A chat against a
  served or managed deployment returned 404 because the request
  skipped the runtime's endpoint resolution and fell back to a
  localhost URL pointing at the proxy itself.
- **Spend groups by a promoted property.** The group-by parameter was
  read without percent-decoding, so the console's own
  `property:<key>` selection failed as an unknown dimension.
- **Spend history reports a disabled rollup store as a hint**, not as
  a failed view.
- **The overview lists managed models by name** with their reserved
  memory, instead of "unknown".
- **An engine that dies after reaching readiness reports why.** The
  health path now carries the bounded, redacted stderr tail into the
  retained error rather than logging only that the process exited.

## [1.6.2] - 2026-07-21

### Added

- **The local llama.cpp engine pin follows your macOS version.** Pinned
  builds now carry their measured minimum macOS, and the host selects the
  newest compatible one: macOS 26 gets the current build, macOS 14 and 15
  get the newest build published against the older toolchain. Previously
  the single pin targeted macOS 26 and died at dynamic-link time on
  anything older. A host older than every pin fails before download with
  the versions named; an explicit `version:` still wins.

### Fixed

- **Loading the admin UI no longer spends the admin rate budget.** Static
  UI bundle assets are exempt from the per-IP admin rate limiter, so
  opening the dashboard cannot starve API polling behind 429s.
- **`sbproxy --version` reports the real product version** instead of a
  stale crate stub.
- **The installer reports the binary it just installed**, not whatever an
  earlier install left on PATH.

## [1.6.1] - 2026-07-21

A point release fixing operational defects found immediately after the
1.6.0 cut.

### Added

- **Configurable admin rate limit.** `proxy.admin.rate_limit_per_minute`
  (default 60, the previous hardcoded value; valid 1 to 100000). Automation
  and dashboards that poll admin endpoints faster than once per second per
  node can now raise the cap instead of silently reading 429s.

### Fixed

- **Docker images start again.** The published linux binaries are built
  against glibc 2.36 so the container runtime image can execute them.
- **Gateway-only clusters no longer report a standing pseudo-outage.**
  Nodes without the worker role are not graded on the model plane, so a
  cluster of pure gateways shows healthy nodes in `/admin/cluster/status`
  and dashboards instead of a permanent degraded state. Worker health
  semantics are unchanged.
- **Model engine launch failures are diagnosable.** A failed engine start
  logs its bounded, credential-redacted stderr tail instead of holding it
  only in memory, and the release certification artifact carries the boot
  log and durable job records.

## [1.6.0] - 2026-07-20

The cluster release. The mesh gains durable replicated state, governed
budgets that mean the same thing on every node, full
self-instrumentation, and a Kubernetes operator that forms it. Local
model serving grows a real deployment control plane and serves across
nodes, tensor-parallel GPU groups, replicas, LoRA adapters, and a
second Python engine. Two load-time behavior changes to note under
Changed: invalid `retry_on` entries and `max_attempts` above 16 now
fail the load, and `sbproxy validate` now fails a config that would
refuse to boot. The serve-related YAML fields remain unpinned, as in
v1.5.0.

### Added

- **Managed model deployments.** Local serving gains a real control
  plane: a canonical `model_host.deployments` desired state (existing
  `serve:` entries lower onto it), content-addressed weight artifacts
  with resumable sha256-verified pulls and protected LRU garbage
  collection, durable deployment revisions and operation jobs, and one
  process-wide runtime manager for atomic reload, warm rolling or
  recreate rollouts with capacity preflight and rollback, admission,
  keep-alive, idle eviction, drain, health, and crash-loop retention.
  Operated through authenticated lifecycle APIs and `sbproxy models
  pull / list / show / ps / stop / remove`.
- **Governed multi-node model serving.** A fleet of gateways serves one
  model estate: constrained node enrollment with strict manual-PKI
  identity verification, a model directory carrying the full node
  roster with stable exclusion reasons and explicit unhealthy-node
  callouts, deterministic capability-aware placement with rolling
  handoffs, durable generation fencing, and signed deployment-authority
  state. A dedicated private HTTP/2 model plane (production mTLS,
  signed one-hop dispatch envelopes, bounded replay protection) routes
  governed requests across current-generation local and peer replicas
  with coordinated cold starts, streaming backpressure, client
  cancellation, and failover only before any client output. Model
  discovery stays OpenAI-shaped and topology-free.
- **Tensor-parallel groups and N replicas per node.** The fit planner
  searches tensor-parallel degrees 1, 2, 4, and 8 over homogeneous GPU
  groups and picks the smallest degree at which a candidate quant fits,
  so a model larger than the largest single card (a 70B at fp16 needs
  about 140 GB) shards across a group instead of being unservable. A
  deployment can also run several replicas of one model on disjoint
  device sets of the same node, so a dense GPU box no longer idles its
  other cards; asking for more replicas than the node can hold fails
  with a reason naming the shortfall.
- **The fit planner understands model shape.** Catalog entries carry a
  `modality` (`chat`, `embedding`, `rerank`, `speech_to_text`,
  `text_to_speech`, `image`): a non-decode model stops being charged
  autoregressive KV-cache VRAM, vLLM launches an embedder in embed
  mode, and a locally served embedder answers `/v1/embeddings` instead
  of a blanket 501. A mixture-of-experts model that does not fit VRAM
  whole keeps attention, shared, and dense tensors on the GPU and
  spills the fewest whole expert layers to CPU RAM (llama.cpp's
  `--n-cpu-moe`), which is how a 30B-A3B-class model runs on a 12 GiB
  card. The planner also predicts decode throughput per placement,
  calibrated against live A100 measurements.
- **SGLang engine driver.** `engine: sglang` serves safetensors models
  on CUDA through SGLang, acquired via `uvx` or a digest-pinned
  container and dispatched over the same OpenAI shape as vLLM. vLLM
  stays the default; SGLang is a one-line opt-in for prefix-heavy agent
  traffic, where the measured head-to-head favors it. The benchmark
  behind that guidance is published in
  `docs/serving-engine-benchmark.md`.
- **Container engine provisioning is the default when a runtime is
  present.** Standing up vLLM from a bare host environment needs its
  whole build toolchain and fails in a cascade on a stock GPU box, so
  when docker or podman is on PATH and the operator has not configured
  provisioning, the Python engines (vLLM, SGLang) now provision from
  curated digest-pinned container images, the exact digests validated
  on real GPU hardware. The host `uvx` path remains available by
  configuration.
- **The embedded in-process engine moves to mistral.rs 0.9**
  (PagedAttention default-on for CUDA, CUDA graphs, FlashInfer). The
  dependency stays opt-in and off by default.
- **Accurate prompt token counting with a pre-flight context-fit
  gate.** Locally served models count prompt tokens against the
  model's own tokenizer (prefetched alongside the weights, parsed once,
  cached) instead of a chars/4 heuristic, and an over-context prompt is
  rejected before dispatch with a clear error instead of failing
  opaquely inside the engine.
- **LoRA adapters over one resident base model.** A vLLM serve entry
  with `lora_adapters` launches the base model with each adapter
  registered by name, so a client requests a fine-tune by name over one
  resident base instead of paying for a separate engine per fine-tune.
  vLLM-only for now; other engines reject the fields with a clear
  reason.
- **Per-deployment engine tuning and version pins.** Canonical managed
  deployments carry the engine tuning knobs (`chunked_prefill`,
  including a TTFT-target mode that derives the batch size,
  `tool_call_parser`, `swap_space_gib`, `cpu_offload_gib`,
  `extra_args`), and the vLLM passthroughs now actually reach the
  engine instead of being rejected at prepare. A deployment can pin its
  own `engine_version` / `engine_image` / `engine_sha256` over the
  node-wide engine policy, so two models on one node can run different
  vLLM versions (canary an upgrade on one model, hold another to its
  certified version); `latest` versions and unpinned images are
  rejected at config validation, and the served engine version surfaces
  in deployment status.
- **Per-completion local-vs-cloud savings.** A serve entry can declare
  the hosted model it displaces and that model's per-million-token
  price in a `reference:` block; every completion the local model
  serves is priced at the reference into a durable ledger, and
  `GET /admin/model-host/value` reports completions and dollars saved
  per model. Explicit config only: no reference means no savings claim,
  never a guessed cloud price.
- **`sbproxy update` acts on stale artifacts.** A plain run now
  fetches, verifies, and atomically swaps a stale engine prebuilt, and
  `--self` replaces the sbproxy binary from its release channel;
  `--check` keeps the report-only behavior. A pinned artifact, or one
  managed elsewhere (a `path`, brew, or apt engine), is reported and
  never mutated; the new `update.{channel, auto, check_interval}`
  block configures it, and `auto` only ever reports in the background.
- **Weight-cache and artifact management.** The admin plane gains a
  verified-artifact inventory (`GET /admin/model-host/files`),
  fail-closed artifact deletion, on-demand garbage collection, per-node
  cluster artifact totals, and a Storage view in the admin UI. A cache
  miss can reuse a discovered Ollama, LM Studio, or Hugging Face cache
  read-only instead of re-downloading weights. `sbproxy models lock`
  pins resolved artifacts to a lockfile, `models verify-lock` reports
  drift, and `--locked` refuses to serve anything off-lock. `sbproxy
  models prune` reclaims content-addressed weight blobs no cached
  artifact references.
- **Served-model priority lanes.** `serve.max_concurrent_requests` caps
  in-flight requests into a local engine behind a queue ordered by the
  calling key's `priority` lane (`interactive`, `standard`, `batch`),
  FIFO within a lane, so a batch flood cannot starve interactive keys;
  an interactive request that would queue spills immediately to the
  next non-served provider when one exists. The lane binds to the key
  record, never a client header.
- **Governed key policy enforces end to end.** One canonical
  effective-policy contract covers configured and dynamically stored
  keys, and lifecycle, tenant, model, provider, route, principal, PII,
  tool, prompt-injection, rate, budget, and admission policy all act on
  the live request path; admin mint, preview, and revisioned PATCH are
  fail-closed and the Keys UI is driven by the server's schema. Keys
  gain a working per-key tokens-per-minute cap, a priority lane,
  `inject_mcp` on dynamically stored keys, and PATCHable metadata, and
  immutable key and attribution dimensions propagate through usage,
  access logs, metrics, traces, and bounded audit events.
- **Cluster-coherent governed-key budgets.** A governed key's request,
  token, and cost limits enforce through a reserve-then-settle flow on
  the live AI path and mean the same thing on every gateway node, in
  two tiers: approximate (the default; each node disseminates settled
  usage over the mesh and admission weighs the whole fleet's spend
  within a bounded staleness window, no external database) and strict
  (atomic reserve and settle against a shared Redis backend, so two
  nodes cannot both admit a request only one has budget for). Strict
  without a Redis backend fails config validation.
- **MCP guardrails.** Deterministic OpenAPI-derived egress policies
  with redirect-target validation, lethal-trifecta session risk
  tracking and enforcement, opt-in dual-LLM quarantine, run-as-user
  credential minting that carries the caller's own Authorization on the
  federation wire, token compaction, and a supervised local stdio MCP
  transport.
- **Traffic governance fills out, and LiteLLM import stops dropping
  keys silently.** OTel, S3, and GCS usage sinks join the existing sink
  set; purpose-scoped egress, quota headroom- and reset-aware routing,
  and local fair-share pools land alongside them. `config
  import-litellm` now classifies every unknown key as mapped, warned,
  or unsupported instead of silently dropping it, and known sink
  callbacks and `max_budget` emit real config.
- **Durable replicated cluster state.** `proxy.cluster.replication`
  turns the mesh's single-owner in-memory state into a replicated,
  durable substrate: each key maps to a preference list of nodes on the
  existing hash ring, writes and reads choose `one`, `quorum`, or `all`
  consistency with read repair, every replica persists write-through to
  redb so an owner restart loses nothing, deletes replicate as
  tombstones collected only after every replica confirms them and a
  grace period passes, and fleet admin runs over topology-safe bounded
  pagination.
- **The mesh reports on itself.** Gossip probe round-trip time and
  indirect-probe retries, enrollment outcomes, transport RPC errors by
  phase and durations by operation, owner-routing outcomes, and a live
  peer-count gauge; every mesh metric now sits in the executable
  stability catalog under the sanctioned `mesh_` prefix.
- **The Kubernetes operator forms the mesh.** With
  `spec.clustering.enabled`, the operator reconciles a StatefulSet
  (stable per-pod identity, one-peer-at-a-time rolling restarts), a
  headless Service publishing the gossip and transport ports, a
  shared-key Secret, and a rendered `proxy.cluster` block with
  full-ordinal seed lists and per-pod node identity, built through the
  typed config so invented fields are impossible. Includes the two
  fixes live validation on kind surfaced: the operator now installs its
  TLS crypto provider (it previously panicked on its first handshake
  and reconciled nothing), and DNS-name gossip seeds resolve before the
  probe path (they were silently skipped, leaving every pod a one-node
  mesh).
- **Compression session state can live on the mesh.** Stateful
  compression's `state.backend: mesh` now runs on the durable
  replicated substrate: conditional versioned session commits with
  deterministic cross-node conflict resolution, tombstoned deletes that
  survive partition and heal, and the same admin list, inspect, and
  purge over fleet pagination. Redis remains the default and
  recommended backend.
- **Measured 3-node cluster benchmark.** `docs/performance.md` gains a
  clustered section from a real 3-node GCP mesh run: forming the mesh
  costs within noise on a single node (43,129 vs 43,958 requests per
  second), three nodes sustain 119,178 requests per second aggregate
  with zero errors, governed spend becomes visible on a peer in 15 to
  20 seconds, and survivors run at 100% success through a mid-run node
  kill, with rejoin about 10 seconds after restart.
- **Request-selectable AI context compression.** Declare named route-local
  profiles and explicit input budgets, then select them through
  `X-Compression`, governed virtual keys, or CEL with deterministic precedence
  and safe invalid-selector behavior. Phase 1 adds `rag_select`,
  `compact_serialization`, and `position_reorder` for explicit line-delimited
  retrieval blocks. The levers use deterministic ranking, reversible
  `sbproxy_table_v1` encoding, closed fail-open outcomes, and semantic-cache
  bypass before the final `window_fit` bound. Stateful summaries use Redis as
  the canonical session store while request workers remain stateless;
  authenticated Admin APIs list, inspect metadata for, and purge that state.
  Per-lever results now appear in bounded metrics and one content-free summary
  event per executed pipeline; reducing levers also feed bounded value metrics,
  dashboards, and the model-host value report. Live request-path acceptance and
  five independently authored structural smoke reports cover the production
  stateless pipeline.
- **MCP tool rollout plane.** Publish several versions of one tool at once
  and roll out breaking changes without breaking callers: a `rollout:` block
  under the `mcp` action's `tool_versioning` declares versions, where each
  routes, and who gets which. Resolution walks a ladder (per-call `_meta`
  requirement, per-session requirements declared at `initialize`, operator
  pins on the authenticated principal, `search_v1`-style catalog aliases,
  then the default), all as semver ranges. Old versions can route to the
  upstream that still serves them or run JavaScript request/response
  adapters against the new one, carry a sunset date that warns or blocks
  past it, and every versioned call lands on
  `sbproxy_mcp_tool_version_calls_total{tool, version, via, deprecated}` so
  migration is observable. `tools/list` advertises the consumer's resolved
  version per tool with the available versions and sunset in `_meta`;
  results carry the version that served them. The `tool_versioning.lockfile`
  is now optional so the rollout plane works without the version-bump gate.
  See `docs/tool-versioning.md` and `examples/mcp-tool-rollout/`.
- **Model deployment management in the built-in admin UI.** Operators can
  browse catalog evidence, add or edit the complete desired deployment map,
  resolve revision conflicts explicitly, and run Load, Stop, or Reset. The
  same UI respects file-managed, admin-managed, and signed cluster-authority
  ownership; file-managed and verifier nodes stay read-only.
- **Cluster operations and unhealthy-node alerts in the admin UI.** The
  Cluster page now shows every node, placement and rollout state, deployment
  authority, and prominent links to unhealthy roster entries. Health remains
  visible when metrics fail, and the last cluster snapshot stays on screen
  with a stale warning after a refresh error.
- Streaming responses now run every built-in output guardrail, with
  verdicts matching the buffered path. A per-stream session matches the
  substring guardrails (injection, toxicity, jailbreak, content safety)
  over a cumulative window of decoded deltas, so a pattern split across
  chunk boundaries still blocks, and word-boundary rules never
  false-block on split words.
- Streamed tool calls are assembled per call and judged by the
  agent-alignment guardrail as each call completes. Block mode holds
  tool-call frames until their call is judged while text keeps flowing;
  flag mode logs and counts without touching the stream.
- Per-entry `stream_policy` (`chunk`, `close`, `off`) on output
  guardrails, plus new metrics:
  `sbproxy_ai_stream_guardrail_violations_total`,
  `sbproxy_ai_stream_guardrail_skipped_total`, and
  `sbproxy_ai_stream_guardrail_decode_fallback_total`.
- A TPOT histogram (`sbproxy_ai_inter_token_latency_seconds`)
  completing the TTFT / TPOT / throughput serving triple, OpenMetrics
  exemplars on the AI latency histograms so a spike links to its
  trace, and the OTel GenAI metric instruments
  (`gen_ai.client.operation.duration`, `gen_ai.client.token.usage`)
  mirrored over OTLP so GenAI-aware backends chart without relabeling.
- `headers:` on the telemetry block for authenticated OTLP export to
  hosted backends. Values accept secret references that resolve at
  boot and fail loud, apply to traces, mirrored metrics, and the
  OTLP log sink, and are masked in config printouts. Every signal now
  carries detected resource attributes (host, process, Kubernetes
  downward API, `OTEL_RESOURCE_ATTRIBUTES`), with explicit
  `resource_attrs` winning conflicts.
- Durable windowed spend rollups: hour and day usage buckets that
  survive restarts, a windowed `/api/usage/spend`
  (`window`/`group_by`/`from`/`to`), and a spend-history section on
  the admin Spend page. On by default with bounded retention; rows
  carry no prompt content and no raw key material.
- Access log AI columns: `cost_usd_micros` (integer micro-USD) and
  `guardrail_category` / `guardrail_action` on every guardrail
  intervention, mirrored onto the request envelope and the admin
  request ring; `/api/requests` accepts `guardrail_action` and
  `guardrail_category` filters.
- Slack and PagerDuty alert delivery channels as formatters over the
  existing webhook transport (PagerDuty trigger/resolve keyed on a
  stable per-rule deduplication key), plus Prometheus alert examples
  for AI budget utilization, provider error burn, and spend velocity.
- MCP `execute_tool` spans following the OTel GenAI agent
  conventions, parented into the caller's trace so agent request,
  tool dispatch, and LLM calls render as one tree; the AI request
  span emits tool-call span events (ids and names always, arguments
  only under `trace_content`).
- Admin views: AI performance (TTFT / TPOT / throughput and provider
  health with failovers, cascade tiers, and router decisions), Spend
  (live attributed cost, token, and request breakdowns by model,
  provider, key, team, and project),
  Guardrails (blocks by category and wasted tokens / spend by kind),
  live tail on the Logs view with full-record row expansion and
  operator-configurable trace deep links
  (`admin.trace_url_template`).
- **Executable capability registry.** SBproxy's claims about itself are
  now checkable code: every capability claim carries a support level,
  nothing may be called stable unless a test proves a production caller
  consumes it, and config-only is the honest, permitted name for a
  surface that parses and does nothing. Build guards fail on a
  published metric no code writes and on a tenant-relevant metric
  family missing its tenant labels, and the shipped Prometheus alert
  rules are validated with promtool in CI. This machinery surfaced the
  availability SLO that read 100 percent forever and the
  never-incremented metric families fixed in this release.
- **Getting started and framework integrations.** A dedicated
  `docs/getting-started.md`, install and quick start grouped together
  in the README, and five framework one-pagers (LangChain, Vercel AI
  SDK, Pydantic AI, Mastra, n8n) whose snippets were all executed
  against a running gateway before landing. The README lede now leads
  with what the gateway does today.

### Changed

- **`sbproxy validate` runs the boot path.** `validate`, `plan`, and
  `apply` now construct the same compiled pipeline the server and
  reload paths construct, so a config that would refuse to boot fails
  validation instead of validating clean (measured before the change:
  five published examples validated but refused to boot). Custom YAML
  tags are rejected at compile: serde_yaml strips unknown tags, so a
  `password: !env ADMIN_PASSWORD` silently became the literal string
  `ADMIN_PASSWORD`; the error now points at `${VAR}` interpolation,
  and `${VAR:-default}` fallbacks work.
- **Status-code upstream retries moved onto a dedicated decision
  hook.** The retry decision fires on the pinned Pingora fork's new
  upstream-response hook, once per upstream response and before any
  bytes reach the client, replacing the response-filter workaround;
  connect-time and status retries now share one attempt counter and
  cap. Load-time validation is a behavior change: a `retry_on` entry
  must be `connect_error`, `timeout`, or a status in 100..=599 (junk
  entries used to deserialize and silently never match; they now fail
  the load naming the entry), and `max_attempts` above 16 is rejected.
  Retries land on
  `sbproxy_upstream_status_retries_total{origin, status}`.

### Fixed

- **`retry_on: timeout` is honored, in both upstream phases.** The
  token was accepted and documented but nothing consulted it. A
  connect-phase timeout now retries under either `timeout` or
  `connect_error`, and an established-connection upstream read or write
  timeout retries when the policy allows it, sharing the same attempt
  cap, and only when the request is replayable and no response bytes
  have reached the client. The fork's retry loop also gains a backstop
  refusing any retry after response bytes were sent, regardless of what
  marked the error retryable.
- **Redis L2 connections keep their TLS, AUTH, and database
  semantics.** `redis://` and `rediss://` URLs preserve ACL and
  percent-encoded credentials, IPv6 hosts, the selected database,
  private CAs, and mutual TLS uniformly across the general L2 store,
  compression state, and admin paths, compiled once per config
  generation into an immutable connection snapshot. The blocking
  plaintext RESP path is replaced with a real client, and connection,
  TLS, authentication, and command failures classify without leaking
  endpoints or credentials.
- **Cross-node mesh RPCs no longer stall about 40 ms on Linux.** The
  transport wrote a frame's length prefix and body as two separate
  writes and never set TCP_NODELAY on accepted sockets, so Nagle plus
  the delayed-ACK timer held every response leg. Frames now leave as
  one write and the server sets nodelay on accept; a small-frame
  replica fetch drops from about 41 ms back to sub-millisecond.
- **The MCP gateway speaks the spec's camelCase on the wire.**
  `initialize` results, tool results, and tool annotations serialized
  as snake_case (`protocol_version`, `is_error`, `read_only_hint`),
  which the official TypeScript SDK's schema rejects outright, so a
  strict client could not connect at all and tolerant clients silently
  dropped tool error flags. Serialization is now camelCase; snake_case
  still parses so results from older nodes survive mixed-version
  rollouts.
- **Raw `hf:` references serve through the live path.** The production
  runtime manager only resolved fully pinned catalog artifacts, so a
  raw `hf:Org/Repo` reference in a `serve:` block failed reconciliation
  and, in practice, no open-weight model could be served on a GPU from
  the gateway. Raw references now resolve, pull, and serve end to end,
  validated on real multi-GPU NVIDIA hardware across vLLM, SGLang,
  embeddings, and tensor-parallel launches.
- **SGLang serving hardening.** The launcher passes a runtime-owned
  memory fraction so SGLang no longer OOMs at launch; liveness probes
  hit a non-generating endpoint instead of one that generated tokens
  (and returned 503 under load); one transient health-probe miss no
  longer kills a ready engine; and the probed SGLang version is
  recorded on the provisioned engine.
- **Self-host admin edges.** Attributed AI token and cost metrics now
  populate `/api/usage/spend` for locally served providers; direct AI
  responses no longer log status 0 when a real response was written; an
  upstream-TLS native-certificate failure on macOS is an actionable
  startup error instead of a panic; and the admin Keys UI submits the
  backend's full key-policy shape.
- **The `alerting:` block alerts, and declared metrics record.** The
  alerting config parsed and silently discarded its settings; it now
  drives a live dispatcher (delivering through the Slack and PagerDuty
  channels above). The response-cache hit/miss, circuit-breaker
  transition, and guardrail-block families were declared and scraped
  but always zero; they are now written by the live request path, and
  the metric drift guard follows aliased writers it was blind to.
- **The release provenance push no longer clobbers the SBOM
  attestation.** The provenance step replaced the image's attestation
  tag wholesale after the CycloneDX attest step, so
  `cosign verify-attestation --type cyclonedx` failed on every
  published image; the jobs are reordered so the SBOM attestation
  appends last, and the offline verification recipe in
  `SUPPLY-CHAIN.md` now works with current cosign.

### Removed

- The unattributed AI metric families `sbproxy_ai_requests_total`,
  `sbproxy_ai_tokens_total`, `sbproxy_ai_cost_dollars_total`, and the
  per-virtual-key trio. They were registered but never written on the
  live path, and counter series register lazily, so no released
  binary ever exposed a sample under these names. Consumers read the
  attributed families; details in docs/metrics-stability.md.
- **The Go-era `secret:<name>` colon form.** It resolved through a
  logical-name map with an environment fallback and was superseded by
  the provider-URI `secret://<backend>/<name>` schemes; a stale
  reference now fails config load with a migration pointer instead of
  resolving through a side channel. `proxy.secrets.map` still parses
  for schema-v1 compatibility and warns at boot that it has no effect.
- **Dead mesh scaffolding and write-only key counters.** The
  unreferenced leader-election, health-monitor, consistency, and
  membership-protocol modules are gone (live membership is the gossip
  loop), along with a legacy wire variant only tests constructed and
  the per-request mesh key counters that were incremented on every AI
  request but never read anywhere. Governed-key budget enforcement is
  unaffected, and the AI hot path now does no counter work at all.
- **Two dead metric families**: `sbproxy_dedup_cache_size` (registered,
  never written, no readers) and the hostname-keyed
  `sbproxy_cache_hits_total` duplicate; the overview dashboard reads
  the now-live `sbproxy_cache_results_total` instead.

## [1.5.0] - 2026-07-08

Model serving lands: run open models on your own GPU behind the same
gateway that fronts the 66 hosted providers, plus the engine-acquisition
and self-host work queued since v1.4.0. No promises about backward
compatibility for any of the new YAML fields below until a later version
pins them.

### Changed

- **Duration strings parse consistently everywhere.** The `ms`/`s`/`m`/`h`/`d`
  units, compound forms like `1h30m`, decimals like `1.5h`, and a bare
  number (seconds) are now accepted by every duration field, instead of
  each config block supporting a different subset (so a value like `1h`
  that parsed in one block and errored in another now works in both). This
  only widens what is accepted; no previously valid value changes meaning.
- **Unresolvable upstream hosts always fail closed.** The upstream SSRF
  guard no longer blocks the request worker on a per-request DNS resolve
  (it resolves asynchronously now), and as part of that an upstream host
  that fails to resolve is uniformly rejected, closing an edge where an
  origin with a private-CIDR allowlist could previously fail open.

### Removed

- **Two rate-limit config options that parsed but never enforced anything
  are gone.** A virtual key's `max_tokens_per_minute` (and the credential
  policy's `tpm`) and an origin's per-origin `rate_limits:` block both
  compiled and round-tripped but were never read at request time, so an
  operator who set them believed they were capped when they were not.
  They are removed rather than wired. Existing configs that still set
  these keys keep loading (the keys are ignored). The live limits are
  unaffected: the top-level workspace `rate_limits:` budget, and the AI
  gateway's `model_rate_limits` / per-surface limits, all still enforce.
- **Two build-only feature flags that nothing enabled were removed**
  (`sbproxy-platform/postgres-store` and an unused `sbproxy-modules`
  rate-limit feature), along with roughly 4,300 lines of verified
  zero-caller internal code. No shipped configuration or public API
  changes; the redb/SQLite storage stack is unaffected.

### Added

- **vLLM, provisioned with `uvx`.** vLLM is a Python package, not a
  single-binary release, so sbproxy now acquires it by fetching `uv`
  (Astral's single-binary package manager) and running the engine through
  `uv tool run` (`uvx`): a cached, ephemeral environment that uv sets up
  on first use, bringing its own Python if the host lacks one. The default
  wheel is CUDA-enabled, so a safetensors model offloads to an NVIDIA GPU
  on a box that carries only the driver. Opt in with
  `engines.vllm.acquire.source: uvx`; `sbproxy run <model>` sets it for
  you. `sbproxy doctor` reports it as the recommended vLLM path.
- **`sbproxy update`: is any of it out of date.** A dry-run freshness
  report: `sbproxy update` checks the inference engine release feed (the
  pinned llama.cpp prebuilt vs the latest) and the cached models (flagging
  any that track a moving ref like `main` and could be behind upstream);
  `--self` also checks the sbproxy binary against its release channel.
  `--json` for tooling. Reports only, nothing is mutated; a pinned artifact
  is never swapped without an explicit run.
- **`sbproxy config print`: see the effective config, with secrets
  masked.** Prints the config after built-in defaults + the file +
  `${ENV}` interpolation, so it is obvious what a box will actually do.
  Inline secret values (an `api_key`, `client_secret`, `token`, ...) are
  masked; secret *references* (`vault://`, `${ENV}`, `file:`, ...) are
  shown, since they are pointers, not the secret. `--json` for tooling,
  YAML by default.
- **`sbproxy models list` / `show`: discover what this host can run.**
  `sbproxy models` (or `models list`) prints one row per catalog model
  with a real per-GPU fit verdict (reusing the same probe `doctor` uses),
  the resolved engine, params, and cache status (cached / not-pulled).
  `sbproxy models show <id>` prints the full entry: HF repo, source,
  revision, sha256 digests, engine, pull policy, and quants. `--json` on
  both for scripts and the admin UI; `--catalog-file` points at an
  operator manifest. Resident / serving state needs a running gateway and
  is not shown by this offline view.
- **`sbproxy run <model>`: serve a model in one command, no YAML.**
  `sbproxy run qwen3-14b` (or `sbproxy run hf:Org/Repo:Q4_K_M --name
  coder`) synthesizes a minimal serving config, checks the model can run
  on this host (the same detection `sbproxy doctor` uses, so a model with
  no viable engine fails now with a remediation instead of a later 502),
  and boots the gateway with an OpenAI-compatible endpoint on loopback at
  `http://127.0.0.1:<port>` (both the IP and `localhost` route). The
  engine and weights are acquired on the first request. Flags override
  the port, engine, acceleration, and cache directory; `--dry-run` prints
  the resolution and the synthesized config without serving.
- **Model pull honors manifest pins and works for safetensors/vLLM on a
  fresh box.** A model's weight pull now uses the manifest `revision`
  (was hard-coded `main`) and verifies the per-file `sha256` when one is
  pinned, so a digest mismatch fails the pull loudly instead of serving
  bad weights. And a safetensors model served via vLLM now pre-fetches
  its `config.json` on first use, so it admits on a box that has never
  pulled it (previously it failed with "no model metadata").
- **sbproxy acquires the inference engine, not just finds it on PATH.**
  A `serve:` block can now carry a per-engine `engines.<engine>.acquire:`
  block: for llama.cpp, `source: release` (the default) fetches a pinned
  ggml-org prebuilt for the host platform and acceleration
  (`accel: auto|cuda|vulkan|metal|cpu`; on Linux a GPU build means the
  Vulkan asset, since there is no upstream CUDA Linux prebuilt),
  sha256-verified when a digest is pinned, while `source: path` points at
  an operator-installed binary for an air-gapped box. A host with no
  engine now serves a GGUF model instead of failing at the first request,
  and a bad acquisition (a `path` source with no path, a `latest`
  version) is rejected at config load, not at runtime. Engine identity
  stays the allowlisted set (`vllm`, `llama_cpp`, `embedded`); only how
  the binary is obtained is configurable. The gateway also detects a
  container runtime now, so `engine: auto` can resolve to vLLM's
  container path for safetensors weights.
- **The released binary is GPU-aware out of the box.** The `gpu-nvidia`
  (NVML GPU discovery with an `nvidia-smi` fallback) and `model-weights`
  (Hugging Face weight download) features moved into the `sbproxy`
  binary's default feature set, so one downloaded artifact adapts to its
  host: the NVIDIA driver library is loaded at runtime when present,
  never linked, and a GPU-free host still runs the same binary (a
  `serve:` provider rejects admission cleanly there). Building with
  `--features gpu-nvidia,model-weights` is no longer needed for local
  model serving. Library consumers of the workspace crates still opt in
  per crate.
- **`sbproxy doctor` is the self-host front door.** The subcommand now
  reports the full picture of what the binary can do on this host and
  how to make it serve: OS and arch, CPU and RAM, free disk in the cache
  directory, the GPU (or CPU / unified-memory budget) the `serve:`
  admission path sees, NVIDIA driver and CUDA / Metal / ROCm, container
  runtimes and daemon liveness, package managers, Python and uv, and
  Hugging Face reach plus whether `HF_TOKEN` is set. For each engine
  (llama.cpp, vLLM, embedded) it lists what is installed (with version)
  and which acquisition sources are viable here, each with a reason.
  Pass a config file (`sbproxy doctor sb.yml`) and it adds, per `serve:`
  model, what `engine: auto` resolves to and a coarse fit preview, and
  exits non-zero when a configured model has no viable engine.
  `--format json` emits a stable machine-readable report; collection is
  read-only.
- **Local model serving runs on Macs and CPU boxes, not just NVIDIA.**
  The fit planner used to see zero devices on anything but an NVIDIA GPU,
  so a `serve:` block on a Mac or a GPU-less server rejected every model.
  The GPU probe is now layered: NVIDIA discrete GPUs first, then Apple
  Silicon unified memory (reported as the working-set budget), then a CPU
  budget sized to a fraction of system RAM. A small GGUF is admitted
  against unified memory or RAM and served by llama.cpp or the embedded
  engine; FP8 and other datacenter quants are still refused on hardware
  that lacks the kernels. Set `SBPROXY_CPU_MEMORY_FRACTION=0` to opt back
  into rejecting admission on a GPU-less host. The weight cache defaults to
  `~/.cache/sbproxy/models` for a non-root run (and the service path
  `/var/lib/sbproxy/models` when running as root), so serving works out of
  the box without configuring `cache_dir`.
- **Serve-preflight warnings at config load.** A config that declares
  `serve:` on a host with no visible GPU, or with a serve entry whose
  engine has no binary and no container runtime, now logs a warning at
  startup and on every hot reload naming the model, the resolved
  engine, and the blocker, instead of degrading silently until the
  first request fails over.

### Changed

- **A forward rule whose header matcher names an invalid HTTP header now
  fails at config load.** The `header:` matcher on a `forward_rules:`
  entry precompiles its name at load time; a name that is not a valid
  header (for example one containing spaces) previously loaded and then
  silently never matched, and now reports a clear error at load and on
  reload. Valid configurations are unaffected.

### Fixed

- **Revoking a key now blocks OIDC/JWT identities mapped to it.** With
  `key_management.oidc_claim_map` configured, a verified token whose mapped
  claim named a revoked, blocked, or expired record was silently downgraded to
  an ungoverned request (no per-key policy) instead of being denied. The
  mapped-claim path now mirrors the bearer path: an inactive record denies with
  403, a claim naming a missing record denies with 401, and a store outage
  fails closed unless `failure_mode_allow` is set. Tokens that carry no mapped
  claim are unaffected.

- **Error responses now emit valid JSON when the message contains a quote or
  backslash.** The shared `send_error` helper and the ledger, policy, and
  storage error paths built the `{"error": "..."}` body by string
  interpolation, so a message carrying a client-supplied value (for example a
  rejected AI `model` name) could break the JSON envelope or inject a sibling
  field. Every error body is now serialized, so the message is always escaped.

- **JSON threat protection now scans the whole request body.** The depth, key,
  and size checks read only the first body chunk, so a JSON payload whose
  oversized structure began past the first chunk could slip past the scan while
  the full body still reached the upstream. The scan now accumulates the
  complete body, bounded by `max_total_size` (or a hard ceiling when unset),
  before validating it.

- **The in-memory idempotency cache and the native SSE reassembly buffer are
  now bounded.** The single-instance idempotency store grew without limit under
  unique keys and is now a capacity-bounded LRU. The native streaming framer
  buffered upstream bytes until a frame boundary and now caps the reassembly
  buffer, so an upstream that never closes a frame cannot grow it without limit.

## [1.4.0] - 2026-06-27

Fourth minor release on the Rust v1.x line. Hardening and reach for the
AI gateway and the clustering mesh: mutually-authenticated TLS on the
peer transport, external HTTP guardrail providers on the request and the
response, native Langfuse and Datadog usage sinks, and per-server
namespace control for MCP federation. One correctness fix promotes
budget windows from parsed-but-ignored to enforced. No config-breaking
changes; existing `sb.yml` files compile unchanged, and every new field
is default-off.

### Added

- **Mesh peer mTLS.** The mesh peer transport can run over
  mutually-authenticated TLS: set `key_management.cache.mesh.peer_tls` with
  `cert_file`, `key_file`, and `ca_file` (plus an optional `server_name`,
  default `sbproxy-mesh`). Every inbound connection must present a CA-signed
  client certificate and every outbound connection presents this node's
  certificate, both verified against the CA, so an untrusted peer cannot join
  the cache fabric. Plaintext when unset.

- **Per-server namespace mode for MCP federation.** A federated upstream can
  set `namespace: always` to expose every tool as `<prefix>.<tool>` and every
  resource as `<prefix>/<uri>`, where the prefix is the server's `prefix` (or
  a name derived from its origin). The default, `on_collision`, keeps bare
  names and only qualifies one when it clashes with an earlier server.

- **External HTTP guardrail providers.** An AI origin's `guardrails.external`
  list runs external guardrail services alongside the built-in checks.
  Input-mode entries (`pre_call` / `during_call`) inspect the request before
  dispatch; output-mode entries (`post_call` / `during_call`) inspect the
  non-streaming response before it is cached or sent. Either blocks on a
  not-allowed verdict (`logging_only` records only), and a transport or parse
  error honors each entry's `fail_open` flag. Provider presets shape the
  request and response for Presidio (`/analyze` with a findings array) and a
  generic `{"input"}` shape that fits Lakera, Aporia, and custom endpoints,
  with an optional API key on a configurable auth header. Streaming-response
  and AWS Bedrock (SigV4) guardrails are not yet wired.

- **Native Langfuse and Datadog usage sinks.** Alongside the JSONL-file,
  webhook, and ledger sinks, `usage_sinks` now accepts `type: langfuse`
  (`host` plus public/secret key; posts a generation observation to
  `/api/public/ingestion`) and `type: datadog` (`api_key` plus optional
  `site` / `service`; posts to the logs-intake API). Both are
  fire-and-forget and never fail the request they record. Object-store
  (S3/GCS) and OTel usage sinks are not yet included.

### Fixed

- **Budget windows now reset per period.** A budget `limit` with a `period`
  (`daily`, `monthly`, or a duration like `30d`) was parsed but never enforced
  as a rolling window, so spend accumulated forever and a daily cap behaved
  like a lifetime cap. Each limit now accrues against its own per-period
  bucket, so a daily cap clears at the next day and a daily and a monthly cap
  on the same scope are tracked independently. Cumulative limits (no `period`,
  or `total` / `lifetime`) are unchanged.

- **MCP federation now advertises the disambiguated name on a collision.**
  When two upstreams exported the same tool name, the gateway kept the
  prefixed name only as an internal registry key while still advertising the
  bare name, so the second tool was unreachable and `tools/list` showed a
  duplicate. The disambiguated name (`<server>.<tool>`, or `<server>/<uri>`
  for resources) is now the advertised, routable name; resource reads still
  forward the original upstream URI.

## [1.3.1] - 2026-06-25

Patch release. Fixes TLS, which was broken on startup in v1.2.0 and v1.3.0.

### Fixed

- **TLS no longer panics on startup.** The OCSP-staple and ACME-renewal
  background tasks were spawned before the proxy runtime existed, so any HTTPS
  listener with a manual cert (`tls_cert_file` / `tls_key_file`) or enabled ACME
  crashed the process on boot ("there is no reactor running"). The tasks now
  spawn on a runtime that is always available.
- **HTTP/2 is now negotiated over TLS.** No TLS listener advertised `h2` in ALPN,
  so every HTTPS connection fell back to HTTP/1.1. The manual-cert, ACME, and
  mTLS listeners now enable h2; clients that do not offer it still get HTTP/1.1.

## [1.3.0] - 2026-06-25

Third minor release on the Rust v1.x line. Two headlines: dynamic key
management with an open-source mesh for clustering, and a wave of
state-of-the-art AI-gateway capabilities. No config-breaking changes;
existing `sb.yml` files compile unchanged, and every new field is
default-off.

### Added

- **Dynamic key management.** Inbound virtual keys are a live, governed
  resource: mint, list, rotate, and revoke them at runtime through an admin
  API under `/admin/keys`, with no reload. Keys are hashed at rest with
  HMAC-SHA256 and a server pepper, and a revoke takes effect on the next
  request. Upstream provider credentials are encrypted at rest with an
  AES-256-GCM envelope or held as a vault reference. Per-key policy travels
  with the key: model and provider allow/deny, rate and token limits, token
  and USD budgets, expiry, required PII redaction, principal selectors, a
  pinned model, injected tools, and an injection-scan bypass. Pluggable
  stores: embedded (redb), Redis, or a secrets manager. OIDC and JWT claims
  can map to a key. New `key_management:` config block. (#542, #543)
- **Open-source mesh clustering.** The mesh layer (SWIM gossip, a
  consistent-hash distributed cache) is now Apache-2.0 in this repository.
  Setting `cache.tier: mesh` keeps the key plane coherent across a replica
  fleet: a key minted on one replica is usable on any, and a revocation on
  one denies on the rest, with no external control plane in the path. Per-key
  spend and rate counters remain node-local; cluster-wide budget enforcement
  uses a shared backend. (#542)
- **State-of-the-art AI-gateway differentiation.** A verifiable, hash-chained
  and optionally Ed25519-signed usage ledger; a single sandboxed CEL policy
  plane over guardrails, budgets, routing, and principal; a guardrail mesh
  that fuses verdicts on a quorum with a verdict cache; outcome-aware routing
  by realized cost-per-success; predictive budgets that warn, then downgrade,
  then block; and LLM-aware resilience: per-error retry, context-window
  compression, hedged and raced dispatch, and content-policy fallback to a
  more permissive provider. (#538, #539, #540, #541)
- **LiteLLM drop-in.** A `config import-litellm` translator, model groups, and
  usage-sink plus budget foundations for moving a LiteLLM proxy over. (#537)
- **Model-based routing** with a failover metric and a refreshed model-id
  catalog. (#536)
- VHS cassettes for the AI gateway and the example configs. (#534)

### Changed

- The mesh wire encoding moved off the unmaintained `bincode` crate to
  `postcard`.
- The README and docs now lead with the two-way framing: SBproxy governs the
  AI you call and the AI that calls you.

## [1.2.0] - 2026-06-24

Second minor release on the Rust v1.x line. Headline: local ONNX
inference for the embedding semantic cache and the prompt-injection
classifier, a standalone OpenAI-compatible embedding source, a
best-of-class OpenTelemetry story for the AI gateway, and the move to
Apache 2.0. No config-breaking changes; existing `sb.yml` files compile
unchanged.

### Added

- **Local ONNX inference for the semantic cache.** The embedding
  semantic cache can vectorize prompts on-box, with no per-call API cost
  and no prompt egress. `source: sidecar` runs the embedder in the
  supervised classifier sidecar; `source: inprocess` loads an ONNX model
  (all-MiniLM-L6-v2 by default) into the proxy behind an explicit opt-in
  and a `max_model_bytes` guard. Prompt-injection v2 gains first-class
  ONNX detectors (`detector: sidecar`, `detector: inprocess`) next to the
  zero-dependency heuristic default. See
  [docs/local-inference.md](docs/local-inference.md).
- **OpenAI-compatible embedding source** (`source: openai`). Vectorize
  prompts through any standalone OpenAI-compatible `/v1/embeddings`
  endpoint, decoupled from the origin's chat providers: point it at
  another sbproxy that fronts an embedding model, at OpenRouter, or at a
  hosted provider. Auth defaults to `Authorization: Bearer`; set
  `auth_header` / `auth_prefix` for `api-key` / `x-api-key` endpoints, or
  carry the credential in arbitrary extra `headers`.
- **Best-of-class OpenTelemetry for the AI gateway.** AI spans now carry
  derived USD cost (and a first-class cost metric), map failures
  (guardrail, provider 429/5xx, content filter) to span status ERROR with
  an `error.type`, and emit capture-gated, redacted prompt and completion
  content as OpenInference / OTel gen_ai span events. A pinned GenAI
  semantic-convention conformance test guards against attribute drift.
  The reference stack adds Arize Phoenix and Langfuse with provisioned
  dashboards, plus cost-aware (ParentBased + TraceIdRatio) trace
  sampling. [docs/observability.md](docs/observability.md) gains a
  verified backend matrix.
- **Per-credential, multi-tenant, multi-model AI value tracking** in the
  reporting surface.
- **GCP Secret Manager vault backend** (`gcpsm://`), joining HashiCorp
  Vault (`vault://`) and AWS Secrets Manager (`awssm://`).
- Configurable retry on upstream response statuses.
- Web Bot Auth key IDs now feed the agent identity proof.

### Changed

- **SBproxy OSS is now licensed Apache 2.0.** The previous Business
  Source License field-of-use restriction is dropped; the project is free
  for any use, including production and commercial, with no field-of-use
  limit.
- **Vault references moved to per-provider schemes.** The scheme now
  selects the backend (`vault://` HashiCorp, `awssm://` AWS, `gcpsm://`
  GCP) rather than a `vault://<alias>` umbrella form. The legacy form
  still resolves during a deprecation window and logs a one-time warning.
- **HTTP/3 (QUIC) is temporarily disabled** until native support lands in
  the underlying proxy engine. Existing config still parses, but no
  HTTP/3 listener starts.
- The admin playground chat route is gated by default.

### Fixed

- Credential selectors are enforced consistently across request paths,
  and the AI preference script context is exposed to request scripts.

## [1.1.0] - 2026-06-06

First minor release on the Rust v1.x line. This release carries
breaking changes to the MCP tool-access policy (now closed-by-default
and principal-aware); read the Breaking section and
`docs/migration-mcp-rbac.md` before upgrading. It also ships 66 native
AI providers behind one OpenAI-compatible API.

### Breaking

- **MCP default-deny**: `ToolAccessPolicy` flipped from
  open-by-default to closed-by-default. An unknown caller (no
  matching ACL rule) is denied every tool. An empty `allowed: []`
  list under an ACL rule means "deny all", not "allow all".
  Operators who want the legacy behavior add `default_allow: true`
  on the origin's MCP action. The legacy `key_permissions: { key: [tools] }`
  shape is gone; rewrite to the principal-aware `tool_access[]`
  selector list. See `docs/migration-mcp-rbac.md`.

- **MCP principal-aware ACL**: `ToolAccessPolicy` now
  carries `tool_access[]` rules with `principals[]` selectors
  (`virtual_key`, `sub`, `team`, `project`, `user`, `role`,
  `tenant_id`) plus an `allowed[]` tool list. The legacy
  `key_permissions: HashMap<String, Vec<String>>` map is removed
  along with `ToolAccessPolicy::is_tool_allowed(key, tool)`; the new
  surface is `policy.check(&principal, tool) -> ToolAccessDecision`
  and `policy.filter_tools(&principal, &tools)`. `tools/list` now
  filters by RBAC against the inbound principal (the legacy schema
  leaked tool names through `tools/list` even when the gate would
  deny the matching `tools/call`). A new `tool_quotas[]` table
  enforces per-tool sliding-window quotas keyed on
  `(tenant_id, principal_id, tool_name)`. See
  `docs/migration-mcp-rbac.md`.

### Added

- **66 native AI providers behind one OpenAI-compatible API.** The
  embedded `ai_providers.yml` registry ships 66 providers (up from 43),
  adding Hugging Face Inference, GitHub Models, Vercel AI Gateway,
  Nebius, Baseten, Lambda, FriendliAI, Scaleway, Nscale, DigitalOcean
  Gradient, OVHcloud, Inference.net, kluster.ai, OpenPipe, Writer,
  Upstage, Aleph Alpha, MiniMax, Volcengine Ark (Doubao), Tencent
  Hunyuan, Baidu Qianfan (ERNIE), StepFun, and Mixedbread. The catalog
  is plain YAML and operator-extensible at runtime via
  `proxy.ai_providers_file`; the `model` field passes through to the
  upstream, so any model a provider serves is reachable without
  per-model config. The "200+ models" reach is native (bring your own
  keys); OpenRouter is one provider among the 66, not a dependency. See
  `docs/providers.md#extending-the-provider-catalog`.

- **Session ledger from live MCP traffic.** A new top-level
  `session_ledger:` block makes SBproxy emit the canonical
  `session-ledger-v1` run record (shared with mcptest) from its
  `tools/call` path: one `header` per session, then one `tool_call`
  record per call carrying `session_id`, a zero-based `hop_index`, the
  bare tool name and server, redacted `params` / `result`, an error
  flag, and the round-trip `duration_ms`. `sink: logging` (default)
  emits each record as a `session_ledger` tracing line; `sink: file`
  with a `path:` appends NDJSON. Off unless `enabled: true`; when off
  the tool-call path pays only a single atomic load. Payloads are
  redacted with the same secret-stripping the access log uses. See
  `docs/mcp.md` and `examples/mcp-federation/sb.yml`.

- **Structured-log schema v2 (`SCHEMA_VERSION = "2"`).** Three changes
  land together so downstream tooling can read them in one swing:
  optional `session_id` and `user_id` top-level fields parallel the
  `RequestEvent` envelope (cross-surface JOIN no longer relies on
  `request_id` alone); the field-key redaction marker is normalized
  to `[REDACTED:<NAME>]` everywhere (was `<redacted:name>` in v1) so
  the schema-v1 layer matches the existing PII-rule replacement
  shape; the schema bump is additive on the field set (a v1 reader
  parsing a v2 line keeps working because every new field is
  `skip_serializing_if = Option::is_none`). Marker normalization is
  a string change; downstream tooling that greps for the old
  `<redacted:...>` form must update.

- **Phase-timing breakdown on the access log + new
  `sbproxy_phase_duration_seconds` Prometheus histogram.** The
  access log carried `latency_ms` end to end and that was it; an
  operator looking at a slow request could not tell from the log
  whether the time went to the auth provider, the upstream, or a
  response transform. Three new optional fields land on every
  `AccessLogEntry`: `auth_ms` (request_start → auth provider
  returned), `upstream_ttfb_ms` (request_start → first upstream
  response byte), `response_filter_ms` (first upstream byte → end
  of `response_filter`). All three are `Option<f64>` and
  `serde-skip` when None, so origins that short-circuit (cache
  hit, auth deny) keep compact lines. The same observations also
  feed a new `sbproxy_phase_duration_seconds{phase, origin}`
  histogram with buckets identical to
  `sbproxy_request_duration_seconds` for cross-cut dashboards. See
  `docs/access-log.md` and `docs/metrics-stability.md`.

- **Nine standard HTTP fields on the access log: `host`, `query`,
  `protocol`, `scheme`, `user_agent`, `referer`, `upstream_status`,
  `response_content_type`, `response_content_encoding`.** The log
  was missing the canonical fields most HTTP access-log consumers
  expect (Apache, NGINX, Envoy, the cookie-cutter ELK pipeline).
  `host` is the client-supplied Host header (distinct from
  `origin`, the matched virtual-host pattern); `upstream_status`
  is the upstream's response code when the proxy rewrote the
  status the client sees. All nine are `Option`, `serde-skip` when
  not applicable. Promoted from the generic header allowlist
  because nearly every analytics consumer wants them. See
  `docs/access-log.md`.

- **Opt-in OpenTelemetry metrics mirror alongside the canonical
  Prometheus surface.** New `telemetry.export_metrics: true`
  (with `telemetry.metrics_interval_secs` cadence, default 30s)
  installs an OTel `MeterProvider` that ships observations to the
  same OTLP collector the trace pipeline targets. The first two
  mirrored instruments are `sbproxy.phase.duration` and
  `sbproxy.request.duration`; record-paths fall back to OTel's
  global no-op meter when the export is off, so operators pay
  nothing for the mirror unless they opt in. The Prometheus
  surface remains canonical; this is for operators who already
  aggregate via Mimir / Datadog / Honeycomb and want to skip the
  Prometheus scrape.

- **OIDC Relying-Party stack shipped end to end.**
  `/oidc/callback` (auth-code + PKCE + sealed session cookie)
  plus the helpers + config wiring for
  `/.well-known/openid-configuration` discovery, refresh-token
  rotation, RP-initiated logout at `/oidc/logout`, userinfo →
  `X-Auth-*` trust headers, an optional server-side session store
  (in-memory + KV-backed redb/file/Redis) for targeted revocation.
  See `docs/configuration.md` § OIDC auth.

- **OpenAI Apps SDK / MCP Apps (SEP-1865) compatibility.**
  Gateway-side `_meta.mcpApps` passthrough for tool definitions,
  `params.audit.cause` plumbing on `tools/call`, and a typed
  validator set (`apps.template_declared`, `apps.iframe_sandbox`,
  `apps.csp_present`, `apps.cache_metadata`) usable by sbproxy,
  the enterprise extension, and any CI gate over the
  `sbproxy-plugin` surface.

- **Web Bot Auth full conformance, publish + sign sides.**
  SBproxy now publishes its own JWKS-shaped
  directory at `/.well-known/http-message-signatures-directory`
  and a Signature Agent Card at
  `/.well-known/web-bot-auth/agent-card` (opt in via
  `web_bot_auth_publish` per origin). New
  `sbproxy-middleware::signatures::MessageSignatureSigner`
  primitive signs outbound requests per RFC 9421, round-trips
  through the existing verifier. See `docs/web-bot-auth.md` and
  `examples/web-bot-auth-publish/`.

- **Three previously-undocumented OSS policies now have docs +
  runnable examples:** `object_authz` (BOLA + BFLA with
  enumeration detection), `content_digest` (RFC 9530 request-body
  verification), `agent_budget` (per-agent semantic rate limit).
  See `docs/object-authz.md`, `docs/content-digest.md`,
  `docs/agent-budget.md`.

- **Discoverable FAQ.** `docs/faq.md` covers install, common
  401 causes, OIDC minimal config, log levels, OSS-vs-enterprise
  scope, and pointers into the rest of `docs/`. Wired into
  `docs/README.md` under "Getting started".

- **Explicit SIGINT/SIGTERM handling with a structured shutdown
  event and a 30s default drain budget.** Pingora's
  `Server::run_forever` already trapped SIGTERM and SIGINT, but
  the proxy emitted no operator-facing log line on receipt, so a
  pod eviction or `docker stop` looked the same as a crash in the
  log stream. This change subscribes to Pingora's execution-phase
  broadcast and emits `shutdown_signal_received`,
  `shutdown_grace_period`, and `shutdown_complete` tracing events
  with the resolved grace budget. The Kubernetes operator
  (`sbproxy-k8s-operator`) now installs the same SIGINT/SIGTERM
  handlers via `tokio::signal::ctrl_c` and
  `tokio::signal::unix::signal(SignalKind::terminate())`; before
  this change the operator relied on the orchestrator SIGKILL at
  `terminationGracePeriodSeconds`. The drain budget is the new
  `SBPROXY_SHUTDOWN_GRACE_MS` env var (or `--shutdown-grace-ms`
  CLI flag) which defaults to 30000ms, matching Kubernetes'
  default `terminationGracePeriodSeconds`. The legacy
  `SB_GRACE_TIME` / `--grace-time` (seconds) still works and
  takes precedence when explicitly set; an unset legacy var lets
  the new 30s default apply. Operator exits 0 on a clean drain,
  1 when the grace window is exceeded, so the orchestrator can
  alert. Documented in `docs/manual.md` §3 and
  `docs/kubernetes.md` §Graceful shutdown.

- **Idempotency middleware now engages on AI gateway origins
  (`action: ai_proxy`).** Before this change, the
  RFC 8594 middleware only ran on general HTTP origins
  (`action: proxy`). AI customers using `Idempotency-Key`
  headers for Stripe-style retries were double-billed by the
  upstream provider because the proxy did not replay from cache.
  The fix engages the same primitive in `handle_ai_proxy` after
  the request body is buffered (the AI gateway already buffers
  for the JSON parser, model router, and guardrails) and before
  the upstream call. On a cache hit the gateway writes the
  cached `(status, headers, body)` triple directly to the client
  with `x-sbproxy-idempotency: HIT` and never contacts the
  provider. On a body conflict the gateway returns 409
  `ledger.idempotency_conflict` per the RFC. On a miss the
  gateway forwards, then records the final client-wire bytes.
  Retries receive the same bytes.
  Reuses the same per-request and pool caps shipped on
  `CompiledIdempotency`: `max_request_body_bytes`,
  `max_response_body_bytes`, `max_concurrent_buffers`. The four
  skip markers (`SKIPPED-OVERSIZE-REQUEST`, `SKIPPED-POOL-FULL`,
  `SKIPPED-OVERSIZE-RESPONSE`, `SKIPPED-MULTIPART`) stamp on the
  outgoing response so operators see graceful degradation in
  dashboards. Multipart bodies (audio transcription, image edit /
  variation, file upload) skip caching with `SKIPPED-MULTIPART`
  because the cache primitive stores raw bytes and multipart
  boundaries may be regenerated by clients on retry. Streaming
  (SSE) chat completion responses abandon the cache record on
  oversize because framing-aware capture is out of scope for v1.

- **`proxy_status` and `problem_details` now cover upstream
  failures.** Before this change, `proxy_status.enabled: true`
  stamped the `Proxy-Status` header on proxy-generated errors
  (auth deny, policy deny, default 404) but **not** on upstream
  failures routed through Pingora's `fail_to_proxy` path (connect
  refused, connect timeout, TLS handshake error, mid-stream
  connection loss). The fix wires both blocks into the
  upstream-failure path so dashboards consuming `Proxy-Status` see
  consistent coverage across error sources. The status code +
  RFC 9209 `error` token derive from the Pingora `ErrorType` via
  a new `map_upstream_failure` translator: 504 +
  `connection_timeout` for `ConnectTimedout` /
  `ReadTimedout`; 502 + `connection_refused` for `ConnectRefused`;
  502 + `tls_protocol_error` for TLS errors; 502 +
  `connection_terminated` for mid-stream loss; 502 +
  `http_request_error` as the catch-all. When
  `problem_details.enabled: true` the body is now rendered as
  `application/problem+json` for upstream failures too, with the
  RFC 9209 error token in the `detail` field so both signals share
  the same vocabulary.

- **Idempotency cache check moved to `request_filter`.** Before this
  change, the cache lookup ran in `request_body_filter`, after
  Pingora had already opened the upstream TCP connection. On a cache
  hit the upstream observed one aborted partial request before the
  proxy served the cached response to the client. The check now runs
  before Pingora's upstream-peer phase: cache hits and body
  conflicts write the response from inside `request_filter` and
  return `Ok(true)`, so the upstream is never contacted at all. On
  cache miss the proxy buffers the body (bounded by
  `max_request_body_bytes` from PR #139), then re-injects it via
  `request_body_filter` at end-of-stream so Pingora's normal upstream
  forwarding picks it up. Existing e2e tests now assert the
  upstream-not-contacted invariant; the previous "may observe one
  aborted partial request" caveat has been removed from
  `docs/configuration.md` and the example README.

- **Idempotency middleware: per-request and pool caps.** Three new
  fields on the `idempotency:` block bound memory usage and let the
  middleware gracefully degrade under pressure rather than buffering
  unbounded bodies. `max_request_body_bytes` (default 1 MiB) caps
  the per-request buffer; bodies above the cap skip caching with
  `x-sbproxy-idempotency: SKIPPED-OVERSIZE-REQUEST` stamped on the
  response. `max_response_body_bytes` (default 1 MiB) caps the
  per-response cache buffer; responses above the cap stream through
  uncached. `max_concurrent_buffers` (default 256) is a per-origin
  pool over concurrent buffered requests; pool exhaustion skips the
  cache with `x-sbproxy-idempotency: SKIPPED-POOL-FULL`. Worst-case
  memory is bounded at `max_concurrent_buffers * max_request_body_bytes`
  per origin.

- **RFC 8594 idempotency middleware (`idempotency:`).** Per-origin
  block that engages on POST / PUT / PATCH (configurable via
  `methods:`) when an `Idempotency-Key` header is present. The
  middleware sits ahead of policies in the handler chain, hashes the
  request body, and short-circuits the three branches per the RFC:
  cache hits replay the cached `(status, headers, body)` verbatim
  with `x-sbproxy-idempotency: HIT`; conflicts (same key, different
  body) return 409 with the `ledger.idempotency_conflict` JSON body;
  misses forward to the upstream and capture the response for the
  next retry. Workspace-isolated keys prevent cross-tenant
  collisions. Memory backend (default) is per-origin and per-replica;
  `backend: redis` binds to `proxy.l2_store` at config-compile time
  for cluster-wide replay. Cached replays do not consume rate-limit
  slots. Documented in `docs/configuration.md` and demonstrated by
  `examples/idempotency/`. Known v1 limitation: the cache check
  fires in `request_body_filter`, after Pingora has already opened
  the upstream connection. On a cache hit the upstream observes one
  aborted partial handshake before the proxy serves the cached
  response to the client; future work moves the check earlier so the
  upstream never sees the replay.

- **RFC 9457 problem-details default renderer (`problem_details:`).**
  New per-origin block that opts in to `application/problem+json` for
  proxy-generated errors (authentication denials, policy denials,
  default 404) that are not matched by an authored `error_pages`
  entry. The two blocks compose: per-status custom pages still win
  when authored; `problem_details` catches everything else with a
  structured `type` / `title` / `status` / `detail` / `instance`
  body. `type_base_uri` produces stable per-status `type` URIs;
  `include_detail: false` suppresses the internal error string.
  Documented in `docs/configuration.md` and demonstrated by
  `examples/problem-details/`.

- **Typed `error_pages` config.** The opaque
  `error_pages: Option<serde_json::Value>` field is now typed as
  `Option<Vec<ErrorPageEntry>>`. Public types `ErrorPageEntry`,
  `StatusSpec`, and `ProblemDetailsConfig` live in `sbproxy-config`.
  The authored YAML shape is unchanged: every existing
  `error_pages:` list keeps parsing, including the `status:` single-
  int / `[status]` list shorthand and `template: true` substitution.
  The OpenAPI emitter now walks typed entries to populate
  per-status `responses` keys (the previous code inspected the
  field as an object and silently produced no entries; this is a
  bug fix on top of the migration).

- **AI gateway Realtime WebSocket dispatch (Phase 7, Option C).**
  `GET /v1/realtime` requests with `Upgrade: websocket` against an
  `ai_proxy` origin are now dispatched through the AI gateway
  pipeline:

  - Pre-upgrade gating runs the same surface classification, 501
    capability check (only providers in
    `provider_supports_realtime` are eligible; today: OpenAI),
    per-surface rate limit, and provider selection as the rest of
    the AI surface set.
  - After the gating passes, Pingora forwards bytes between
    client and provider transparently through the upgraded
    connection. The dispatcher does not terminate the WebSocket;
    per-frame guardrails and frame-exact audio metering are
    reserved for a future enterprise terminate-and-relay path so
    every AI gateway feature added to `handle_action` continues
    to apply to realtime through one shared code path.
  - `sbproxy_ai_realtime_sessions_active` (gauge),
    `sbproxy_ai_realtime_session_duration_seconds` (histogram),
    `sbproxy_ai_realtime_audio_seconds_total` (counter), and
    `sbproxy_ai_realtime_frames_forwarded_total` (counter) are
    registered. The OSS dispatch ticks the gauge on session open
    and observes the duration histogram on close. Documented in
    `docs/metrics-stability.md`.
  - At session close, `logging` emits a session-end
    `AiBillingEvent` with `AudioSeconds { seconds }` valued at
    the wall-clock session duration so realtime usage appears on
    the standard billing-event bus alongside chat/image/audio.
  - `RealtimeSessionTracker` (lock-free atomic counters) and
    `audio_seconds_from_frame(bytes, sample_rate, channels)` ship
    in `sbproxy-ai::realtime` for the eventual terminate-and-relay
    path to consume.
  - `docs/ai-gateway.md` documents the new dispatch path with a
    YAML example and the per-surface rate-limit knob.

- **AI gateway OpenAI surface dispatch (Option A).** The `ai_proxy`
  action now routes every OpenAI-compatible surface through a
  single classifier with per-surface observability and gating:

  - New `AiSurface` enum + `classify_surface(method, path)` cover
    chat completions, models, embeddings, assistants and threads
    (full v2 surface), batches, fine-tuning, files, realtime,
    image generation/edits/variations, audio transcription/speech,
    moderations, and reranking. Marked `#[non_exhaustive]` so
    future variants don't break downstream pattern matches.
  - Method coverage extended past GET/POST: DELETE, PUT, PATCH,
    HEAD, and OPTIONS dispatch through `AiClient::forward_with_method`
    without engaging the JSON body-parse pipeline.
  - Multipart bodies (image edits/variations, audio transcription,
    file uploads) byte-forward via `AiClient::forward_bytes` with
    the inbound `Content-Type` preserved. Previously these surfaces
    returned a 400 "invalid JSON body" from the chat-path body parse.
  - Provider capability matrix in `api_routes.rs` corrected:
    Anthropic no longer claims audio/reranking/moderations support,
    Gemini no longer claims moderations. A new
    `provider_supports_surface` matrix gates non-universal surfaces
    with **501 Not Implemented** when no configured provider
    supports the surface.
  - Per-surface observability: new
    `sbproxy_ai_surface_requests_total{surface, method}` counter and
    `sbproxy_ai_surface_request_duration_seconds{surface, method}`
    histogram. Sibling of the existing per-provider metrics so
    dashboards can pivot between surface and provider views.
    Documented in `docs/metrics-stability.md`.
  - Per-surface input guardrails: image generation, audio speech,
    reranking, and moderations bodies now have their input field
    (`prompt`, `input`, `query`, `input`) extracted and run through
    the same guardrail pipeline as chat-style `messages`.
  - Per-surface rate limits: new `per_surface_rate_limits` field
    on the AI handler config, keyed by surface label. 429 fires
    before any upstream call when the cap is hit.
  - Surface-aware billing event: new `AiBillingEvent` carrying
    `AiUsage` with `Tokens`, `Images { count, resolution }`,
    `AudioSeconds`, `Characters`, `RerankUnits`, and `PerCall`
    variants. Every dispatched request emits exactly one event.
    Image generation, audio speech, and reranking emit real cost
    via per-surface pricing tables (`lookup_image_price`,
    `lookup_audio_speech_price`, `lookup_rerank_price`,
    `lookup_audio_transcription_price`). `docs/ai-gateway.md`
    documents the new surface, methods, guardrails, and rate-limit
    knobs.

- **Policy verdict audit bus + Plugin dispatch.**
  Wires the previously-dead `Policy::Plugin` arm in `server.rs` to
  call the trait's `enforce()`, folds the returned `PolicyDecision`
  into the existing chain reducer, and emits a
  `PolicyVerdictEvent` for every decision on a bounded
  `tokio::sync::mpsc` audit bus per
  `docs/adr-policy-audit-binding.md`. The OSS substrate ships an
  in-memory drain stub; enterprise replaces the consumer with a
  NATS-backed audit-chain subscriber. Multi-policy resolution
  rules from `docs/adr-policy-verdict-shape.md` are implemented at
  the chain level: any Deny wins, the first Confirm wins over
  AllowWithHeaders, AllowWithHeaders accumulate, otherwise Allow.
  `Confirm` in OSS routes through the existing AllowWithHeaders
  mechanism with `X-Policy-Confirm: <reason>` stamped on the
  response; an `expires_at` already in the past synthesises a 410
  and an SSRF-blocked `webhook_url` synthesises a 502 at decision
  time. New metrics:
  `sbproxy_policy_audit_events_total{verdict, surface, policy_id}`,
  `sbproxy_policy_audit_events_dropped_total{tenant}`,
  `sbproxy_policy_decision_duration_seconds{surface}`. New Grafana
  dashboard `sbproxy-policy-verdicts` covers the surface.
  ([crates/sbproxy-observe/src/events.rs],
  [crates/sbproxy-observe/src/metrics.rs],
  [crates/sbproxy-core/src/policy_bus.rs],
  [crates/sbproxy-core/src/policy_dispatch.rs],
  [crates/sbproxy-core/src/server.rs],
  [crates/sbproxy-plugin/src/traits.rs],
  [dashboards/grafana/sbproxy-policy-verdicts.json])

- **Synthetic-transaction `/readyz` probe.** Optional
  background driver that fires an in-process request through the
  compiled handler chain on a fixed cadence and reports the verdict as
  a `synthetic_pipeline` component on `/readyz`. Disabled by default;
  opt in via `proxy.synthetic_probe.enabled: true` and define an origin
  for the configured sentinel hostname (default `__synthetic.local`)
  pointing at a non-network action (`static`, `mock`, `echo`, `noop`).
  Failures bump the new
  `sbproxy_synthetic_probe_failures_total{reason}` counter so they do
  not pollute real-traffic error metrics.
  ([crates/sbproxy-config/src/types.rs],
  [crates/sbproxy-core/src/synthetic.rs],
  [crates/sbproxy-observe/src/synthetic.rs],
  [crates/sbproxy-observe/src/metrics.rs],
  [e2e/tests/synthetic_probe.rs])

- **`GET /admin/drift` config drift endpoint.** Returns
  whether the on-disk config file has diverged from what the running
  proxy has loaded, without triggering a reload. Compares a
  content-hash baseline captured at startup (and refreshed on every
  `/admin/reload`) against a fresh hash of the current file. K8s
  operators and dashboards scrape this so they can flag an edited
  config that has not been hot-reloaded yet. Documented in
  `docs/configuration.md` § Admin fields.
  ([crates/sbproxy-core/src/admin.rs],
  [crates/sbproxy-core/src/server.rs],
  [docs/configuration.md])

- **Deterministic clock-skew testing hooks.** `ClockSkewMonitor` now
  accepts an injected clock source for tests while production continues
  to use the system clock.
  ([crates/sbproxy-observe/src/clock_skew.rs])

- **Operator runbook hooks and fast-track ADR template.** Added a
  dashboard-oriented operator runbook, linked all Grafana panels to the
  relevant triage sections, and added a fast-track ADR amendment
  template plus OSS threat-model refresh checklist.
  ([docs/operator-runbook.md], [docs/adr-fast-track-amendment.md],
  [docs/threat-model.md], [dashboards/grafana/])

- **Live reverse-DNS resolver for agent verification.** `SystemResolver`
  now uses `hickory-resolver` for PTR and forward-confirmation lookups,
  replacing the previous typed PTR stub.
  ([crates/sbproxy-security/src/agent_verify.rs])

- **Multi-window SLO burn-rate replay harness.** `sbproxy-observe`
  now includes a burn-rate evaluator and `AlertSnapshot` replay helper
  for substrate availability and latency alert taxonomy tests.
  ([crates/sbproxy-observe/src/alerting/burn_rate.rs],
  [e2e/tests/slo_burn_rate.rs])

- **Vault-style quote-token seed references.** `ai_crawl_control.quote_token.secret_ref`
  now accepts `secret:` references resolved through `sbproxy-vault`
  with the existing environment fallback, in addition to the older
  `secret_ref.env` and inline `seed_hex` paths.
  ([crates/sbproxy-modules/src/policy/ai_crawl.rs])

- **Operator first-24-hours quickstart.** Added a concise
  `docs/quickstart-operator.md` covering deploy, `/readyz`, metrics,
  Grafana, logs, and rollback, linked from the README and Kubernetes
  docs.
  ([docs/quickstart-operator.md])

- **Hostname cardinality override for metrics.** `proxy.metrics.cardinality.hostname_cap`
  can lower the `hostname` label budget independently from the default
  per-label cap, enabling deterministic overflow tests and tighter
  multi-tenant Prometheus budgets.
  ([crates/sbproxy-config/src/types.rs],
  [crates/sbproxy-observe/src/cardinality.rs])

- **`release-fast` build profile for CI images.** Docker-based CI and
  local kind smoke-test builds can now use `CARGO_PROFILE=release-fast`
  to skip fat LTO and use more codegen units, cutting link memory/time
  while leaving production release artifacts on the existing `release`
  profile.
  ([Cargo.toml], [Dockerfile.ci], [Dockerfile.cloudbuild])

- **Reproducible build probe workflow.** CI now has an informational
  double-build lane that builds the release binary twice on independent
  GitHub-hosted runners, uploads each binary and SHA-256, and publishes
  a comparison report without yet treating non-identical output as a
  failure.
  ([.github/workflows/reproducible-build.yml], [SUPPLY-CHAIN.md])

- **Phase 2: CEL `features[...]` namespace.** Per-request
  flags parsed from the `x-sb-flags` header and `?_sb.<key>` query
  prefix are now exposed to CEL expressions. Built-in flags surface
  as bools (`features.debug`, `features.trace`,
  `features["no-cache"]`, `features.any_set`); free-form `k=v` extras
  surface as strings (`features["env"]`). Wired into the rate-limit
  CEL evaluator and `ExpressionPolicy::evaluate_with_views`.
  ([crates/sbproxy-extension/src/cel/context.rs])

- **`SB_WORKER_THREADS` env var.** Positive integer overrides the
  auto-detected Pingora worker thread count
  (`std::thread::available_parallelism()`). Useful for benchmarking
  with a fixed worker count or capping the pool below a cgroup quota.
  ([crates/sbproxy-core/src/server.rs])

- **`/live`, `/livez`, `/ready`, `/healthz`, and rich `/health`
  admin endpoints.**
  `/livez` returns `{"alive":true}` on every call and never 503s, so
  K8s liveness probes don't trip on transient readiness failures.
  `/live` is a bare alias. `/ready` is an alias for `/readyz`.
  `/healthz` stays a fixed liveness body, while `/health` now returns
  version, build hash, timestamp, uptime, and readiness checks for
  dashboards / SIEM ingestion. Existing `/readyz` behavior unchanged.
  ([crates/sbproxy-observe/src/health.rs],
  [crates/sbproxy-core/src/admin.rs])

- **`--request-log-level` and `SB_REQUEST_LOG_LEVEL`.** Operators can
  now tune request/access logging independently from application logs.
  The setting appends an `access_log=<level>` target directive to the
  effective `tracing-subscriber` filter while preserving the existing
  per-target `RUST_LOG` escape hatch.
  ([crates/sbproxy/src/main.rs])

- **Access-log forced emission and file output.** `access_log` now
  supports `slow_request_threshold_ms` and `always_log_errors` so slow
  requests and 5xxs bypass sampling after status/method filters match.
  It also supports `output: { type: file, path, max_size_mb,
  max_backups, compress }` for direct JSON-line access-log files with
  size-based rotation and optional gzip compression of rotated files.
  ([crates/sbproxy-config/src/types.rs],
  [crates/sbproxy-core/src/server.rs],
  [crates/sbproxy-observe/src/access_log.rs])

- **OCSP stapling for the manual fallback cert.** `OcspStapler`
  (which previously existed but was unwired) now does an immediate
  fetch on startup, refreshes every 12 hours, and pushes the bytes
  into `CertResolver::update_fallback_ocsp` so subsequent rustls
  handshakes staple the response on the wire. No-op when no manual
  cert is configured or when the cert lacks an AIA extension.
  ([crates/sbproxy-tls/src/ocsp.rs],
  [crates/sbproxy-tls/src/cert_resolver.rs])

- **Readiness synthetic probe primitive.** `sbproxy-observe` now ships a
  `SyntheticProbe` type so startup or test wiring can register an
  in-process readiness probe that exercises a caller-provided path and
  reports through the same `/readyz` component model as built-in probes.
  ([crates/sbproxy-observe/src/health.rs])

### Removed

- **`sbproxy_ai::IdempotencyCache`.** The OSS AI gateway never wired
  this cache; it was publicly re-exported but had zero callers in the
  workspace. The new `idempotency:` block on general HTTP origins
  (above) supersedes it. AI gateway integration is a follow-up tracked
  in `docs/missing.md`. Plugin authors that imported the removed
  type can switch to
  `sbproxy_middleware::idempotency::{IdempotencyCache,
  InMemoryIdempotencyCache, KvIdempotencyCache}` which carries the
  richer surface (workspace isolation, body-hash conflict detection,
  conflict body builder).

### Changed

- **mTLS now wired on the ACME path.** Previously, an operator who
  configured `mtls:` alongside `acme:` got plain TLS until they
  noticed clients reaching the upstream without the expected cert
  headers. The ACME branch now mirrors the manual-cert branch:
  builds `TlsSettings` with the configured `ClientCertVerifier` and
  falls back to plain TLS only when mTLS setup itself fails.
  ([crates/sbproxy-core/src/server.rs])

- **Examples and Kubernetes smoke checks are local-only.** The
  Docker-backed examples smoke lane and kind-based Kubernetes operator
  smoke lane no longer run automatically on pull requests. They remain
  available as `make examples-smoke` and `make k8s-operator-smoke` for
  explicit local / release validation.
  ([Makefile], [docs/kubernetes.md])

- **Reload drain state is now one coherent atomic snapshot.** The
  drain flag and active request count are packed into one `AtomicU64`,
  so `is_draining()` no longer combines two independent relaxed loads.
  Added loom coverage for the last-request-finish interleaving.
  ([crates/sbproxy-core/src/reload.rs])

- **Optional readiness dependencies no longer fail `/readyz` by
  default.** The default admin health registry now registers absent
  ledger and bot-auth-directory probes as `not_configured`, matching the
  existing future-wave stubs and keeping `/readyz` green when those
  optional services are not wired in a deployment.
  ([crates/sbproxy-observe/src/health.rs],
  [crates/sbproxy-core/src/admin.rs])

- **`docs/manual.md` rewrites** matching what actually ships:
  - §6 Health checks: `/livez`, `/readyz`, `/healthz`, and rich
    `/health` semantics, replacing the old per-endpoint URL fork
    diagram and stale `/health` alias wording.
  - §10 Feature flags: CEL accessor table, kill-switch note, and
    a "planned, not yet wired" note for Lua / JS / WASM features
    namespaces and workspace-level pub/sub flags.
  - §3 CPU detection: documents the new `SB_WORKER_THREADS` knob.
  - §13 env-var table: adds `SB_WORKER_THREADS` and
    `SB_DISABLE_SB_FLAGS`; later updates add
    `SB_REQUEST_LOG_LEVEL` and access-log file/forced-emit examples.

### Fixed

- **CAP `sub` binding only fires for a genuinely resolved agent.** The
  CAP verifier binds a token's `sub` to the request's resolved agent id
  (rejecting a mismatch with `403`). Because the agent-class resolver is
  installed with the built-in catalog by default and always stamps
  *some* id (falling through to the `human` sentinel when no signal
  matches), the binding would have rejected every CAP token whose `sub`
  was not literally `"human"`, even on origins that never configured
  agent classes. The binding now skips the resolver's fallback / `human`
  verdict and engages only when the resolver actually identified an
  agent, so an unauthenticated caller falls through to the normal CAP
  validation path. Set `cap.require_agent_binding: true` to fail closed
  when no agent is resolved.

- **Virtual-key model allow/block lists are now enforced.** A virtual
  key (or `ai_provider` credential) with `models.allow` / `models.block`
  declared its scope but the AI dispatch path never checked it, so a key
  confined to a subset of the gateway's models could still call any
  model the gateway served. The matched key's allow/block lists are now
  enforced against the effective model (after any `route_to_model`
  rewrite): a request for a disallowed model is rejected with `403`
  before any upstream call, the block-list taking precedence over the
  allow-list. Keys with no `models.allow` are unaffected. See
  `examples/ai-virtual-keys/`.

- **Licensing-projection wire formats now match the canonical specs [BREAKING].** Two projection emitters were producing
  document shapes that didn't match their cited specifications.
  `/licenses.xml` previously declared the namespace
  `https://rsl.ai/spec/1.0` and emitted a flat
  `<rsl><license urn=...>...</license></rsl>` document. The canonical
  RSL Collective spec at <https://rslstandard.org/rsl> uses the
  namespace `https://rslstandard.org/rsl` and a nested
  `<rsl><content url="..."><license>...</license></content></rsl>`
  shape; the `<content>` `url` attribute is the canonical wildcard
  `https://<hostname>/*` for the origin-wide license. `/.well-known/tdmrep.json`
  previously wrapped its policies in a `{"version", "generated", "policies": [...]}`
  envelope; the W3C TDMRep CG-FINAL spec mandates a bare JSON array
  at the document root with `location`, `tdm-reservation`
  (integer 0 or 1), and `tdm-policy` (URL of the policy document)
  fields per entry. Both emitters now produce the canonical shapes.
  Operators consuming `/licenses.xml` or `/.well-known/tdmrep.json`
  programmatically must update their parsers to the new shapes; the
  in-process JSON envelope and the response middleware that stamps
  `TDM-Reservation: 1` and the URN-bearing `license` field are
  unaffected. Conformance is asserted by the active structure-shape
  tests; the earlier schema-validation tests were removed because
  neither standard publishes a machine-readable schema to validate
  against (RSL 1.0 is prose-only; W3C TDMRep ships no JSON Schema).
  ([crates/sbproxy-modules/src/projections/licenses.rs],
  [crates/sbproxy-modules/src/projections/tdmrep.rs],
  [e2e/tests/rsl_licenses_projection_e2e.rs],
  [e2e/tests/tdmrep_projection_e2e.rs])

- **Build under prometheus 0.14 type inference.** Sites in
  `sbproxy-observe::metrics` and `sbproxy-core::server` that passed
  heterogeneous `&[&String, &str]` arrays to
  `prometheus::with_label_values` no longer compile on prometheus
  0.14 because Rust unifies the array element type to `&String` and
  rejects bare `&str` literals. Coerced all such call sites to
  uniform `&[&str]` via `.as_str()` so the workspace builds clean
  again. No behavioral change.
  ([crates/sbproxy-observe/src/metrics.rs],
  [crates/sbproxy-core/src/server.rs])

- **WASM extension docs corrected.** `CLAUDE.md` previously labeled the
  WASM surface as "WASM stub" while marketing docs claimed
  production-grade support; the runtime is real
  (`wasmtime` + WASI preview-1 with sandboxed memory and CPU caps,
  stderr capture, no FS or network). `llms.txt` also incorrectly
  claimed "WASI networking with host allowlist" but `allowed_hosts` is
  parsed-but-inert until WASI sockets land. CLAUDE.md and llms.txt now
  match the shipped surface.
  ([CLAUDE.md], [llms.txt],
  [crates/sbproxy-extension/src/wasm/mod.rs])

- **E2E proxy startup flake under CPU contention.** The e2e
  `ProxyHarness` keeps its HTTP-level readiness probe, but now gives
  release/debug proxy boots a 10-second window instead of 5 seconds so
  tests like `action_graphql` do not fail spuriously while cargo is
  competing for CPU.
  ([e2e/src/lib.rs])

- **Docs CI Rust snippet failures.** Workspace-dependent documentation
  examples that cannot compile as standalone `rust-script` programs are
  now tagged `rust,no_run`, keeping docs-ci focused on executable
  snippets instead of illustrative API fragments.
  ([docs/architecture.md], [docs/audit-log.md], [docs/cache-reserve.md])

- **Unsafe-code drift guardrails.** Crates that do not need unsafe now
  forbid it at the crate root, while `sbproxy-vault` explicitly allows
  its narrowly-scoped volatile zeroization unsafe with an inline
  justification.
  ([crates/sbproxy-*/src/lib.rs])

- **Outbound webhook delivery identity headers.** Signed customer
  webhooks now include `Sbproxy-Subscription-Id`,
  `Sbproxy-Delivery-Id`, and 1-based `Sbproxy-Attempt` headers, with a
  fresh delivery ULID on every retry attempt.
  ([crates/sbproxy-observe/src/notify.rs])

- **AI client retry resilience.** Provider retries now honor
  `provider.max_retries` as same-provider retry attempts with
  bounded jittered exponential backoff before recording provider
  failure and moving to the next eligible provider.
  ([crates/sbproxy-ai/src/client.rs])

- **Dynamic Web Bot Auth directory dispatch.** The main request auth
  path now invokes `BotAuthProvider::verify_async` when a configured
  hosted directory and `Signature-Agent` header are present, so dynamic
  directory failures surface distinctly instead of falling through the
  static inline-agent verifier.
  ([crates/sbproxy-core/src/server.rs])

- **ACME/Pebble order polling.** Certificate issuance now polls the
  authorization to `valid` after responding to the HTTP-01 challenge
  before polling the order to `ready`, matching Pebble's stricter state
  progression. Finalization also parses the order returned by the
  finalize response and falls back to polling the original order URL,
  avoiding accidental POST-as-GET polling of the finalize URL when
  `Location` is absent.
  ([crates/sbproxy-tls/src/acme.rs])

- **JWKS unknown-`kid` key rotation.** JWTs that reference an unseen
  `kid` now trigger one rate-limited JWKS refetch before failing
  closed, with a Prometheus counter for success / failure /
  rate-limited outcomes. This avoids requiring operator intervention
  for routine IdP key rotation.
  ([crates/sbproxy-modules/src/auth/jwks.rs],
  [crates/sbproxy-modules/src/auth/mod.rs],
  [crates/sbproxy-observe/src/metrics.rs])

- **Rate-limit LRU pollution bypass.** Per-key local token buckets now
  preserve deny state in a bounded cold tier after hot LRU eviction, so
  a spray of attacker keys cannot reset an already-throttled
  legitimate client.
  ([crates/sbproxy-modules/src/policy/mod.rs])

### Open follow-ups

Tracked in Linear, not in this changeset:

- the upstream issue full configurable
  synthetic transaction through the live request pipeline. The
  `SyntheticProbe` readiness primitive has landed; config and pipeline
  execution remain.
- Phase 2.5: Lua / JS / WASM `features` namespace, plus
  workspace-level flags via messenger pub/sub
- the upstream issue remaining
  rate-limiter proptest coverage. The reload-drain loom portion has
  landed.

## [1.0.1] - 2026-05-04

Patch release. No runtime behavior changes.

### Fixed

- **Container image publish**: the `release.yml` workflow's docker
  prepare step extracted the flat-layout tarballs into `/tmp/`
  directly, which tripped a sticky-bit `Cannot utime` error on the
  archive's `./` entry and caused `ghcr.io/soapbucket/sbproxy:1.0.0`
  to never publish. Each platform tarball now extracts to a per-arch
  staging dir before the binary moves into the docker context.

## [1.0.0] - 2026-05-03

First Rust release of SBproxy on this repository.

### What changed

- **Implementation**: SBproxy is now written in Rust on Cloudflare's
  Pingora. The Go implementation that previously occupied this repo
  (`v0.1.0` through `v0.1.2`) has moved to
  [`soapbucket/sbproxy-go`](https://github.com/soapbucket/sbproxy-go),
  which is archived and read-only; its `v0.1.2` release tag preserves
  the final historical release.
- **Data plane**: routing, AI gateway, MCP gateway, guardrails, security
  policies, and scripting (CEL, Lua, JavaScript, WebAssembly) all ship
  open source in this release. See [`docs/architecture.md`](docs/architecture.md)
  for the request pipeline shape.
- **Editions**: this release originally described a separate paid tier
  layered on the open-source data plane. That split no longer exists.
  Every feature ships in one Apache-2.0 binary; the `1.2.0` entry
  records the relicensing that got there.

### Upgrading from v0.1.x (Go)

The internal config schema (`schema-v1`) is supported by both the Go
`v0.1.x` line and this Rust `v1.x` line, so existing `sb.yml` files
should compile unchanged. See [`MIGRATION.md`](MIGRATION.md) for the
full upgrade path.
