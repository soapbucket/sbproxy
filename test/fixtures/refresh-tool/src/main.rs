//! Fixture refresh tool (Q2.13).
//!
//! Regenerates the signed registry feed, KYA token, and Bot Auth
//! directory JWS samples used by Wave 1 and Wave 2 e2e tests. Reads
//! its keypair seeds from `test/fixtures/wave2/registry/keys.json`
//! (and the parallel files for the Bot Auth directory) so the
//! outputs are deterministic byte-for-byte across runs. Running
//! the tool twice MUST produce a clean `git diff --exit-code`.
//!
//! When the production-key contract rotates (e.g. the
//! `feed.sbproxy.dev` Ed25519 signing key advances on its 90-day
//! cadence per `adr-agent-registry-feed.md`), the developer:
//!
//! 1. Updates the relevant `keys.json` with the new seed.
//! 2. Runs `bash test/fixtures/refresh.sh`.
//! 3. Commits the diff alongside the production-key rotation PR.
//!
//! CI runs the script in a verification job and asserts
//! `git diff --exit-code test/fixtures/`. If a developer changes a
//! key without regenerating, the diff surfaces and the PR is held.
//!
//! See also `.github/workflows/fixture-freshness.yml`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

// --- Deterministic clock ---

/// All fixture timestamps freeze at this UTC moment so signatures
/// stay byte-identical across regen runs. Coordinated with the
/// `valid_from` / `valid_until` windows below.
const FIXED_NOW_RFC3339: &str = "2026-05-01T00:00:00.000Z";
const FIXED_VALID_UNTIL_RFC3339: &str = "2026-08-01T00:00:00.000Z";

// --- Paths ---

/// Returns the absolute path to the workspace root (the parent of
/// the `test/fixtures/refresh-tool/` directory the binary lives in).
fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // CARGO_MANIFEST_DIR resolves to .../test/fixtures/refresh-tool;
    // pop three components to get the workspace root.
    manifest
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn main() -> Result<()> {
    let root = workspace_root();
    eprintln!("workspace root: {}", root.display());

    refresh_registry_feed(&root).context("registry feed")?;
    refresh_kya_token(&root).context("kya token")?;
    refresh_bot_auth_directory(&root).context("bot-auth directory")?;

    eprintln!("ok: all fixtures regenerated");
    Ok(())
}

// --- Registry feed (G2.1) ---

/// Regenerate the Wave 2 agent-registry feed at
/// `e2e/fixtures/wave2/registry/feed-good.json`. Signs the body with
/// the Ed25519 key seeded from
/// `test/fixtures/wave2/registry/keys.json`.
///
/// The wire format follows `adr-agent-registry-feed.md` § "Top-level
/// feed shape" and § "Signing": Ed25519 over JCS-canonicalised body
/// with `signature.value` cleared. We use a tiny in-tree JCS
/// helper (`jcs_canonicalize`) because the spec is small and the
/// only Rust crate that implements it is unmaintained.
fn refresh_registry_feed(root: &Path) -> Result<()> {
    let keys_path = root.join("test/fixtures/wave2/registry/keys.json");
    let signing_key = load_signing_key(&keys_path, "feed_signing_seed")?;

    // Two entries: one for the OSS-side bot-auth e2e (GPTBot) and
    // one for the cross-pillar wave2_billing_audit. Adding new
    // entries is fine; just keep them ordered alphabetically by
    // `agent_id` so JCS canonicalisation produces a stable order.
    let body = json!({
        "format_version": 1,
        "generated_at":   FIXED_NOW_RFC3339,
        "expires_at":     FIXED_VALID_UNTIL_RFC3339,
        "issuer":         "feed.sbproxy.dev",
        "entries": [
            {
                "agent_id":  "anthropic-claudebot",
                "vendor":    "Anthropic",
                "purpose":   "training",
                "expected_user_agents":         ["(?i)\\bClaudeBot/\\d"],
                "expected_reverse_dns_suffixes": [".claudebot.anthropic.com"],
                "expected_keyids":              [],
                "reputation_score":         92,
                "robots_compliance_score":  99,
                "flags":                    [],
                "deprecated":               false,
                "aliases":                  [],
                "contact_url":              "https://docs.anthropic.com/claudebot"
            },
            {
                "agent_id":  "openai-gptbot",
                "vendor":    "OpenAI",
                "purpose":   "training",
                "expected_user_agents":         ["(?i)\\bGPTBot/\\d"],
                "expected_reverse_dns_suffixes": [".gptbot.openai.com"],
                "expected_keyids":              [],
                "reputation_score":         87,
                "robots_compliance_score":  98,
                "flags":                    ["throttled"],
                "deprecated":               false,
                "aliases":                  [],
                "contact_url":              "https://platform.openai.com/docs/gptbot"
            }
        ],
        "signature": {
            "alg":   "ed25519",
            "kid":   "sb-feed-2026-q2",
            "value": ""
        }
    });

    // --- Sign per ADR § "Signing" ---
    let signing_input = jcs_canonicalize(&body);
    let signature = signing_key.sign(signing_input.as_bytes());
    let mut signed = body.clone();
    signed["signature"]["value"] = Value::String(B64.encode(signature.to_bytes()));

    // --- Write the feed ---
    let out = root.join("e2e/fixtures/wave2/registry/feed-good.json");
    let mut bytes = serde_json::to_vec_pretty(&signed)?;
    bytes.push(b'\n');
    write_atomic(&out, &bytes)?;
    eprintln!("  wrote {}", out.display());

    // --- Write the public-key directory (consumer side) ---
    let public_key = signing_key.verifying_key();
    let directory = json!({
        "format_version": 1,
        "generated_at":   FIXED_NOW_RFC3339,
        "active": {
            "kid":         "sb-feed-2026-q2",
            "alg":         "ed25519",
            "public_key":  B64.encode(public_key.to_bytes()),
            "valid_from":  FIXED_NOW_RFC3339,
            "valid_until": FIXED_VALID_UNTIL_RFC3339,
        },
        "grace":   [],
        "revoked": []
    });
    let dir_out = root.join("e2e/fixtures/wave2/registry/keys-good.json");
    let mut dir_bytes = serde_json::to_vec_pretty(&directory)?;
    dir_bytes.push(b'\n');
    write_atomic(&dir_out, &dir_bytes)?;
    eprintln!("  wrote {}", dir_out.display());

    Ok(())
}

// --- KYA token (Wave 5 placeholder) ---

/// KYA tokens (Know-Your-Agent, Wave 5) are not implemented in
/// Wave 2; this stub writes a deterministic placeholder so the
/// fixture path exists and CI's freshness check has a stable
/// artifact. When Wave 5 lands, this function gets the real KYA
/// token shape (JWS over claims per the Wave 5 ADR).
fn refresh_kya_token(root: &Path) -> Result<()> {
    let placeholder = b"# Wave 5 KYA token placeholder\n# Real format lands with G5.x; see docs/AIGOVERNANCE-BUILD.md\n";
    let out = root.join("e2e/fixtures/wave2/kya/sample.kya");
    write_atomic(&out, placeholder)?;
    eprintln!("  wrote {}", out.display());
    Ok(())
}

// --- Bot Auth directory (A1.3) ---

/// Regenerate the JWS sample bodies under
/// `e2e/fixtures/wave1/bot_auth_directory/`. Used by Q1.4 and the
/// Q2.13 freshness check; structure follows the JWKS-shaped
/// directory body from `adr-bot-auth-directory.md`.
///
/// The directory itself is signed (per ADR § "Directory
/// self-signature") with one of the keys it publishes. We use the
/// same Ed25519 key throughout for determinism; in production the
/// keys rotate per the rules in the ADR.
fn refresh_bot_auth_directory(root: &Path) -> Result<()> {
    let keys_path = root.join("test/fixtures/wave1/bot_auth_directory/keys.json");
    let signing_key = load_signing_key(&keys_path, "directory_signing_seed")?;
    let public_key = signing_key.verifying_key();
    let public_b64url = B64URL.encode(public_key.to_bytes());

    // Thumbprint per RFC 7638 § 3 for OKP keys: SHA-256 over the
    // canonicalised JSON `{ "crv":"Ed25519","kty":"OKP","x":"<x>" }`.
    let thumbprint_input = format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
        public_b64url
    );
    let kid = B64URL.encode(Sha256::digest(thumbprint_input.as_bytes()));

    let directory = json!({
        "keys": [
            {
                "kty":         "OKP",
                "crv":         "Ed25519",
                "x":           public_b64url,
                "kid":         kid,
                "alg":         "EdDSA",
                "use":         "sig",
                "agent":       "openai-gptbot",
                "valid_from":  FIXED_NOW_RFC3339,
                "valid_until": FIXED_VALID_UNTIL_RFC3339,
            }
        ]
    });

    let body_bytes = jcs_canonicalize(&directory);
    let signature = signing_key.sign(body_bytes.as_bytes());

    // RFC 9421 self-signature header captured alongside the body so
    // the test harness can replay both halves. The proxy reads the
    // body off the wire and the `Signature` / `Signature-Input`
    // headers off the response; the fixture pack mirrors that.
    let directory_out = root.join("e2e/fixtures/wave1/bot_auth_directory/directory-good.json");
    let mut bytes = body_bytes.into_bytes();
    bytes.push(b'\n');
    write_atomic(&directory_out, &bytes)?;
    eprintln!("  wrote {}", directory_out.display());

    let header_out = root.join("e2e/fixtures/wave1/bot_auth_directory/directory-good.headers");
    let header_text = format!(
        "Signature-Input: sig1=(\"@signature-params\");keyid=\"{}\";alg=\"ed25519\"\nSignature: sig1=:{}:\n",
        kid,
        B64.encode(signature.to_bytes())
    );
    write_atomic(&header_out, header_text.as_bytes())?;
    eprintln!("  wrote {}", header_out.display());

    // --- Negative-case fixture: directory signed with wrong key ---
    let bad_key = SigningKey::from_bytes(&[0x99u8; 32]);
    let bad_sig = bad_key.sign(jcs_canonicalize(&directory).as_bytes());
    let bad_header = format!(
        "Signature-Input: sig1=(\"@signature-params\");keyid=\"{}\";alg=\"ed25519\"\nSignature: sig1=:{}:\n",
        kid,
        B64.encode(bad_sig.to_bytes())
    );
    let bad_out = root.join("e2e/fixtures/wave1/bot_auth_directory/directory-bad-signature.headers");
    write_atomic(&bad_out, bad_header.as_bytes())?;
    eprintln!("  wrote {}", bad_out.display());

    Ok(())
}

// --- Helpers ---

/// Load an Ed25519 signing key from a JSON file shaped like
/// `{ "<seed_field>": "<hex-encoded-32-byte-seed>" }`. The seed
/// fields are committed in `test/fixtures/.../keys.json`; the same
/// seed deterministically produces the same keypair, which is
/// what makes the regen output byte-identical.
///
/// Test seeds are NOT real production keys; they are documented
/// as such in `test/fixtures/README.md`.
fn load_signing_key(path: &Path, field: &str) -> Result<SigningKey> {
    let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let v: Value = serde_json::from_slice(&raw)?;
    let seed_hex = v
        .get(field)
        .and_then(|s| s.as_str())
        .with_context(|| format!("missing field {field} in {}", path.display()))?;
    let seed = hex::decode(seed_hex)?;
    if seed.len() != 32 {
        anyhow::bail!("seed must be 32 bytes; got {}", seed.len());
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&seed);
    Ok(SigningKey::from_bytes(&buf))
}

/// Atomically write `bytes` to `path`. Creates parent directories
/// if missing. Idempotent: a re-write with identical content
/// preserves the file's bytes (and crucially produces no diff).
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Idempotency check: skip the write entirely if the bytes
    // match. This keeps mtimes stable on no-op runs which is
    // friendlier to incremental rebuild systems.
    if let Ok(existing) = std::fs::read(path) {
        if existing == bytes {
            return Ok(());
        }
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// JCS (RFC 8785) canonical JSON. Just enough for the field set we
/// emit: no NaN/Infinity, no exotic Unicode, all keys are ASCII.
///
/// Implementation: keys sorted lexicographically, no whitespace,
/// strings re-encoded with the JSON spec's minimum escaping. The
/// `serde_json::Value::to_string` impl already handles strings
/// correctly; we walk the tree and sort objects ourselves.
fn jcs_canonicalize(value: &Value) -> String {
    let mut out = String::new();
    canon_into(value, &mut out);
    out
}

fn canon_into(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            // JCS pins JSON Number serialisation to ECMA-404; we sidestep
            // float edge cases by only emitting integers from the fixture
            // generator. If a float lands here, fall back to serde_json's
            // default which is ECMA-404 compliant for finite values.
            out.push_str(&n.to_string());
        }
        Value::String(s) => {
            // serde_json::to_string handles JSON escaping correctly.
            let escaped = serde_json::to_string(s).expect("string encode");
            out.push_str(&escaped);
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canon_into(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // JCS § 3.2.3: sort keys lexicographically by Unicode code
            // point. ASCII keys, which is all we emit, behave identically
            // under both byte-wise and code-point ordering.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let escaped = serde_json::to_string(k).expect("key encode");
                out.push_str(&escaped);
                out.push(':');
                canon_into(map.get(*k).expect("present"), out);
            }
            out.push('}');
        }
    }
}
