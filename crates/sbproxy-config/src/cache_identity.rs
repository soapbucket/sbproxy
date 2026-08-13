//! Per-origin cache config identity (WOR-2407).
//!
//! A shared response-cache store (Redis, memcached, a file store on a
//! shared volume) is one flat key space across every node in a mesh.
//! The cache key names the request, so without something naming the
//! config as well, a node mid-rolling-change reads entries another node
//! wrote under a config that no longer applies. Whichever node writes
//! first decides what the whole fleet serves until the TTL expires.
//!
//! [`origin_cache_fingerprint`] is that name: a digest over the part of
//! one origin's compiled config that decides **what the upstream
//! returns for a given cache key**. It becomes the last segment of the
//! key, so two revisions partition instead of colliding. Neither
//! refuses to serve; each simply keeps its own entries, and the older
//! set ages out on its existing TTLs.
//!
//! # What the projection covers, and why it is narrow
//!
//! The obvious implementation is a hash of the whole config document,
//! and it is wrong. Every unrelated edit, a log level or a second
//! origin, would rotate every key in the fleet at once: a cold cache, a
//! load spike at the origin, and with Redis or a file store the old
//! entries holding space until they expire. So this is a projection of
//! one origin, not a document digest.
//!
//! The boundary comes from where the cache actually sits. The stored
//! representation is the **raw upstream** one: `response_filter`
//! captures upstream status and headers and buffers the upstream body
//! before any response transform runs, and a hit replays those stored
//! bytes straight to the client. So response-side config cannot change
//! what is in an entry, and request-side config can.
//!
//! Covered, because each one changes what the upstream returns:
//!
//! * the action, which carries the upstream target and, on an AI
//!   origin, the provider and model
//! * auth, which decides the identity the upstream answers
//! * request modifiers, transforms, Proxy-Wasm filters, and
//!   `on_request` scripts, all of which rewrite what is sent
//! * forward rules and the fallback origin, which reroute
//! * variables, which those rewrites interpolate
//! * outbound credentials and Web Bot Auth signing, which change who
//!   the upstream thinks is asking
//! * attached extension bundles, which can carry request-side hooks
//! * the `response_cache` block itself, including
//!   [`ResponseCacheConfig::epoch`]
//!
//! Deliberately not covered: response modifiers, CORS, HSTS,
//! compression, sessions, error pages, observability, timeouts, and
//! policies. The first group runs downstream of the cache write. The
//! last gates whether a request proceeds at all without changing the
//! representation it would get.
//!
//! Within an origin the projection errs toward covering. Rotating a
//! credential moves the fingerprint even though the response is
//! probably identical, which costs one cold start for one origin.
//! Missing a field that mattered costs correctness, and there is no
//! symmetric argument for accepting that.

use compact_str::CompactString;
use sha2::{Digest, Sha256};

use crate::snapshot::CompiledOrigin;

/// Domain label separating this digest from every other SHA-256 in the
/// workspace.
///
/// Bump the version suffix to retire the keyspace rather than
/// reinterpret it: a change to what the projection covers must not let
/// a new build open an entry the old one wrote under the same
/// fingerprint.
const CACHE_COMPAT_DOMAIN: &[u8] = b"sbproxy-respcache-compat-v1";

/// Hex chars of the digest that reach the cache key.
///
/// 16 hex chars is 64 bits. The fingerprint only has to separate the
/// handful of configs one deployment runs during a rollout, not resist
/// a search, and the key is length-bounded for the sake of memcached's
/// 250-byte limit.
const FINGERPRINT_HEX_LEN: usize = 16;

/// Compute the cache-compatibility fingerprint for one compiled origin.
///
/// Pure function of the origin's config. Any nondeterminism here would
/// partition a single node from its own entries across a restart, so
/// every JSON value goes through RFC 8785 canonicalization rather than
/// `serde_json`'s map order.
///
/// Called once per origin at compile time. Nothing on the request path
/// recomputes it.
pub fn origin_cache_fingerprint(origin: &CompiledOrigin) -> CompactString {
    let mut hasher = Sha256::new();
    hasher.update(CACHE_COMPAT_DOMAIN);

    // Upstream selection and the identity it answers.
    update_json(&mut hasher, b"action", &origin.action_config);
    update_optional_json(&mut hasher, b"auth", origin.auth_config.as_ref());

    // Everything that rewrites the request before it is sent.
    update_json_slice(&mut hasher, b"transforms", &origin.transform_configs);
    update_serializable(
        &mut hasher,
        b"request_modifiers",
        &origin.request_modifiers.as_slice(),
    );
    update_serializable(&mut hasher, b"filters", &origin.filters.as_slice());
    update_json_slice(&mut hasher, b"on_request", &origin.on_request);
    update_json_slice(&mut hasher, b"forward_rules", &origin.forward_rules);
    update_optional_json(&mut hasher, b"fallback", origin.fallback_origin.as_ref());
    update_variables(&mut hasher, origin.variables.as_deref());

    // Outbound identity. Both change who the upstream thinks is asking,
    // and an upstream that answers a signed or credentialed request
    // differently is the ordinary case rather than the exotic one.
    update_optional_json(
        &mut hasher,
        b"outbound_credential",
        origin.outbound_credential.as_ref(),
    );
    update_field(&mut hasher, b"outbound_web_bot_auth");
    update_field(&mut hasher, &[u8::from(origin.outbound_web_bot_auth)]);

    // Attached extension bundles, which can carry request-side hooks.
    update_extensions(&mut hasher, &origin.extensions);

    // The cache's own configuration, including the operator epoch.
    update_serializable(&mut hasher, b"response_cache", &origin.response_cache);

    let digest = hasher.finalize();
    let mut out = String::with_capacity(FINGERPRINT_HEX_LEN);
    for byte in digest.iter().take(FINGERPRINT_HEX_LEN / 2) {
        out.push(hex_nibble(byte >> 4));
        out.push(hex_nibble(byte & 0x0f));
    }
    CompactString::from(out)
}

fn hex_nibble(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'a' + (nibble - 10)) as char,
    }
}

/// Absorb one length-delimited field.
///
/// The length prefix is what stops two adjacent fields from aliasing:
/// without it `("ab", "c")` and `("a", "bc")` hash identically, and two
/// different configs would share a fingerprint.
fn update_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Absorb a labeled JSON value in RFC 8785 canonical form.
fn update_json(hasher: &mut Sha256, label: &[u8], value: &serde_json::Value) {
    update_field(hasher, label);
    match serde_json_canonicalizer::to_vec(value) {
        Ok(canonical) => update_field(hasher, &canonical),
        // Reachable only for a non-finite float, which no config path
        // produces. Absorbing the debug form keeps the field in the
        // digest: dropping it would let two configs that differ only
        // here share a fingerprint, which is the failure this module
        // exists to prevent.
        Err(_) => update_field(hasher, format!("{value:?}").as_bytes()),
    }
}

fn update_optional_json(hasher: &mut Sha256, label: &[u8], value: Option<&serde_json::Value>) {
    match value {
        Some(value) => update_json(hasher, label, value),
        None => {
            update_field(hasher, label);
            update_field(hasher, b"");
        }
    }
}

fn update_json_slice(hasher: &mut Sha256, label: &[u8], values: &[serde_json::Value]) {
    update_field(hasher, label);
    update_field(hasher, (values.len() as u64).to_le_bytes().as_slice());
    for value in values {
        update_json(hasher, b"item", value);
    }
}

/// Absorb the origin's template variables.
///
/// Hand-rolled rather than routed through [`update_serializable`]
/// because the map is keyed by `CompactString`, which has no `Serialize`
/// impl in this build. Keys are sorted so `HashMap` iteration order
/// cannot move the fingerprint between two runs over the same config.
fn update_variables(
    hasher: &mut Sha256,
    variables: Option<&std::collections::HashMap<CompactString, serde_json::Value>>,
) {
    update_field(hasher, b"variables");
    let Some(variables) = variables else {
        update_field(hasher, b"");
        return;
    };
    let mut names: Vec<&CompactString> = variables.keys().collect();
    names.sort_unstable();
    update_field(hasher, (names.len() as u64).to_le_bytes().as_slice());
    for name in names {
        update_field(hasher, name.as_bytes());
        match variables.get(name) {
            Some(value) => update_json(hasher, b"value", value),
            // Unreachable: `name` came from this map's own key set.
            None => update_field(hasher, b""),
        }
    }
}

/// Absorb the origin's attached extension bundles.
///
/// Keys are sorted for the same reason [`update_variables`] sorts its
/// own: `HashMap` order must not move the fingerprint between two runs
/// over one config.
fn update_extensions(
    hasher: &mut Sha256,
    extensions: &std::collections::HashMap<String, serde_yaml::Value>,
) {
    update_field(hasher, b"extensions");
    let mut names: Vec<&String> = extensions.keys().collect();
    names.sort_unstable();
    update_field(hasher, (names.len() as u64).to_le_bytes().as_slice());
    for name in names {
        update_field(hasher, name.as_bytes());
        match extensions.get(name).map(serde_json::to_value) {
            Some(Ok(json)) => update_json(hasher, b"value", &json),
            // A YAML value with no JSON projection (a non-string map
            // key, say). Absorb its debug form rather than skipping the
            // field, so two configs differing only here cannot collide.
            Some(Err(_)) => update_field(hasher, b"<unprojectable>"),
            // Unreachable: `name` came from this map's own key set.
            None => update_field(hasher, b""),
        }
    }
}

/// Absorb any serializable config block by way of its JSON projection.
fn update_serializable<T: serde::Serialize>(hasher: &mut Sha256, label: &[u8], value: &T) {
    match serde_json::to_value(value) {
        Ok(json) => update_json(hasher, label, &json),
        // Same reasoning as `update_json`: absorb something rather than
        // skip the field, so a serialization failure cannot silently
        // merge two configs.
        Err(_) => {
            update_field(hasher, label);
            update_field(hasher, b"<unserializable>");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_delimiting_stops_adjacent_fields_from_aliasing() {
        // Without the length prefix these two absorb the same bytes.
        let mut split = Sha256::new();
        update_field(&mut split, b"ab");
        update_field(&mut split, b"c");

        let mut joined = Sha256::new();
        update_field(&mut joined, b"a");
        update_field(&mut joined, b"bc");

        assert_ne!(
            split.finalize(),
            joined.finalize(),
            "field boundaries must survive into the digest"
        );
    }

    #[test]
    fn canonicalization_ignores_json_key_order() {
        let a: serde_json::Value =
            serde_json::from_str(r#"{"url":"https://x","type":"proxy"}"#).expect("valid json");
        let b: serde_json::Value =
            serde_json::from_str(r#"{"type":"proxy","url":"https://x"}"#).expect("valid json");

        let mut first = Sha256::new();
        update_json(&mut first, b"action", &a);
        let mut second = Sha256::new();
        update_json(&mut second, b"action", &b);

        assert_eq!(
            first.finalize(),
            second.finalize(),
            "key order must not partition a node from its own entries"
        );
    }

    #[test]
    fn an_absent_optional_differs_from_a_null_one() {
        let mut absent = Sha256::new();
        update_optional_json(&mut absent, b"auth", None);
        let mut null = Sha256::new();
        update_optional_json(&mut null, b"auth", Some(&serde_json::Value::Null));
        assert_ne!(
            absent.finalize(),
            null.finalize(),
            "an unconfigured block and an explicitly null one are different configs"
        );
    }
}
