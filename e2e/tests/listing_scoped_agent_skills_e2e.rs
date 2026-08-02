//! WOR-196: Listing-scoped Agent Skills resolution + Catalog
//! aggregation.
//!
//! Validates the three new surfaces this ticket lands:
//!
//! - `GET /.well-known/agent-skills/<listing>/index.json` serves a
//!   single Listing's `spec.skills[]` manifest.
//! - `GET /.well-known/agent-skills/<listing>/<artifact>` re-hosts a
//!   skill body the manifest pins.
//! - `GET /.well-known/agent-skills/index.json` returns the union of
//!   the top-level `agent_skills:` block and every visible Listing
//!   whose `spec.resources[].ref` lists this hostname.
//!
//! Each test boots the proxy against a temp workspace that carries
//! both an `sb.yml` and a `listings/*.yaml` sibling. The listings
//! inline their skill bodies via `body:` so the test does not depend
//! on filesystem layout under the workspace.

use sbproxy_e2e::ProxyHarness;

const SB_YML: &str = r#"
proxy:
  http_bind_port: 0  # overridden by the harness

origins:
  "catalog.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>catalog</h1>"
    # Top-level WOR-193 agent_skills block: serves as the per-origin
    # surface and as one source of entries for the aggregated index.
    # Both url spellings appear so WOR-2217's property test covers
    # each one.
    agent_skills:
      - name: "origin-pinned"
        type: skill-md
        description: "Origin-level skill (top-level config)."
        url: "/skills/origin-pinned.md"
        visibility: public
        body: |
          # origin-pinned
          From the top-level agent_skills block.
      - name: "origin-relative"
        type: skill-md
        description: "Origin-level skill declared with a relative url."
        url: "skills/origin-relative.md"
        visibility: public
        body: |
          # origin-relative
          Declared with the relative url spelling.
"#;

const LISTING_PUBLIC: &str = r#"
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: public-listing
spec:
  type: api
  status: published
  resources:
    - ref: origins/catalog.localhost
      revision:
        mode: pin
        value: abc1234
  skills:
    - name: listing-public
      type: skill-md
      description: "Listing-scoped public skill"
      url: /skills/listing-public.md
      visibility: public
      body: |
        # listing-public
        Public skill on the catalog listing.
    - name: listing-private
      type: skill-md
      description: "Listing-scoped authenticated-only skill"
      url: /skills/listing-private.md
      visibility: authenticated
      body: |
        # listing-private
        Authenticated callers see this entry.
    - name: listing-relative
      type: skill-md
      description: "Listing-scoped skill declared with a relative url"
      url: skills/listing-relative.md
      visibility: public
      body: |
        # listing-relative
        Declared with the relative url spelling.
"#;

const LISTING_OTHER_HOSTNAME: &str = r#"
apiVersion: sbproxy.dev/v1
kind: Listing
metadata:
  name: other-listing
spec:
  type: api
  status: published
  resources:
    - ref: origins/other.localhost
      revision:
        mode: pin
        value: deadbee
  skills:
    - name: other-skill
      type: skill-md
      description: "Belongs to a different hostname"
      url: /skills/other.md
      visibility: public
      body: |
        # other-skill
"#;

fn start() -> anyhow::Result<ProxyHarness> {
    ProxyHarness::start_with_workspace(
        SB_YML,
        &[
            ("listings/public-listing.yaml", LISTING_PUBLIC),
            ("listings/other-listing.yaml", LISTING_OTHER_HOSTNAME),
        ],
    )
}

#[test]
fn per_listing_index_serves_listing_skills() {
    let h = start().expect("start proxy");
    let resp = h
        .get(
            "/.well-known/agent-skills/public-listing/index.json",
            "catalog.localhost",
        )
        .expect("GET per-listing index");
    assert_eq!(
        resp.status,
        200,
        "body: {}",
        resp.text().unwrap_or_default()
    );
    let v: serde_json::Value =
        serde_json::from_str(&resp.text().unwrap()).expect("manifest is JSON");
    assert_eq!(
        v["$schema"], "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
        "must carry the v0.2.0 schema URI"
    );
    let entries = v["entries"].as_array().expect("entries array");
    // Anonymous caller: only the public entry is visible.
    let names: Vec<&str> = entries
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"listing-public"),
        "expected listing-public in {names:?}"
    );
    assert!(
        !names.contains(&"listing-private"),
        "authenticated-only entry must be filtered for anonymous"
    );
}

#[test]
fn per_listing_index_filters_visibility_on_auth_header() {
    let h = start().expect("start proxy");
    let resp = h
        .get_with_headers(
            "/.well-known/agent-skills/public-listing/index.json",
            "catalog.localhost",
            &[("authorization", "Bearer demo")],
        )
        .expect("GET per-listing index");
    let v: serde_json::Value = serde_json::from_str(&resp.text().unwrap()).unwrap();
    let entries = v["entries"].as_array().unwrap();
    let names: Vec<&str> = entries
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"listing-public"));
    assert!(
        names.contains(&"listing-private"),
        "authenticated caller must see the private entry"
    );
}

#[test]
fn per_listing_artifact_is_rehosted() {
    let h = start().expect("start proxy");
    let resp = h
        .get(
            "/.well-known/agent-skills/public-listing/skills/listing-public.md",
            "catalog.localhost",
        )
        .expect("GET listing artifact");
    assert_eq!(resp.status, 200);
    let ct = resp
        .headers
        .get("content-type")
        .cloned()
        .unwrap_or_default();
    assert!(
        ct.starts_with("text/markdown"),
        "skill-md must serve as text/markdown; got {ct}"
    );
    let body = resp.text().expect("utf-8");
    assert!(body.contains("listing-public"));
}

#[test]
fn aggregated_index_unions_origin_and_listings() {
    let h = start().expect("start proxy");
    let resp = h
        .get("/.well-known/agent-skills/index.json", "catalog.localhost")
        .expect("GET aggregated");
    assert_eq!(resp.status, 200);
    let v: serde_json::Value = serde_json::from_str(&resp.text().unwrap()).unwrap();
    let entries = v["entries"].as_array().expect("entries array");
    let names: Vec<&str> = entries
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    // Per-origin entry (WOR-193 surface) survives.
    assert!(
        names.contains(&"origin-pinned"),
        "aggregated must include origin-level skill; got {names:?}"
    );
    // Listing-scoped public entry is unioned in.
    assert!(
        names.contains(&"listing-public"),
        "aggregated must include public listing skill; got {names:?}"
    );
    // The "other" listing pins a different hostname so it must not
    // appear on this aggregated view.
    assert!(
        !names.contains(&"other-skill"),
        "aggregated must not leak skills from listings that don't publish this host"
    );
    // Authenticated-only listing skill is filtered for anonymous.
    assert!(
        !names.contains(&"listing-private"),
        "anonymous aggregated view must filter visibility: authenticated"
    );
}

#[test]
fn aggregated_index_authenticated_includes_private_listing_skill() {
    let h = start().expect("start proxy");
    let resp = h
        .get_with_headers(
            "/.well-known/agent-skills/index.json",
            "catalog.localhost",
            &[("authorization", "Bearer demo")],
        )
        .expect("GET aggregated auth");
    let v: serde_json::Value = serde_json::from_str(&resp.text().unwrap()).unwrap();
    let names: Vec<&str> = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"listing-private"));
}

#[test]
fn per_listing_index_does_not_serve_manifest_for_unknown_listing() {
    let h = start().expect("start proxy");
    let resp = h
        .get(
            "/.well-known/agent-skills/no-such-listing/index.json",
            "catalog.localhost",
        )
        .expect("GET unknown listing");
    // Unknown listing falls through past the well-known handler;
    // the static origin serves its own body, which must not parse as
    // a v0.2.0 manifest envelope.
    let body = resp.text().unwrap_or_default();
    let is_manifest = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v["$schema"].as_str().map(|s| s.to_string()))
        .map(|s| s.contains("agentskills.io"))
        .unwrap_or(false);
    assert!(
        !is_manifest,
        "unknown listing must not serve a v0.2.0 manifest envelope; body={body}"
    );
}

// --- WOR-2217: every URL the manifest advertises must be fetchable ---

/// Strip scheme and authority off a manifest URL, leaving the path to
/// request. The harness always sends a `Host` header, so a re-hosted
/// entry always renders fully-qualified.
fn path_of(url: &str) -> String {
    for prefix in ["http://", "https://"] {
        if let Some(rest) = url.strip_prefix(prefix) {
            return match rest.find('/') {
                Some(i) => rest[i..].to_string(),
                None => "/".to_string(),
            };
        }
    }
    url.to_string()
}

/// Fetch every URL a rendered manifest advertises and require the
/// proxy to actually serve the pinned artifact there.
///
/// The status code alone is not a sufficient check on this fixture:
/// the origin's action is `static`, so a path the well-known handler
/// declines falls through and gets a 200 carrying `<h1>catalog</h1>`.
/// The digest comparison is what makes the assertion real. It is also
/// the right check on its own terms, since the digest is the contract
/// the manifest offers a cooperative agent.
fn assert_manifest_urls_are_fetchable(h: &ProxyHarness, manifest_path: &str, host: &str) {
    use sha2::{Digest, Sha256};

    let resp = h.get(manifest_path, host).expect("GET manifest");
    assert_eq!(
        resp.status,
        200,
        "manifest at {manifest_path} must serve; body: {}",
        resp.text().unwrap_or_default()
    );
    let v: serde_json::Value =
        serde_json::from_str(&resp.text().unwrap()).expect("manifest is JSON");
    let entries = v["entries"].as_array().expect("entries array");
    assert!(
        !entries.is_empty(),
        "manifest at {manifest_path} advertised no entries; the assertion below would be vacuous"
    );

    for e in entries {
        let name = e["name"].as_str().expect("entry name");
        let url = e["url"].as_str().expect("entry url");
        let kind = e["type"].as_str().expect("entry type");
        let manifest_digest = e["digest"].as_str().expect("entry digest");
        let path = path_of(url);

        let art = h.get(&path, host).expect("GET advertised artifact");
        assert_ne!(
            art.status, 404,
            "manifest at {manifest_path} advertises {url} for skill '{name}', but the proxy \
             returns 404 for {path}"
        );
        assert_eq!(
            art.status, 200,
            "manifest at {manifest_path} advertises {url} for skill '{name}'; got status {}",
            art.status
        );

        let observed = format!("sha256:{}", hex::encode(Sha256::digest(&art.body)));
        assert_eq!(
            manifest_digest,
            observed,
            "manifest at {manifest_path} advertises {url} for skill '{name}' and pins digest \
             {manifest_digest}, but the body served at {path} hashes to {observed}. The \
             advertised URL does not resolve to the pinned artifact. Body: {}",
            String::from_utf8_lossy(&art.body)
        );

        if kind == "skill-md" {
            let ct = art.headers.get("content-type").cloned().unwrap_or_default();
            assert!(
                ct.starts_with("text/markdown"),
                "skill '{name}' at {path} must serve as text/markdown; got {ct}"
            );
        }
    }
}

#[test]
fn every_url_in_the_per_listing_manifest_is_fetchable() {
    let h = start().expect("start proxy");
    assert_manifest_urls_are_fetchable(
        &h,
        "/.well-known/agent-skills/public-listing/index.json",
        "catalog.localhost",
    );
}

#[test]
fn every_url_in_the_aggregated_manifest_is_fetchable() {
    // The aggregated document mixes the top-level `agent_skills:`
    // entries, re-hosted at the bare path, with the Listing entries
    // re-hosted under `/.well-known/agent-skills/<listing>/`. Both
    // have to be right in one manifest.
    let h = start().expect("start proxy");
    assert_manifest_urls_are_fetchable(
        &h,
        "/.well-known/agent-skills/index.json",
        "catalog.localhost",
    );
}

#[test]
fn per_listing_manifest_advertises_the_listing_scoped_artifact_path() {
    // WOR-2217 regression pin. A path-absolute `url` used to render
    // as `https://catalog.localhost/skills/listing-public.md`, an
    // address only the top-level `agent_skills:` block re-hosts.
    let h = start().expect("start proxy");
    let resp = h
        .get(
            "/.well-known/agent-skills/public-listing/index.json",
            "catalog.localhost",
        )
        .expect("GET per-listing index");
    let v: serde_json::Value = serde_json::from_str(&resp.text().unwrap()).unwrap();
    let url = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "listing-public")
        .expect("listing-public entry")["url"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        url.ends_with("/.well-known/agent-skills/public-listing/skills/listing-public.md"),
        "per-listing manifest must advertise the listing-scoped path; got {url}"
    );
}

#[test]
fn aggregated_index_falls_back_to_top_level_only_when_no_listings_match() {
    // Boot a proxy with the top-level agent_skills block but no
    // Listing that publishes this hostname. The aggregated endpoint
    // still serves the top-level entries, satisfying the WOR-196
    // backwards-compat AC.
    let h = ProxyHarness::start_with_workspace(
        SB_YML,
        &[("listings/other-listing.yaml", LISTING_OTHER_HOSTNAME)],
    )
    .expect("start proxy");
    let resp = h
        .get("/.well-known/agent-skills/index.json", "catalog.localhost")
        .expect("GET aggregated");
    assert_eq!(resp.status, 200);
    let v: serde_json::Value = serde_json::from_str(&resp.text().unwrap()).unwrap();
    let names: Vec<&str> = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"origin-pinned"));
    assert!(!names.contains(&"other-skill"));
}
