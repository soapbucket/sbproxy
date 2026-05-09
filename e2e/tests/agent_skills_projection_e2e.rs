//! WOR-193 / WOR-194 / WOR-195: Agent Skills v0.2.0 projection
//! conformance.
//!
//! Validates the v0.2.0 manifest shape projected by the agent_skills
//! module. Per the spec at
//! `https://schemas.agentskills.io/discovery/0.2.0/schema.json` the
//! manifest is a JSON object with `$schema` and `entries` fields, and
//! each entry carries `name`, `type`, `description`, `url`, and
//! `digest`.

use sbproxy_e2e::ProxyHarness;

const FIXTURE: &str = include_str!("../fixtures/agent_skills/sb.yml");

fn start() -> anyhow::Result<ProxyHarness> {
    ProxyHarness::start_with_yaml(FIXTURE)
}

// --- Test 1: manifest is served with the right schema and content type ---

#[test]
fn agent_skills_manifest_served_at_canonical_path() {
    let harness = start().expect("start proxy");
    let resp = harness
        .get("/.well-known/agent-skills/index.json", "skills.localhost")
        .expect("GET manifest");
    assert_eq!(resp.status, 200);
    let ct = resp
        .headers
        .get("content-type")
        .cloned()
        .unwrap_or_default();
    assert!(
        ct.starts_with("application/json"),
        "Content-Type must be application/json; got {ct}"
    );
    let body = resp.text().expect("utf-8 body");
    let v: serde_json::Value = serde_json::from_str(&body).expect("manifest is JSON");
    assert_eq!(
        v["$schema"], "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
        "manifest must carry the v0.2.0 $schema URI"
    );
    assert!(
        v["entries"].is_array(),
        "manifest must carry an entries array"
    );
}

// --- Test 2: anonymous callers receive only public entries ---

#[test]
fn anonymous_caller_sees_public_only_manifest() {
    let harness = start().expect("start proxy");
    let resp = harness
        .get("/.well-known/agent-skills/index.json", "skills.localhost")
        .expect("GET manifest");
    let v: serde_json::Value = serde_json::from_str(&resp.text().unwrap()).unwrap();
    let entries = v["entries"].as_array().unwrap();
    assert_eq!(
        entries.len(),
        1,
        "anonymous caller must see only the one public entry; got {entries:?}"
    );
    assert_eq!(entries[0]["name"], "deploy-via-pr");
    assert_eq!(entries[0]["type"], "skill-md");
    assert!(entries[0]["digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
}

// --- Test 3: authenticated callers receive the full manifest ---

#[test]
fn authenticated_caller_sees_full_manifest() {
    let harness = start().expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/.well-known/agent-skills/index.json",
            "skills.localhost",
            &[("authorization", "Bearer demo-token")],
        )
        .expect("GET manifest");
    let v: serde_json::Value = serde_json::from_str(&resp.text().unwrap()).unwrap();
    let entries = v["entries"].as_array().unwrap();
    assert_eq!(
        entries.len(),
        2,
        "authenticated caller must see both entries; got {entries:?}"
    );
    let names: Vec<&str> = entries
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"deploy-via-pr"));
    assert!(names.contains(&"internal-rotate-secret"));
}

// --- Test 4: skill body is served with the right content type ---

#[test]
fn skill_md_body_served_with_markdown_content_type() {
    let harness = start().expect("start proxy");
    let resp = harness
        .get("/skills/deploy-via-pr.md", "skills.localhost")
        .expect("GET skill body");
    assert_eq!(resp.status, 200);
    let ct = resp
        .headers
        .get("content-type")
        .cloned()
        .unwrap_or_default();
    assert!(
        ct.starts_with("text/markdown"),
        "skill-md body Content-Type must start with text/markdown; got {ct}"
    );
    let body = resp.text().expect("utf-8 body");
    assert!(body.contains("deploy-via-pr"));
}

// --- Test 5: origin without agent_skills 404s the well-known URL ---

#[test]
fn unconfigured_origin_404s_well_known_url() {
    let yaml = r#"
proxy:
  http_bind_port: 0

origins:
  "noskills.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "no skills here"
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get("/.well-known/agent-skills/index.json", "noskills.localhost")
        .expect("GET manifest");
    assert_eq!(
        resp.status, 404,
        "unconfigured origin must 404 the well-known URL"
    );
}

// --- Test 6: digest field in manifest matches the served body ---

#[test]
fn manifest_digest_matches_served_body() {
    use sha2::{Digest, Sha256};

    let harness = start().expect("start proxy");
    let resp = harness
        .get("/.well-known/agent-skills/index.json", "skills.localhost")
        .expect("GET manifest");
    let v: serde_json::Value = serde_json::from_str(&resp.text().unwrap()).unwrap();
    let entry = &v["entries"][0];
    let url = entry["url"].as_str().unwrap();
    let manifest_digest = entry["digest"].as_str().unwrap();
    let path = if let Some(rest) = url.strip_prefix("http://") {
        match rest.find('/') {
            Some(i) => &rest[i..],
            None => "/",
        }
    } else if let Some(rest) = url.strip_prefix("https://") {
        match rest.find('/') {
            Some(i) => &rest[i..],
            None => "/",
        }
    } else {
        url
    };
    let body_resp = harness
        .get(path, "skills.localhost")
        .expect("GET skill body");
    assert_eq!(body_resp.status, 200);
    let mut hasher = Sha256::new();
    hasher.update(&body_resp.body);
    let observed_digest = format!("sha256:{}", hex::encode(hasher.finalize()));
    assert_eq!(
        manifest_digest, observed_digest,
        "manifest digest must match the SHA-256 of the served body"
    );
}
