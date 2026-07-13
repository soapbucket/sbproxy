use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Barrier};

use sbproxy_core::model_plane::{
    body_sha256_hex, DispatchAuthProof, DispatchEnvelope, DispatchEnvelopeError,
    DispatchReplayFence, DispatchSigner, DispatchVerifier, SignedDispatchEnvelope,
    DISPATCH_ENVELOPE_SCHEMA_VERSION,
};
use sbproxy_mesh::enrollment::{AuthorityInit, EnrollmentAuthority};
use sbproxy_mesh::peer_identity::PeerIdentityAuthenticator;
use sbproxy_mesh::transport::tls::MeshTlsConfig;
use sbproxy_mesh::{ClusterHandle, ClusterNodeRole, MeshNode};
use sbproxy_model_host::PriorityClass;

const NOW: u64 = 1_750_000_000_000;
const BODY: &[u8] = br#"{"model":"qwen","messages":[]}"#;
const DEVELOPMENT_KEY: &[u8] = b"development-model-plane-key-32b";

fn envelope() -> DispatchEnvelope {
    DispatchEnvelope {
        schema_version: DISPATCH_ENVELOPE_SCHEMA_VERSION,
        issuer_node_id: "gateway-a".to_string(),
        audience_node_id: "worker-a".to_string(),
        request_id: "req_01HYMODELPLANE".to_string(),
        nonce: "nonce_01HYMODELPLANE_0001".to_string(),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 10_000,
        hop_count: 1,
        tenant_id: "tenant-a".to_string(),
        governed_key_id: "key-a".to_string(),
        policy_revision: "policy-7".to_string(),
        deployment: "qwen".to_string(),
        deployment_generation: 7,
        logical_model: "qwen/qwen2.5-coder".to_string(),
        priority: PriorityClass::Standard,
        method: "POST".to_string(),
        path: "/v1/chat/completions".to_string(),
        content_type: Some("application/json".to_string()),
        body_sha256: body_sha256_hex(BODY),
    }
}

fn sign(envelope: DispatchEnvelope) -> SignedDispatchEnvelope {
    envelope
        .sign(DispatchSigner::DevelopmentSharedKey(DEVELOPMENT_KEY))
        .expect("sign fixture")
}

fn assert_code<T>(result: Result<T, DispatchEnvelopeError>, expected: &str) {
    let error = result.err().expect("expected dispatch error");
    assert_eq!(error.code(), expected, "{error}");
}

fn enrolled_handle(
    node_id: &str,
    roles: BTreeSet<ClusterNodeRole>,
) -> (tempfile::TempDir, ClusterHandle, String) {
    let temp = tempfile::tempdir().expect("identity directory");
    let directory = temp.path().join("authority");
    let authority = EnrollmentAuthority::initialize(
        &directory,
        AuthorityInit {
            cluster_id: "cluster-a".to_string(),
            node_id: node_id.to_string(),
            roles,
            labels: BTreeMap::new(),
            server_name: "sbproxy-mesh".to_string(),
        },
    )
    .expect("initialize identity");
    let fingerprint = authority.identity().document.certificate_sha256.clone();
    let identity = authority
        .identity()
        .document
        .to_cluster_identity()
        .expect("cluster identity");
    let tls = MeshTlsConfig {
        cert_pem: std::fs::read_to_string(directory.join("node.pem")).expect("certificate"),
        key_pem: std::fs::read_to_string(directory.join("node-key.pem")).expect("key"),
        ca_pem: std::fs::read_to_string(directory.join("ca.pem")).expect("CA"),
    };
    let authenticator =
        PeerIdentityAuthenticator::load_installed(&directory, &identity, "sbproxy-mesh", &tls)
            .expect("load identity");
    let mesh = MeshNode::new(identity.node_id.clone(), Vec::new(), 8)
        .with_identity_authenticator(Some(Arc::new(authenticator)));
    let handle = ClusterHandle::distributed(identity, Arc::new(mesh)).expect("cluster handle");
    (temp, handle, fingerprint)
}

#[test]
fn development_hmac_round_trips_and_binds_the_body() {
    let signed = sign(envelope());
    let json = signed.to_json().expect("encode envelope");
    let decoded = SignedDispatchEnvelope::parse_json(&json).expect("strict decode");
    let verified = decoded
        .verify(
            DispatchVerifier::DevelopmentSharedKey(DEVELOPMENT_KEY),
            "worker-a",
            NOW,
            BODY,
        )
        .expect("verify envelope");
    assert_eq!(verified.envelope.deployment, "qwen");
    assert!(verified.authenticated_peer.is_none());

    assert_code(
        decoded.verify(
            DispatchVerifier::DevelopmentSharedKey(DEVELOPMENT_KEY),
            "worker-a",
            NOW,
            b"changed",
        ),
        "request_digest_mismatch",
    );
    assert_code(
        decoded.verify(
            DispatchVerifier::DevelopmentSharedKey(b"different-development-key-32bytes"),
            "worker-a",
            NOW,
            BODY,
        ),
        "peer_authentication_failed",
    );
}

#[test]
fn peer_identity_requires_gateway_role_and_tls_leaf_binding() {
    let (_temp, gateway, fingerprint) = enrolled_handle(
        "gateway-a",
        BTreeSet::from([ClusterNodeRole::Authority, ClusterNodeRole::Gateway]),
    );
    let signed = envelope()
        .sign(DispatchSigner::PeerIdentity(&gateway))
        .expect("sign peer envelope");
    let verified = signed
        .verify(
            DispatchVerifier::PeerIdentity {
                cluster: &gateway,
                tls_peer_certificate_sha256: &fingerprint,
            },
            "worker-a",
            NOW,
            BODY,
        )
        .expect("verify peer envelope");
    assert_eq!(
        verified.authenticated_peer.expect("peer claims").node_id,
        "gateway-a"
    );
    assert_code(
        signed.verify(
            DispatchVerifier::PeerIdentity {
                cluster: &gateway,
                tls_peer_certificate_sha256: "different-leaf",
            },
            "worker-a",
            NOW,
            BODY,
        ),
        "peer_authentication_failed",
    );
    assert_code(
        signed.verify(
            DispatchVerifier::DevelopmentSharedKey(DEVELOPMENT_KEY),
            "worker-a",
            NOW,
            BODY,
        ),
        "peer_authentication_failed",
    );

    let (_temp, worker, worker_fingerprint) = enrolled_handle(
        "gateway-a",
        BTreeSet::from([ClusterNodeRole::Authority, ClusterNodeRole::Worker]),
    );
    let worker_signed = envelope()
        .sign(DispatchSigner::PeerIdentity(&worker))
        .expect("worker can prove identity");
    assert_code(
        worker_signed.verify(
            DispatchVerifier::PeerIdentity {
                cluster: &worker,
                tls_peer_certificate_sha256: &worker_fingerprint,
            },
            "worker-a",
            NOW,
            BODY,
        ),
        "peer_authentication_failed",
    );
}

#[test]
fn envelope_rejects_wrong_audience_expiry_hop_and_lifetime() {
    assert_code(
        sign(envelope()).verify(
            DispatchVerifier::DevelopmentSharedKey(DEVELOPMENT_KEY),
            "worker-b",
            NOW,
            BODY,
        ),
        "audience_mismatch",
    );

    let mut expired = envelope();
    expired.expires_at_unix_ms = NOW;
    assert_code(
        sign(expired).verify(
            DispatchVerifier::DevelopmentSharedKey(DEVELOPMENT_KEY),
            "worker-a",
            NOW,
            BODY,
        ),
        "dispatch_expired",
    );

    let mut wrong_hop = envelope();
    wrong_hop.hop_count = 2;
    assert_code(
        sign(wrong_hop).verify(
            DispatchVerifier::DevelopmentSharedKey(DEVELOPMENT_KEY),
            "worker-a",
            NOW,
            BODY,
        ),
        "hop_limit_exceeded",
    );

    let mut excessive_lifetime = envelope();
    excessive_lifetime.expires_at_unix_ms = excessive_lifetime.issued_at_unix_ms + 30_001;
    assert_code(
        sign(excessive_lifetime).verify(
            DispatchVerifier::DevelopmentSharedKey(DEVELOPMENT_KEY),
            "worker-a",
            NOW,
            BODY,
        ),
        "invalid_dispatch_lifetime",
    );
}

#[test]
fn envelope_denies_unknown_fields_oversize_values_and_unapproved_routes() {
    let signed = sign(envelope());
    let mut unknown = serde_json::to_value(&signed).expect("value");
    unknown
        .as_object_mut()
        .expect("object")
        .insert("unexpected".to_string(), serde_json::json!(true));
    assert_code(
        SignedDispatchEnvelope::parse_json(&serde_json::to_vec(&unknown).unwrap()),
        "invalid_envelope",
    );

    let mut oversize = serde_json::to_value(&signed).expect("value");
    oversize["envelope"]["request_id"] = serde_json::json!("x".repeat(129));
    assert_code(
        SignedDispatchEnvelope::parse_json(&serde_json::to_vec(&oversize).unwrap()),
        "invalid_envelope",
    );

    for (method, path) in [
        ("GET", "/v1/chat/completions"),
        ("POST", "/admin/model-host/status"),
    ] {
        let mut invalid = envelope();
        invalid.method = method.to_string();
        invalid.path = path.to_string();
        assert_code(
            invalid.sign(DispatchSigner::DevelopmentSharedKey(DEVELOPMENT_KEY)),
            "invalid_envelope",
        );
    }
}

#[test]
fn replay_fence_allows_exactly_one_concurrent_winner() {
    let fence = Arc::new(DispatchReplayFence::new(128));
    let barrier = Arc::new(Barrier::new(32));
    let mut threads = Vec::new();
    for _ in 0..32 {
        let fence = Arc::clone(&fence);
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            fence
                .check_and_record("gateway-a", "nonce-a", NOW + 10_000, NOW)
                .is_ok()
        }));
    }
    let accepted = threads
        .into_iter()
        .map(|thread| thread.join().expect("thread"))
        .filter(|accepted| *accepted)
        .count();
    assert_eq!(accepted, 1);
}

#[test]
fn full_replay_fence_fails_closed_and_prunes_only_expired_entries() {
    let fence = DispatchReplayFence::new(1);
    fence
        .check_and_record("gateway-a", "nonce-one", NOW + 10, NOW)
        .expect("first nonce");
    assert_code(
        fence.check_and_record("gateway-a", "nonce-two", NOW + 20, NOW),
        "replay_fence_full",
    );
    assert_code(
        fence.check_and_record("gateway-a", "nonce-one", NOW + 20, NOW),
        "replay_detected",
    );
    fence
        .check_and_record("gateway-a", "nonce-two", NOW + 20, NOW + 10)
        .expect("expired entry pruned");
}

#[test]
fn auth_proof_json_is_strict() {
    let signed = sign(envelope());
    assert!(matches!(
        signed.auth,
        DispatchAuthProof::DevelopmentHmac { .. }
    ));
    let mut auth = serde_json::to_value(&signed).expect("value");
    auth["auth"]["extra"] = serde_json::json!("not allowed");
    assert_code(
        SignedDispatchEnvelope::parse_json(&serde_json::to_vec(&auth).unwrap()),
        "invalid_envelope",
    );
}
