use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use sbproxy_mesh::enrollment::{
    install_worker_enrollment, verify_signed_identity, AuthorityInit, EnrollmentAuthority,
    EnrollmentRequest, EnrollmentTokenConstraints, EnrollmentTokenRejection, WorkerEnrollment,
};
use sbproxy_mesh::{ClusterIdentity, ClusterNodeRole};

fn authority_init() -> AuthorityInit {
    AuthorityInit {
        cluster_id: "production-a".to_string(),
        node_id: "authority-a".to_string(),
        roles: BTreeSet::from([ClusterNodeRole::Gateway, ClusterNodeRole::Authority]),
        labels: BTreeMap::from([("zone".to_string(), "us-central1-a".to_string())]),
        server_name: "sbproxy-mesh".to_string(),
    }
}

fn worker_constraints() -> EnrollmentTokenConstraints {
    EnrollmentTokenConstraints {
        allowed_roles: BTreeSet::from([ClusterNodeRole::Worker]),
        labels: BTreeMap::from([("zone".to_string(), "us-central1-b".to_string())]),
    }
}

fn worker_request(
    token: String,
    worker: &WorkerEnrollment,
    constraints: &EnrollmentTokenConstraints,
) -> EnrollmentRequest {
    worker.request(
        token,
        constraints.allowed_roles.clone(),
        constraints.labels.clone(),
    )
}

#[test]
fn initialize_writes_complete_owner_only_authority_and_signed_identity() {
    let parent = tempfile::tempdir().expect("temp dir");
    let authority_dir = parent.path().join("authority");
    let authority = EnrollmentAuthority::initialize(&authority_dir, authority_init())
        .expect("initialize authority");

    for name in [
        "ca.pem",
        "ca-key.pem",
        "node.pem",
        "node-key.pem",
        "gossip.key",
        "authority-signing.key",
        "authority-verifying.key",
        "identity.json",
        "tokens.json",
    ] {
        let metadata = std::fs::metadata(authority_dir.join(name))
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert!(metadata.is_file(), "{name}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(metadata.permissions().mode() & 0o077, 0, "{name}");
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&authority_dir)
                .expect("authority metadata")
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }

    let signed = authority.identity();
    verify_signed_identity(signed, authority.verifying_key()).expect("valid identity signature");
    assert_eq!(signed.document.cluster_id, "production-a");
    assert_eq!(signed.document.node_id, "authority-a");
    assert!(signed.document.roles.contains(&ClusterNodeRole::Authority));

    let reopened = EnrollmentAuthority::open(&authority_dir).expect("reopen authority");
    assert_eq!(reopened.identity(), signed);
    assert!(EnrollmentAuthority::initialize(&authority_dir, authority_init()).is_err());
}

#[test]
fn token_store_contains_hash_and_constraints_but_never_clear_token() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority =
        EnrollmentAuthority::initialize(temp.path().join("authority"), authority_init())
            .expect("authority");
    let constraints = worker_constraints();
    let issued = authority
        .create_token(constraints.clone(), Duration::from_secs(300))
        .expect("token");

    let store =
        std::fs::read_to_string(authority.directory().join("tokens.json")).expect("token store");
    assert!(
        !store.contains(issued.token()),
        "clear token leaked to store"
    );
    assert!(store.contains(issued.token_id()));
    assert!(store.contains("sha256"));
    assert!(store.contains("us-central1-b"));
    assert_eq!(issued.constraints(), &constraints);
}

#[test]
fn worker_private_key_stays_local_and_installed_identity_matches_manual_identity() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority =
        EnrollmentAuthority::initialize(temp.path().join("authority"), authority_init())
            .expect("authority");
    let constraints = worker_constraints();
    let issued = authority
        .create_token(constraints.clone(), Duration::from_secs(300))
        .expect("token");
    let worker = WorkerEnrollment::generate("worker-b", "sbproxy-mesh").expect("worker CSR");
    let request = worker_request(issued.into_token(), &worker, &constraints);
    let request_json = serde_json::to_string(&request).expect("request JSON");
    assert!(!request_json.contains("PRIVATE KEY"));

    let response = authority.enroll(request).expect("enroll worker");
    let response_json = serde_json::to_string(&response).expect("response JSON");
    assert!(!response_json.contains("PRIVATE KEY"));
    verify_signed_identity(&response.identity, &response.authority_verifying_key)
        .expect("signed response identity");

    let installed = install_worker_enrollment(temp.path().join("worker"), worker, response)
        .expect("install worker");
    assert!(installed.node_key_file.exists());
    assert!(std::fs::read_to_string(&installed.node_key_file)
        .expect("installed key")
        .contains("PRIVATE KEY"));
    let expected = ClusterIdentity {
        cluster_id: "production-a".to_string(),
        node_id: "worker-b".to_string(),
        roles: BTreeSet::from([ClusterNodeRole::Worker]),
        labels: constraints.labels,
        peer_address: None,
        model_endpoint: None,
    };
    assert_eq!(installed.identity, expected);
}

#[test]
fn enrollment_rejects_replay_widened_roles_changed_labels_and_bad_csr() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority =
        EnrollmentAuthority::initialize(temp.path().join("authority"), authority_init())
            .expect("authority");
    let constraints = worker_constraints();

    let issued = authority
        .create_token(constraints.clone(), Duration::from_secs(300))
        .expect("token");
    let worker = WorkerEnrollment::generate("worker-b", "sbproxy-mesh").expect("worker");
    let request = worker_request(issued.into_token(), &worker, &constraints);
    authority.enroll(request.clone()).expect("first enrollment");
    let replay = authority.enroll(request).expect_err("replay denied");
    assert_eq!(
        replay.token_rejection(),
        Some(EnrollmentTokenRejection::Consumed)
    );

    let issued = authority
        .create_token(constraints.clone(), Duration::from_secs(300))
        .expect("token");
    let mut widened = worker_request(issued.into_token(), &worker, &constraints);
    widened.roles.insert(ClusterNodeRole::Authority);
    let error = authority.enroll(widened).expect_err("widened roles denied");
    assert_eq!(
        error.token_rejection(),
        Some(EnrollmentTokenRejection::Constraints)
    );

    let issued = authority
        .create_token(constraints.clone(), Duration::from_secs(300))
        .expect("token");
    let mut relabeled = worker_request(issued.into_token(), &worker, &constraints);
    relabeled
        .labels
        .insert("zone".to_string(), "us-central1-c".to_string());
    let error = authority
        .enroll(relabeled)
        .expect_err("changed labels denied");
    assert_eq!(
        error.token_rejection(),
        Some(EnrollmentTokenRejection::Constraints)
    );

    let issued = authority
        .create_token(constraints.clone(), Duration::from_secs(300))
        .expect("token");
    let mut bad_csr = worker_request(issued.into_token(), &worker, &constraints);
    bad_csr.csr_pem = bad_csr.csr_pem.replace('A', "B");
    assert!(authority.enroll(bad_csr).is_err());
}

#[test]
fn reenrollment_advances_a_durable_node_identity_epoch() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority =
        EnrollmentAuthority::initialize(temp.path().join("authority"), authority_init())
            .expect("authority");
    let constraints = worker_constraints();

    let enroll_once = || {
        let token = authority
            .create_token(constraints.clone(), Duration::from_secs(300))
            .expect("rotation token");
        let worker = WorkerEnrollment::generate("worker-b", "sbproxy-mesh").expect("rotation CSR");
        authority
            .enroll(worker_request(token.into_token(), &worker, &constraints))
            .expect("rotation enrollment")
    };

    let first = enroll_once();
    let second = enroll_once();
    assert_eq!(first.identity.document.identity_epoch, 1);
    assert_eq!(second.identity.document.identity_epoch, 2);

    let reopened = EnrollmentAuthority::open(authority.directory()).expect("reopen authority");
    let token = reopened
        .create_token(constraints.clone(), Duration::from_secs(300))
        .expect("post-restart token");
    let worker = WorkerEnrollment::generate("worker-b", "sbproxy-mesh").expect("post-restart CSR");
    let third = reopened
        .enroll(worker_request(token.into_token(), &worker, &constraints))
        .expect("post-restart enrollment");
    assert_eq!(third.identity.document.identity_epoch, 3);
}

#[test]
fn expired_token_is_rejected() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority =
        EnrollmentAuthority::initialize(temp.path().join("authority"), authority_init())
            .expect("authority");
    let constraints = worker_constraints();
    let issued = authority
        .create_token(constraints.clone(), Duration::from_secs(1))
        .expect("token");
    let worker = WorkerEnrollment::generate("worker-b", "sbproxy-mesh").expect("worker");
    std::thread::sleep(Duration::from_millis(1_100));

    let error = authority
        .enroll(worker_request(issued.into_token(), &worker, &constraints))
        .expect_err("expired token denied");
    assert_eq!(
        error.token_rejection(),
        Some(EnrollmentTokenRejection::Expired)
    );
}

#[test]
fn concurrent_enrollment_consumes_token_exactly_once() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority = Arc::new(
        EnrollmentAuthority::initialize(temp.path().join("authority"), authority_init())
            .expect("authority"),
    );
    let constraints = worker_constraints();
    let issued = authority
        .create_token(constraints.clone(), Duration::from_secs(300))
        .expect("token");
    let worker = WorkerEnrollment::generate("worker-b", "sbproxy-mesh").expect("worker");
    let request = worker_request(issued.into_token(), &worker, &constraints);
    let barrier = Arc::new(Barrier::new(3));

    let attempts = (0..2)
        .map(|_| {
            let authority = Arc::clone(&authority);
            let barrier = Arc::clone(&barrier);
            let request = request.clone();
            std::thread::spawn(move || {
                barrier.wait();
                authority.enroll(request)
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = attempts
        .into_iter()
        .map(|attempt| attempt.join().expect("enrollment thread"))
        .collect::<Vec<_>>();

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| result
                .as_ref()
                .err()
                .and_then(|error| error.token_rejection())
                == Some(EnrollmentTokenRejection::Consumed))
            .count(),
        1
    );
}
