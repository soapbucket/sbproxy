use std::collections::BTreeMap;
use std::time::Duration;

use sbproxy_model_host::{
    plan_fit_kv_with_margin, AdmissionGate, AdmissionReason, DeviceResidencySet, GpuDescriptor,
    GpuVendor, MemoryEstimate, ModelMetadata, PriorityClass, ResidencyProtection,
};

const GIB: u64 = 1024 * 1024 * 1024;

fn gpu(index: u32, free_gib: u64) -> GpuDescriptor {
    GpuDescriptor {
        index,
        vendor: GpuVendor::Nvidia,
        name: format!("GPU {index}"),
        total_vram_bytes: free_gib * GIB,
        free_vram_bytes: free_gib * GIB,
        compute_capability: Some((8, 9)),
        supports_fp8: true,
        mem_bandwidth_gbps: None,
    }
}

#[test]
fn fit_reports_a_complete_memory_breakdown_for_the_selected_device() {
    let metadata = ModelMetadata {
        params: 1_000_000_000,
        layers: 24,
        kv_heads: 8,
        head_dim: 128,
        max_context: 8192,
    };
    let plan = plan_fit_kv_with_margin(
        &gpu(3, 24),
        &metadata,
        &["Q4_K_M".to_string()],
        4096,
        1.15,
        0.10,
        None,
    )
    .unwrap();

    assert_eq!(plan.memory.device_index, 3);
    assert!(plan.memory.weight_bytes > 0);
    assert!(plan.memory.kv_bytes > 0);
    assert!(plan.memory.runtime_overhead_bytes > 0);
    assert!(plan.memory.safety_margin_bytes > 0);
    assert_eq!(
        plan.memory.total_bytes,
        plan.memory.weight_bytes
            + plan.memory.kv_bytes
            + plan.memory.runtime_overhead_bytes
            + plan.memory.safety_margin_bytes
    );
    assert_eq!(plan.estimated_vram_bytes, plan.memory.total_bytes);
}

#[test]
fn residency_is_per_device_and_never_evicts_protected_generations() {
    let mut residency = DeviceResidencySet::new(BTreeMap::from([(0, 8 * GIB), (1, 24 * GIB)]));
    let estimate = |device_index, total_bytes| MemoryEstimate {
        device_index,
        weight_bytes: total_bytes,
        kv_bytes: 0,
        runtime_overhead_bytes: 0,
        safety_margin_bytes: 0,
        total_bytes,
    };

    let too_large = residency
        .reserve(
            "large-on-small",
            1,
            estimate(0, 10 * GIB),
            ResidencyProtection::default(),
            1,
        )
        .unwrap_err();
    assert_eq!(too_large.reason, AdmissionReason::InsufficientCapacity);
    residency
        .reserve(
            "large",
            1,
            estimate(1, 10 * GIB),
            ResidencyProtection::default(),
            1,
        )
        .unwrap();
    residency
        .reserve(
            "small-device",
            1,
            estimate(0, 6 * GIB),
            ResidencyProtection {
                active: true,
                ..ResidencyProtection::default()
            },
            1,
        )
        .unwrap();
    let blocked = residency
        .reserve(
            "other-small",
            1,
            estimate(0, 4 * GIB),
            ResidencyProtection::default(),
            2,
        )
        .unwrap_err();
    assert_eq!(blocked.reason, AdmissionReason::InsufficientCapacity);
    assert!(residency.contains(0, "small-device", 1));
    assert!(residency.contains(1, "large", 1));

    residency.update_protection(0, "small-device", 1, ResidencyProtection::default());
    let admitted = residency
        .reserve(
            "other-small",
            1,
            estimate(0, 4 * GIB),
            ResidencyProtection::default(),
            3,
        )
        .unwrap();
    assert_eq!(admitted.evicted, vec!["small-device".to_string()]);
    assert!(residency.contains(1, "large", 1));

    let duplicate_generation = residency
        .reserve(
            "large",
            1,
            estimate(0, 1),
            ResidencyProtection::default(),
            4,
        )
        .unwrap_err();
    assert_eq!(
        duplicate_generation.reason,
        AdmissionReason::InsufficientCapacity
    );
    assert!(residency.contains(1, "large", 1));
    assert!(!residency.contains(0, "large", 1));
}

#[tokio::test]
async fn priority_queue_is_fifo_within_class_and_bounded() {
    let gate = AdmissionGate::new(1, 3, Duration::from_secs(30)).unwrap();
    let active = gate.admit(PriorityClass::Standard).await.unwrap();
    let (order_tx, mut order_rx) = tokio::sync::mpsc::unbounded_channel();

    let spawn = |name: &'static str,
                 priority: PriorityClass,
                 gate: AdmissionGate,
                 tx: tokio::sync::mpsc::UnboundedSender<&'static str>| {
        tokio::spawn(async move {
            let permit = gate.admit(priority).await.unwrap();
            tx.send(name).unwrap();
            drop(permit);
        })
    };
    let batch = spawn(
        "batch",
        PriorityClass::Batch,
        gate.clone(),
        order_tx.clone(),
    );
    tokio::task::yield_now().await;
    let standard = spawn(
        "standard",
        PriorityClass::Standard,
        gate.clone(),
        order_tx.clone(),
    );
    tokio::task::yield_now().await;
    let interactive = spawn(
        "interactive",
        PriorityClass::Interactive,
        gate.clone(),
        order_tx,
    );
    tokio::task::yield_now().await;
    assert_eq!(gate.counts().queued, 3);
    drop(active);

    assert_eq!(order_rx.recv().await.unwrap(), "interactive");
    assert_eq!(order_rx.recv().await.unwrap(), "standard");
    assert_eq!(order_rx.recv().await.unwrap(), "batch");
    batch.await.unwrap();
    standard.await.unwrap();
    interactive.await.unwrap();
    assert_eq!((gate.counts().active, gate.counts().queued), (0, 0));

    let bounded = AdmissionGate::new(1, 1, Duration::from_secs(30)).unwrap();
    let active = bounded.admit(PriorityClass::Standard).await.unwrap();
    let first_gate = bounded.clone();
    let first = tokio::spawn(async move { first_gate.admit(PriorityClass::Standard).await });
    tokio::task::yield_now().await;
    let rejection = bounded.admit(PriorityClass::Standard).await.unwrap_err();
    assert_eq!(rejection.reason, AdmissionReason::QueueFull);
    first.abort();
    tokio::task::yield_now().await;
    assert_eq!(bounded.counts().queued, 0, "cancelled waiters are removed");
    drop(active);
}

#[tokio::test(start_paused = true)]
async fn timeout_drain_and_keep_alive_account_for_the_full_permit_lifecycle() {
    let gate = AdmissionGate::new(1, 2, Duration::from_secs(5)).unwrap();
    gate.mark_ready_idle();
    let active = gate.admit(PriorityClass::Standard).await.unwrap();
    tokio::time::advance(Duration::from_secs(60)).await;
    assert!(!gate.is_idle_expired(Duration::from_secs(30)));

    let timeout_gate = gate.clone();
    let timeout = tokio::spawn(async move { timeout_gate.admit(PriorityClass::Batch).await });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(5)).await;
    assert_eq!(
        timeout.await.unwrap().unwrap_err().reason,
        AdmissionReason::QueueTimeout
    );
    assert_eq!(gate.counts().queued, 0);

    let queued_gate = gate.clone();
    let queued = tokio::spawn(async move { queued_gate.admit(PriorityClass::Interactive).await });
    tokio::task::yield_now().await;
    let drain_gate = gate.clone();
    let drain = tokio::spawn(async move { drain_gate.drain(Duration::from_secs(10)).await });
    tokio::task::yield_now().await;
    assert_eq!(
        queued.await.unwrap().unwrap_err().reason,
        AdmissionReason::Draining
    );
    assert!(!drain.is_finished());
    drop(active);
    let report = drain.await.unwrap();
    assert_eq!(report.cancelled_queued, 1);
    assert_eq!(report.remaining_active, 0);
    assert!(!report.timed_out);

    gate.resume();
    let permit = gate.admit(PriorityClass::Standard).await.unwrap();
    tokio::time::advance(Duration::from_secs(100)).await;
    assert!(!gate.is_idle_expired(Duration::from_secs(30)));
    drop(permit);
    tokio::time::advance(Duration::from_secs(29)).await;
    assert!(!gate.is_idle_expired(Duration::from_secs(30)));
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(gate.is_idle_expired(Duration::from_secs(30)));

    assert!(
        gate.begin_idle_drain_if_expired_at(tokio::time::Instant::now(), Duration::from_secs(30))
    );
    assert_eq!(
        gate.admit(PriorityClass::Standard)
            .await
            .unwrap_err()
            .reason,
        AdmissionReason::Draining
    );
}
