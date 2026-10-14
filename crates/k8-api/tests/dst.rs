// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Wave-0 Deterministic Simulation Testing (DST) harness for `k8-api`.
//!
//! Exercises 100 seeds × 250 steps over a seeded `SplitMix64` PRNG and virtual monotonic clock
//! (`now_ms`), verifying resource quota conservation, PodSecurity `restricted` auditing, and
//! $3f + 1$ BFT jury quorum invariants after every transition.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use k8_api::{
    audit_pod_spec_restricted, restricted_container_security_context,
    restricted_pod_security_context, CpuQuantity, JuryError, JuryQuorum, JuryVote, MemoryQuantity,
    ResourceQuotaSpec, ResourceRequest, ResourceUsage, VerdictOutcome,
};
use k8s_openapi::api::core::v1::{Container, PodSpec};
use std::collections::{BTreeMap, BTreeSet};

/// Deterministic `SplitMix64` pseudo-random number generator.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn range(&mut self, upper: u64) -> u64 {
        if upper <= 1 {
            0
        } else {
            self.next_u64() % upper
        }
    }
}

#[test]
fn dst_resource_quota_and_bft_jury_invariants_100_seeds() {
    let roster: BTreeSet<String> = ["arb-0", "arb-1", "arb-2", "arb-3"]
        .into_iter()
        .map(String::from)
        .collect();

    let quota = ResourceQuotaSpec {
        max_cpu: CpuQuantity::from_millicores(8_000),
        max_memory: MemoryQuantity::from_bytes(16 * 1024 * 1024 * 1024),
        max_gpu: 4,
        max_pods: 8,
    };

    for seed in 1_u64..=100 {
        let mut rng = SplitMix64::new(seed);
        let mut now_ms: u64 = 1_700_000_000_000;
        let mut usage = ResourceUsage::default();
        let mut active_workloads: BTreeMap<u64, (ResourceRequest, JuryQuorum)> = BTreeMap::new();
        let mut next_id: u64 = 1;

        for _step in 0..250 {
            now_ms = now_ms.saturating_add(10 + rng.range(500));
            let action = rng.range(4);

            match action {
                0 => {
                    // Attempt to admit a new sandboxed workload
                    let cpu_m = (1 + rng.range(4)) * 500;
                    let mem_b = (1 + rng.range(4)) * 512 * 1024 * 1024;
                    let gpu = rng.range(2) as u32;
                    let req = ResourceRequest {
                        cpu: CpuQuantity::from_millicores(cpu_m),
                        memory: MemoryQuantity::from_bytes(mem_b),
                        gpu,
                    };

                    let pod_spec = PodSpec {
                        automount_service_account_token: Some(false),
                        security_context: Some(restricted_pod_security_context()),
                        containers: vec![Container {
                            name: "agent".to_string(),
                            security_context: Some(restricted_container_security_context()),
                            ..Default::default()
                        }],
                        ..Default::default()
                    };
                    assert!(
                        audit_pod_spec_restricted(&pod_spec).is_ok(),
                        "seed={seed}: restricted pod spec must always pass security audit"
                    );

                    if let Ok(next_usage) = quota.admit(&usage, &req) {
                        usage = next_usage;
                        let wid = next_id;
                        next_id += 1;
                        let quorum = JuryQuorum::new(format!("aw-{wid}"), 1, 1, roster.clone())
                            .expect("valid 4-arbiter BFT quorum");
                        active_workloads.insert(wid, (req, quorum));
                    }
                }
                1 => {
                    // Cast an honest or Byzantine vote on an active workload
                    if !active_workloads.is_empty() {
                        let keys: Vec<u64> = active_workloads.keys().copied().collect();
                        let idx = rng.range(keys.len() as u64) as usize;
                        let wid = keys[idx];
                        let (_, quorum) = active_workloads.get_mut(&wid).expect("workload exists");

                        let arb_idx = rng.range(4);
                        let arbiter_id = format!("arb-{arb_idx}");
                        // Arbiter 3 may attempt Byzantine equivocation; arbiters 0..=2 are honest
                        let (outcome, digest) = if arb_idx == 3 && rng.range(2) == 1 {
                            (VerdictOutcome::Reject, "sha256:bad".to_string())
                        } else {
                            (VerdictOutcome::Approve, "sha256:good".to_string())
                        };

                        let vote = JuryVote {
                            workload_id: format!("aw-{wid}"),
                            round: 1,
                            arbiter_id: arbiter_id.clone(),
                            outcome,
                            artifact_digest: digest,
                            timestamp_ms: now_ms,
                        };

                        match quorum.record_vote(vote) {
                            Ok(Some(receipt)) => {
                                assert!(
                                    receipt.signers.len() >= quorum.quorum_threshold(),
                                    "seed={seed}: receipt must have >= 2f+1 signers"
                                );
                                assert_eq!(
                                    receipt.outcome,
                                    VerdictOutcome::Approve,
                                    "seed={seed}: honest supermajority only approves sha256:good"
                                );
                            }
                            Ok(None) => {}
                            Err(JuryError::EquivocationDetected(id, _)) => {
                                assert_eq!(id, "arb-3", "seed={seed}: only arb-3 equivocates");
                            }
                            Err(other) => {
                                unreachable!("seed={seed}: unexpected jury error: {other}")
                            }
                        }
                    }
                }
                _ => {
                    // Release a completed workload and verify resource conservation
                    if !active_workloads.is_empty() {
                        let keys: Vec<u64> = active_workloads.keys().copied().collect();
                        let idx = rng.range(keys.len() as u64) as usize;
                        let wid = keys[idx];
                        let (req, _) = active_workloads.remove(&wid).expect("remove workload");
                        usage = quota.release(&usage, &req).expect("release must succeed");
                    }
                }
            }

            // Invariant 1: Exact conservation of CPU, memory, GPU, and pod count
            let expected_pods = active_workloads.len() as u32;
            let expected_cpu: u64 = active_workloads
                .values()
                .map(|(r, _)| r.cpu.millicores())
                .sum();
            let expected_mem: u64 = active_workloads
                .values()
                .map(|(r, _)| r.memory.bytes())
                .sum();
            let expected_gpu: u32 = active_workloads.values().map(|(r, _)| r.gpu).sum();

            assert_eq!(usage.pods, expected_pods, "seed={seed}: pod count drift");
            assert_eq!(
                usage.cpu.millicores(),
                expected_cpu,
                "seed={seed}: cpu millicores drift"
            );
            assert_eq!(
                usage.memory.bytes(),
                expected_mem,
                "seed={seed}: memory bytes drift"
            );
            assert_eq!(usage.gpu, expected_gpu, "seed={seed}: gpu count drift");

            // Invariant 2: Quota ceilings are never violated
            assert!(usage.pods <= quota.max_pods);
            assert!(usage.cpu <= quota.max_cpu);
            assert!(usage.memory <= quota.max_memory);
            assert!(usage.gpu <= quota.max_gpu);
        }
    }
}

#[test]
fn dst_lifecycle_conditions_finalizers_and_network_policy_100_seeds() {
    use k8_api::{
        audit_network_policy_zero_trust, build_isolated_network_policy, ensure_cleanup_finalizer,
        find_condition, has_cleanup_finalizer, remove_cleanup_finalizer, upsert_condition,
        EgressRuleSpec, WorkloadCondition, CONDITION_ACCEPTED, CONDITION_DISPATCHED,
        CONDITION_JURY_VERIFIED, CONDITION_READY, CONDITION_SANDBOXED,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    let condition_types = [
        CONDITION_ACCEPTED,
        CONDITION_SANDBOXED,
        CONDITION_DISPATCHED,
        CONDITION_JURY_VERIFIED,
        CONDITION_READY,
    ];
    let statuses = ["False", "True", "Unknown"];

    for seed in 1_u64..=100 {
        let mut rng = SplitMix64::new(seed ^ 0xA5A5_5A5A_F0F0_0F0F);
        let mut now_sec: u64 = 1_700_000_000;
        let mut meta = ObjectMeta::default();
        let mut conditions: Vec<WorkloadCondition> = Vec::new();
        let mut expected_last_transition: BTreeMap<String, (String, String)> = BTreeMap::new();

        for step in 0..200 {
            now_sec = now_sec.saturating_add(1 + rng.range(60));
            let iso = format!("2026-10-14T00:00:{now_sec}Z");

            // 1. Exercise finalizer idempotence
            if rng.range(3) == 0 {
                let _ = ensure_cleanup_finalizer(&mut meta);
                assert!(has_cleanup_finalizer(&meta));
                // Calling ensure_cleanup_finalizer a second time is a no-op
                assert!(!ensure_cleanup_finalizer(&mut meta));
            } else if rng.range(5) == 0 {
                let _ = remove_cleanup_finalizer(&mut meta);
                assert!(!has_cleanup_finalizer(&meta));
                assert!(!remove_cleanup_finalizer(&mut meta));
            }

            // 2. Exercise condition transition monotonicity (SPEC-0002 Invariant 1)
            let ctype = condition_types[rng.range(condition_types.len() as u64) as usize];
            let status = statuses[rng.range(statuses.len() as u64) as usize];
            let reason = format!("Step{step}Reason");

            let prev = expected_last_transition.get(ctype).cloned();
            upsert_condition(
                &mut conditions,
                WorkloadCondition {
                    type_: ctype.to_string(),
                    status: status.to_string(),
                    reason: reason.clone(),
                    message: Some(format!("step={step}")),
                    last_transition_time: iso.clone(),
                },
            );

            let observed = find_condition(&conditions, ctype).expect("condition must exist");
            assert_eq!(observed.status, status);
            assert_eq!(observed.reason, reason);

            match prev {
                Some((prev_status, prev_ts)) if prev_status == status => {
                    assert_eq!(
                        observed.last_transition_time, prev_ts,
                        "seed={seed} step={step}: unchanged status must preserve last_transition_time"
                    );
                }
                _ => {
                    assert_eq!(
                        observed.last_transition_time, iso,
                        "seed={seed} step={step}: changed status must update last_transition_time"
                    );
                    expected_last_transition
                        .insert(ctype.to_string(), (status.to_string(), iso.clone()));
                }
            }

            // Conditions list must remain strictly sorted and deduplicated by `type_`
            for pair in conditions.windows(2) {
                assert!(
                    pair[0].type_ < pair[1].type_,
                    "seed={seed}: conditions must be strictly sorted and unique by type_"
                );
            }

            // 3. Exercise zero-trust NetworkPolicy synthesis & audit (SPEC-0002 Invariant 3)
            if step % 20 == 0 {
                let octet = 1 + rng.range(250);
                let egress = EgressRuleSpec {
                    allow_dns: rng.range(2) == 1,
                    allowed_cidrs: vec![format!("10.{octet}.0.0/16")],
                    allowed_tcp_ports: vec![443],
                };
                let netpol = build_isolated_network_policy(
                    &format!("agent-s{seed}"),
                    "default",
                    Some("researcher"),
                    Some(&egress),
                )
                .expect("valid isolated network policy");
                assert!(
                    audit_network_policy_zero_trust(&netpol).is_ok(),
                    "seed={seed}: synthesized NetworkPolicy must pass zero-trust audit"
                );
            }
        }
    }
}

#[test]
fn dst_rbac_quota_storage_and_admission_100_seeds() {
    use k8_api::{
        audit_pod_volumes, audit_role_least_privilege, audit_service_account_zero_trust,
        build_dedicated_service_account, build_scoped_role, build_scratch_volume_and_mount,
        evaluate_quota_admission, evaluate_workload_admission, AdmissionContext, AdmissionGate,
        AgentWorkload, AgentWorkloadSpec, EgressRuleSpec, IsolationProfile, NamespaceQuotaSpec,
        QuotaUsageSnapshot, ScopedRuleSpec, ScratchMedium, ScratchVolumeSpec,
        DEFAULT_KATA_MEMORY_OVERHEAD_BYTES, DEFAULT_QUOTA_WARN_PERMILLE,
    };

    let ns_quota = NamespaceQuotaSpec {
        max_cpu_millis: 16_000,
        max_memory_bytes: 32 * 1024 * 1024 * 1024,
        max_pods: 8,
        warn_threshold_permille: DEFAULT_QUOTA_WARN_PERMILLE,
    };

    for seed in 1_u64..=100 {
        let mut rng = SplitMix64::new(seed ^ 0x1357_9BDF_2468_ACE0);
        let mut usage = QuotaUsageSnapshot::default();
        let mut active: Vec<(u64, u64, IsolationProfile)> = Vec::new();

        for step in 0..150 {
            let action = rng.range(4);
            match action {
                0 => {
                    // Attempt to admit a workload through the full multi-gate admission engine
                    let cpu_m = (1 + rng.range(4)) * 1_000;
                    let mem_gi = 1 + rng.range(4);
                    let cpu_str = format!("{cpu_m}m");
                    let mem_str = format!("{mem_gi}Gi");
                    let profile = if rng.range(2) == 0 {
                        IsolationProfile::KataMicroVm
                    } else {
                        IsolationProfile::StandardRestricted
                    };

                    let spec = AgentWorkloadSpec {
                        image: "ghcr.io/unsigned-gg/agent:latest".to_string(),
                        cpu: Some(cpu_str.clone()),
                        memory: Some(mem_str.clone()),
                        isolation_profile: profile,
                        egress: Some(EgressRuleSpec {
                            allow_dns: true,
                            allowed_cidrs: vec!["10.42.0.0/16".to_string()],
                            allowed_tcp_ports: vec![443],
                        }),
                        scratch_volumes: vec![ScratchVolumeSpec {
                            name: "scratch-tmp".to_string(),
                            mount_path: "/tmp".to_string(),
                            size_limit: "64Mi".to_string(),
                            medium: ScratchMedium::Memory,
                        }],
                        rbac_rules: vec![ScopedRuleSpec {
                            api_group: String::new(),
                            resource: "configmaps".to_string(),
                            verbs: vec!["get".to_string()],
                            resource_names: vec![format!("cfg-{step}")],
                        }],
                        ..Default::default()
                    };

                    let (vol, mount) =
                        build_scratch_volume_and_mount(&spec.scratch_volumes[0]).expect("scratch");
                    let pod_spec = PodSpec {
                        automount_service_account_token: Some(false),
                        security_context: Some(restricted_pod_security_context()),
                        volumes: Some(vec![vol]),
                        containers: vec![Container {
                            name: "agent".to_string(),
                            security_context: Some(restricted_container_security_context()),
                            volume_mounts: Some(vec![mount]),
                            ..Default::default()
                        }],
                        ..Default::default()
                    };
                    assert!(audit_pod_volumes(&pod_spec).is_ok());

                    let ctx = AdmissionContext {
                        quota: Some((ns_quota.clone(), usage.clone())),
                        required_receipt: None,
                    };
                    let run_id = format!("agent-s{seed}-{step}");
                    let mut workload = AgentWorkload::new(&run_id, spec);
                    workload.metadata.namespace = Some("agent-ns".to_string());

                    let outcome1 = evaluate_workload_admission(&workload, &ctx);
                    let outcome2 = evaluate_workload_admission(&workload, &ctx);
                    // Invariant 4: Admission evaluation is deterministic
                    assert_eq!(outcome1, outcome2);

                    let quota_res =
                        evaluate_quota_admission(&ns_quota, &usage, 1, &cpu_str, &mem_str, profile);

                    assert_eq!(outcome1.allowed, quota_res.is_ok());
                    if let Ok(report) = quota_res {
                        usage = QuotaUsageSnapshot {
                            used_cpu_millis: report.projected_cpu_millis,
                            used_memory_bytes: report.projected_memory_bytes,
                            used_pods: report.projected_pods,
                        };
                        active.push((cpu_m, mem_gi * 1024 * 1024 * 1024, profile));
                    } else {
                        assert!(outcome1
                            .violations
                            .iter()
                            .any(|v| v.gate == AdmissionGate::NamespaceQuota));
                    }
                }
                1 => {
                    // Release a workload and verify Kata memory overhead conservation
                    if !active.is_empty() {
                        let idx = rng.range(active.len() as u64) as usize;
                        let (cpu_m, mem_bytes, profile) = active.swap_remove(idx);
                        let eff_mem = match profile {
                            IsolationProfile::KataMicroVm => {
                                mem_bytes.saturating_add(DEFAULT_KATA_MEMORY_OVERHEAD_BYTES)
                            }
                            IsolationProfile::StandardRestricted => mem_bytes,
                        };
                        usage.used_cpu_millis -= cpu_m;
                        usage.used_memory_bytes -= eff_mem;
                        usage.used_pods -= 1;
                    }
                }
                _ => {
                    // Exercise RBAC least-privilege builders and adversarial rejection
                    let sa = build_dedicated_service_account(
                        "agent-rbac",
                        "agent-ns",
                        BTreeMap::new(),
                        false,
                    )
                    .expect("sa");
                    assert!(audit_service_account_zero_trust(&sa).is_ok());

                    let role = build_scoped_role(
                        "agent-rbac",
                        "agent-ns",
                        BTreeMap::new(),
                        &[ScopedRuleSpec {
                            api_group: String::new(),
                            resource: "secrets".to_string(),
                            verbs: vec!["get".to_string()],
                            resource_names: vec!["named-secret".to_string()],
                        }],
                    )
                    .expect("scoped role");
                    assert!(audit_role_least_privilege(&role).is_ok());
                }
            }

            // Verify exact Kata overhead + container memory conservation
            let expected_pods = active.len() as u32;
            let expected_cpu: u64 = active.iter().map(|(c, _, _)| *c).sum();
            let expected_mem: u64 = active
                .iter()
                .map(|(_, m, p)| match p {
                    IsolationProfile::KataMicroVm => *m + DEFAULT_KATA_MEMORY_OVERHEAD_BYTES,
                    IsolationProfile::StandardRestricted => *m,
                })
                .sum();

            assert_eq!(usage.used_pods, expected_pods);
            assert_eq!(usage.used_cpu_millis, expected_cpu);
            assert_eq!(usage.used_memory_bytes, expected_mem);
            assert!(usage.used_pods <= ns_quota.max_pods);
            assert!(usage.used_cpu_millis <= ns_quota.max_cpu_millis);
            assert!(usage.used_memory_bytes <= ns_quota.max_memory_bytes);
        }
    }
}

#[test]
fn dst_lease_election_backoff_and_cluster_invariants_100_seeds() {
    use k8_api::{
        build_controller_lease, compute_requeue_delay_ms, evaluate_cluster_invariants,
        evaluate_lease_transition, BackoffPolicy, ClusterInventorySnapshot, IsolationProfile,
        K8sNodeSnapshot, LeaseDecision, LeaseStateSnapshot, ProviderNodeRecord,
        ScheduledPodFootprint, ServiceEndpointSnapshot, DEFAULT_KATA_MEMORY_OVERHEAD_BYTES,
    };

    let replicas = ["controller-0", "controller-1", "controller-2"];
    let policy = BackoffPolicy {
        base_delay_ms: 500,
        max_delay_ms: 60_000,
        max_exponent: 8,
        jitter_permille: 200,
    };

    for seed in 0..100_u64 {
        let mut rng = SplitMix64::new(seed ^ 0xCAFE_BABE_DEAD_BEEF);
        let mut now_ms: u64 = 1_700_000_000_000;
        let mut lease_state: Option<LeaseStateSnapshot> = None;
        let mut scheduled_pods: Vec<ScheduledPodFootprint> = Vec::new();

        for step in 0..160_u64 {
            // Advance virtual monotonic clock by 1s..=8s
            now_ms = now_ms.saturating_add(1_000 + rng.range(7_001));

            // Pick a starting replica permutation and let all 3 replicas attempt transition at `now_ms`
            let start_idx = rng.range(3) as usize;
            let mut leaders_at_tick = Vec::new();
            let prev_transitions = lease_state.as_ref().map_or(0, |s| s.lease_transitions);
            let prev_holder = lease_state.as_ref().and_then(|s| s.holder_identity.clone());

            for offset in 0..3_usize {
                let candidate = replicas[(start_idx + offset) % 3];
                let outcome = evaluate_lease_transition(
                    "k8-orchestrator-leader",
                    "agent-ns",
                    lease_state.as_ref(),
                    candidate,
                    now_ms,
                    15,
                )
                .expect("valid lease evaluation");

                // Update shared lease state when a transition mutates the lease
                if outcome.is_leader {
                    if let Some(prev) = &prev_holder {
                        if prev == candidate {
                            assert_eq!(outcome.decision, LeaseDecision::Renew);
                        }
                    }
                    lease_state = Some(outcome.next_state.clone());
                    let lease_obj =
                        build_controller_lease(&outcome.next_state).expect("build lease");
                    assert_eq!(
                        lease_obj
                            .spec
                            .as_ref()
                            .and_then(|s| s.holder_identity.as_deref()),
                        Some(candidate)
                    );
                } else {
                    assert!(matches!(outcome.decision, LeaseDecision::Standby { .. }));
                }
            }

            // Re-verify INV-0004-02: probing all 3 replicas at the exact same `now_ms` against the
            // settled state grants leadership (`is_leader == true`) to at most 1 replica.
            for &candidate in &replicas {
                let check = evaluate_lease_transition(
                    "k8-orchestrator-leader",
                    "agent-ns",
                    lease_state.as_ref(),
                    candidate,
                    now_ms,
                    15,
                )
                .expect("probe lease");
                if check.is_leader {
                    leaders_at_tick.push(candidate);
                }
            }
            assert_eq!(
                leaders_at_tick.len(),
                1,
                "INV-0004-02 violated: exactly one leader must hold the lease at now_ms={now_ms}"
            );
            let current_transitions = lease_state.as_ref().map_or(0, |s| s.lease_transitions);
            assert!(current_transitions >= prev_transitions);

            // Exercise deterministic exponential backoff
            let failure_count = rng.range(16) as u32;
            let d1 = compute_requeue_delay_ms(&policy, failure_count, seed ^ step);
            let d2 = compute_requeue_delay_ms(&policy, failure_count, seed ^ step);
            assert_eq!(d1, d2);
            assert!((policy.base_delay_ms..=policy.max_delay_ms).contains(&d1));

            // Mutate scheduled pods and audit cluster invariants
            if rng.range(2) == 0 && scheduled_pods.len() < 6 {
                let node_name = if rng.range(2) == 0 {
                    "cygnus-worker-01".to_string()
                } else {
                    "cygnus-worker-02".to_string()
                };
                let profile = if rng.range(2) == 0 {
                    IsolationProfile::KataMicroVm
                } else {
                    IsolationProfile::StandardRestricted
                };
                scheduled_pods.push(ScheduledPodFootprint {
                    name: format!("pod-{seed}-{step}"),
                    namespace: "agent-ns".to_string(),
                    node_name,
                    cpu_millis: 1_000,
                    memory_bytes: 1024 * 1024 * 1024,
                    isolation_profile: profile,
                });
            } else if !scheduled_pods.is_empty() {
                let idx = rng.range(scheduled_pods.len() as u64) as usize;
                scheduled_pods.swap_remove(idx);
            }

            let snapshot = ClusterInventorySnapshot {
                provider_nodes: vec![
                    ProviderNodeRecord {
                        provider_id: "hetzner://1001".to_string(),
                        expected_name: "cygnus-worker-01".to_string(),
                        require_kata_runtime: true,
                    },
                    ProviderNodeRecord {
                        provider_id: "hetzner://1002".to_string(),
                        expected_name: "cygnus-worker-02".to_string(),
                        require_kata_runtime: true,
                    },
                ],
                k8s_nodes: vec![
                    K8sNodeSnapshot {
                        name: "cygnus-worker-01".to_string(),
                        provider_id: Some("hetzner://1001".to_string()),
                        ready: true,
                        unschedulable: false,
                        allocatable_cpu_millis: 8_000,
                        allocatable_memory_bytes: 16 * 1024 * 1024 * 1024,
                        kata_runtime_capable: true,
                    },
                    K8sNodeSnapshot {
                        name: "cygnus-worker-02".to_string(),
                        provider_id: Some("hetzner://1002".to_string()),
                        ready: true,
                        unschedulable: false,
                        allocatable_cpu_millis: 8_000,
                        allocatable_memory_bytes: 16 * 1024 * 1024 * 1024,
                        kata_runtime_capable: true,
                    },
                ],
                scheduled_pods: scheduled_pods.clone(),
                services: vec![ServiceEndpointSnapshot {
                    name: "reverie".to_string(),
                    namespace: "agent-ns".to_string(),
                    service_type: "LoadBalancer".to_string(),
                    ready_endpoints: 2,
                }],
                kata_memory_overhead_bytes: None,
                memory_warn_permille: None,
            };

            let r1 = evaluate_cluster_invariants(&snapshot);
            let r2 = evaluate_cluster_invariants(&snapshot);
            // INV-0004-04: Deterministic report digest
            assert_eq!(r1, r2);
            assert!(r1.healthy);

            // INV-0004-03: Node Kata Memory Conservation
            for summary in &r1.node_summaries {
                let node_pods: Vec<_> = scheduled_pods
                    .iter()
                    .filter(|p| p.node_name == summary.node_name)
                    .collect();
                let expected_container_mem: u64 = node_pods.iter().map(|p| p.memory_bytes).sum();
                let expected_kata_count = node_pods
                    .iter()
                    .filter(|p| p.isolation_profile == IsolationProfile::KataMicroVm)
                    .count() as u32;
                let expected_effective = expected_container_mem
                    + u64::from(expected_kata_count) * DEFAULT_KATA_MEMORY_OVERHEAD_BYTES;
                assert_eq!(summary.kata_pod_count, expected_kata_count);
                assert_eq!(summary.effective_memory_bytes, expected_effective);
            }
        }
    }
}

#[test]
fn dst_node_drain_binpacking_pdb_and_immutable_drift_100_seeds() {
    use k8_api::{
        audit_pod_priority_and_grace_period, audit_pvc_mutation, audit_statefulset_immutable_drift,
        evaluate_node_drain, DrainBlockReason, DrainCandidatePod, DrainClusterContext,
        DriftRemediationStrategy, IsolationProfile, K8sNodeSnapshot, PdbBudgetSnapshot,
        PodEvictionAction, ScheduledPodFootprint, WorkloadPriorityTier,
        DEFAULT_KATA_MEMORY_OVERHEAD_BYTES, MAX_TERMINATION_GRACE_SECONDS,
    };
    use k8s_openapi::api::apps::v1::{StatefulSet, StatefulSetSpec};
    use k8s_openapi::api::core::v1::{
        PersistentVolumeClaim, PersistentVolumeClaimSpec, VolumeResourceRequirements,
    };
    use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    for seed in 0..100_u64 {
        let mut rng = SplitMix64::new(seed ^ 0x5005_d4a1_9c0d_e004);

        let nodes = vec![
            K8sNodeSnapshot {
                name: "cygnus-worker-01".to_string(),
                provider_id: Some("hetzner://1001".to_string()),
                ready: true,
                unschedulable: false,
                allocatable_cpu_millis: 8_000,
                allocatable_memory_bytes: 16 * 1024 * 1024 * 1024,
                kata_runtime_capable: true,
            },
            K8sNodeSnapshot {
                name: "cygnus-worker-02".to_string(),
                provider_id: Some("hetzner://1002".to_string()),
                ready: true,
                unschedulable: false,
                allocatable_cpu_millis: 8_000,
                allocatable_memory_bytes: 16 * 1024 * 1024 * 1024,
                kata_runtime_capable: true,
            },
            K8sNodeSnapshot {
                name: "cygnus-worker-03".to_string(),
                provider_id: Some("hetzner://1003".to_string()),
                ready: true,
                unschedulable: false,
                allocatable_cpu_millis: 4_000,
                allocatable_memory_bytes: 8 * 1024 * 1024 * 1024,
                kata_runtime_capable: false,
            },
        ];

        for step in 0..40_u64 {
            let pod_count = 1 + rng.range(8) as usize;
            let mut candidate_pods = Vec::with_capacity(pod_count);
            for i in 0..pod_count {
                let tier = match rng.range(4) {
                    0 => WorkloadPriorityTier::SpotScavenger,
                    1 => WorkloadPriorityTier::BatchResearch,
                    2 => WorkloadPriorityTier::InteractiveAgent,
                    _ => WorkloadPriorityTier::EstateCoordinator,
                };
                let profile = if rng.range(2) == 0 {
                    IsolationProfile::KataMicroVm
                } else {
                    IsolationProfile::StandardRestricted
                };
                let is_daemonset = rng.range(10) == 0;
                let has_unmanaged_local_storage = !is_daemonset && rng.range(12) == 0;
                let use_pdb = !is_daemonset && rng.range(3) == 0;

                candidate_pods.push(DrainCandidatePod {
                    name: format!("pod-{seed}-{step}-{i}"),
                    namespace: "agent-ns".to_string(),
                    priority_tier: tier,
                    isolation_profile: profile,
                    cpu_millis: 1_000 + rng.range(3) * 1_000,
                    memory_bytes: (1 + rng.range(3)) * 1024 * 1024 * 1024,
                    is_daemonset,
                    is_mirror_pod: false,
                    has_unmanaged_local_storage,
                    pdb_name: if use_pdb {
                        Some("agent-pdb".to_string())
                    } else {
                        None
                    },
                });
            }

            let allowed_disruptions = u32::try_from(rng.range(4)).expect("u32");
            let ctx = DrainClusterContext {
                target_node: "cygnus-worker-01".to_string(),
                nodes: nodes.clone(),
                existing_pods_on_other_nodes: vec![ScheduledPodFootprint {
                    name: "existing-02".to_string(),
                    namespace: "agent-ns".to_string(),
                    node_name: "cygnus-worker-02".to_string(),
                    cpu_millis: 1_000,
                    memory_bytes: 1024 * 1024 * 1024,
                    isolation_profile: IsolationProfile::KataMicroVm,
                }],
                drain_candidates: candidate_pods,
                pdbs: vec![PdbBudgetSnapshot {
                    name: "agent-pdb".to_string(),
                    namespace: "agent-ns".to_string(),
                    disruptions_allowed: allowed_disruptions,
                }],
                allow_local_storage_erasure: false,
                kata_memory_overhead_bytes: Some(DEFAULT_KATA_MEMORY_OVERHEAD_BYTES),
            };

            let r1 = evaluate_node_drain(&ctx);
            let r2 = evaluate_node_drain(&ctx);
            assert_eq!(r1, r2);
            assert_eq!(r1.safe_to_drain, r1.blocked_count == 0);

            // INV-0005-01: Destination node capacity & Kata capability conservation
            for dest in &r1.destination_summaries {
                let node_spec = nodes
                    .iter()
                    .find(|n| n.name == dest.node_name)
                    .expect("destination node exists");
                assert!(dest.post_drain_cpu_millis <= node_spec.allocatable_cpu_millis);
                assert!(
                    dest.post_drain_effective_memory_bytes <= node_spec.allocatable_memory_bytes
                );
            }

            // INV-0005-02: PDB disruption budget non-negativity
            let mut pdb_evictions = 0_u32;
            for dec in &r1.pod_decisions {
                if let PodEvictionAction::EvictAndReschedule {
                    destination_node, ..
                } = &dec.action
                {
                    let src_pod = ctx
                        .drain_candidates
                        .iter()
                        .find(|p| p.name == dec.pod_name)
                        .expect("candidate pod");
                    if src_pod.pdb_name.as_deref() == Some("agent-pdb") {
                        pdb_evictions += 1;
                    }
                    if src_pod.isolation_profile == IsolationProfile::KataMicroVm {
                        let node_spec = nodes
                            .iter()
                            .find(|n| &n.name == destination_node)
                            .expect("dest node");
                        assert!(node_spec.kata_runtime_capable);
                    }
                } else if let PodEvictionAction::Blocked {
                    reason: DrainBlockReason::UnmanagedLocalStorage,
                } = &dec.action
                {
                    assert!(!r1.safe_to_drain);
                }
            }
            assert!(pdb_evictions <= allowed_disruptions);

            // INV-0005-03: Immutable field drift soundness
            let live_sts = StatefulSet {
                metadata: ObjectMeta {
                    name: Some("reverie-db".to_string()),
                    ..Default::default()
                },
                spec: Some(StatefulSetSpec {
                    service_name: Some("reverie-headless".to_string()),
                    volume_claim_templates: Some(vec![PersistentVolumeClaim {
                        metadata: ObjectMeta {
                            name: Some("data".to_string()),
                            ..Default::default()
                        },
                        spec: Some(PersistentVolumeClaimSpec {
                            storage_class_name: Some("hcloud-volumes".to_string()),
                            resources: Some(VolumeResourceRequirements {
                                requests: Some(BTreeMap::from([(
                                    "storage".to_string(),
                                    Quantity("20Gi".to_string()),
                                )])),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let mut mutated_sts = live_sts.clone();
            mutated_sts
                .spec
                .as_mut()
                .unwrap()
                .volume_claim_templates
                .as_mut()
                .unwrap()[0]
                .spec
                .as_mut()
                .unwrap()
                .storage_class_name = Some("local-path".to_string());
            let sts_drift = audit_statefulset_immutable_drift(&live_sts, &mutated_sts);
            assert_eq!(
                sts_drift.strategy,
                DriftRemediationStrategy::RejectedForbiddenMutation
            );

            let live_pvc = live_sts
                .spec
                .as_ref()
                .unwrap()
                .volume_claim_templates
                .as_ref()
                .unwrap()[0]
                .clone();
            let mut shrunk_pvc = live_pvc.clone();
            shrunk_pvc
                .spec
                .as_mut()
                .unwrap()
                .resources
                .as_mut()
                .unwrap()
                .requests = Some(BTreeMap::from([(
                "storage".to_string(),
                Quantity("10Gi".to_string()),
            )]));
            assert_eq!(
                audit_pvc_mutation(&live_pvc, &shrunk_pvc).strategy,
                DriftRemediationStrategy::RejectedForbiddenMutation
            );

            // INV-0005-04: Priority & Termination Grace Containment
            let bad_grace_pod = PodSpec {
                priority_class_name: Some("k8-interactive-agent".to_string()),
                termination_grace_period_seconds: Some(
                    i64::try_from(MAX_TERMINATION_GRACE_SECONDS + 1 + rng.range(500)).unwrap(),
                ),
                ..Default::default()
            };
            assert!(audit_pod_priority_and_grace_period(
                &bad_grace_pod,
                MAX_TERMINATION_GRACE_SECONDS
            )
            .is_err());
        }
    }
}

#[test]
fn dst_immutable_configs_secret_hygiene_probes_and_rollout_quorum_100_seeds() {
    use k8_api::{
        audit_pod_probes, audit_pod_secret_and_token_hygiene, build_http_get_probe,
        build_immutable_config_map, build_immutable_secret, build_projected_token_volume,
        compute_kv_content_hash, evaluate_rollout_quorum, BoundTokenProjectionSpec, HttpProbeSpec,
        ProbeError, RolloutQuorumSpec, SecretHygieneError,
    };
    use k8s_openapi::api::core::v1::{
        Container, EnvVar, EnvVarSource, ExecAction, Probe, SecretKeySelector, VolumeMount,
    };

    for seed in 0..100_u64 {
        let mut rng = SplitMix64::new(seed ^ 0x6006_e5b2_ad1e_f005);

        for step in 0..40_u64 {
            // INV-0006-01: Content-Addressed Immutable Config Determinism
            let mut entries_a = BTreeMap::new();
            let mut entries_b = BTreeMap::new();
            let key_count = 1 + rng.range(5);
            for k in 0..key_count {
                let key = format!("CONFIG_KEY_{k}");
                let val = format!("val-{seed}-{step}-{}", rng.range(10_000));
                entries_a.insert(key.clone(), val.clone());
                entries_b.insert(key, val);
            }
            let h1 = compute_kv_content_hash(&entries_a);
            let h2 = compute_kv_content_hash(&entries_b);
            assert_eq!(h1, h2);
            assert_eq!(h1.len(), 8);

            let cm1 = build_immutable_config_map("agent-cfg", "agent-ns", &entries_a).expect("cm1");
            let cm2 = build_immutable_config_map("agent-cfg", "agent-ns", &entries_b).expect("cm2");
            assert_eq!(cm1, cm2);
            assert_eq!(cm1.immutable, Some(true));
            assert_eq!(
                cm1.metadata.name.as_deref(),
                Some(format!("agent-cfg-{h1}").as_str())
            );

            let sec1 = build_immutable_secret("agent-sec", "agent-ns", &entries_a).expect("sec1");
            assert_eq!(sec1.immutable, Some(true));
            assert_eq!(
                sec1.metadata.name.as_deref(),
                Some(format!("agent-sec-{h1}").as_str())
            );

            let mut mutated_entries = entries_a.clone();
            mutated_entries.insert("EXTRA_KEY".to_string(), "mutated".to_string());
            let cm_mut = build_immutable_config_map("agent-cfg", "agent-ns", &mutated_entries)
                .expect("cm_mut");
            assert_ne!(cm1.metadata.name, cm_mut.metadata.name);

            // Reject empty secret value body
            let mut empty_sec_entries = entries_a.clone();
            empty_sec_entries.insert("API_TOKEN".to_string(), "   ".to_string());
            assert!(matches!(
                build_immutable_secret("agent-sec", "agent-ns", &empty_sec_entries),
                Err(SecretHygieneError::EmptySecretValueBody(_))
            ));

            // INV-0006-02: Zero Plaintext Secret Env Vars & Bounded Token Expiry
            let ttl = 600 + rng.range(3001) as i64;
            let (tok_vol, tok_mount) = build_projected_token_volume(&BoundTokenProjectionSpec {
                volume_name: "vault-token".to_string(),
                mount_path: "/var/run/secrets/tokens".to_string(),
                token_rel_path: "token".to_string(),
                audience: "openbao.unsigned.gg".to_string(),
                expiration_seconds: ttl,
            })
            .expect("valid projected token");

            let good_pod = PodSpec {
                volumes: Some(vec![tok_vol]),
                containers: vec![Container {
                    name: "agent".to_string(),
                    env: Some(vec![EnvVar {
                        name: "OPENBAO_API_TOKEN".to_string(),
                        value: None,
                        value_from: Some(EnvVarSource {
                            secret_key_ref: Some(SecretKeySelector {
                                name: "agent-sec".to_string(),
                                key: "API_TOKEN".to_string(),
                                optional: Some(false),
                            }),
                            ..Default::default()
                        }),
                    }]),
                    volume_mounts: Some(vec![tok_mount]),
                    ..Default::default()
                }],
                ..Default::default()
            };
            assert!(audit_pod_secret_and_token_hygiene(&good_pod).is_ok());

            let bad_pod = PodSpec {
                containers: vec![Container {
                    name: "agent".to_string(),
                    env: Some(vec![EnvVar {
                        name: "LITELLM_API_KEY".to_string(),
                        value: Some("sk-plaintext-leak".to_string()),
                        value_from: None,
                    }]),
                    ..Default::default()
                }],
                ..Default::default()
            };
            assert!(matches!(
                audit_pod_secret_and_token_hygiene(&bad_pod),
                Err(SecretHygieneError::PlaintextSensitiveEnvVar { .. })
            ));

            // INV-0006-03: Probe Timing & Shell-Free Containment
            let period_seconds = 5 + rng.range(15) as i32;
            let timeout_seconds = 1 + rng.range(period_seconds as u64) as i32;
            let liveness_threshold = 2 + rng.range(4) as i32;
            let startup_threshold = liveness_threshold + 1 + rng.range(10) as i32;

            let liveness_probe = build_http_get_probe(&HttpProbeSpec {
                path: "/healthz".to_string(),
                port: 8080,
                initial_delay_seconds: 0,
                period_seconds,
                timeout_seconds,
                failure_threshold: liveness_threshold,
                success_threshold: 1,
            })
            .expect("valid liveness");
            let readiness_probe = build_http_get_probe(&HttpProbeSpec {
                path: "/readyz".to_string(),
                port: 8080,
                initial_delay_seconds: 0,
                period_seconds,
                timeout_seconds,
                failure_threshold: 3,
                success_threshold: 1,
            })
            .expect("valid readiness");
            let startup_probe = build_http_get_probe(&HttpProbeSpec {
                path: "/healthz".to_string(),
                port: 8080,
                initial_delay_seconds: 0,
                period_seconds,
                timeout_seconds,
                failure_threshold: startup_threshold,
                success_threshold: 1,
            })
            .expect("valid startup");

            let probed_pod = PodSpec {
                containers: vec![Container {
                    name: "agent".to_string(),
                    liveness_probe: Some(liveness_probe),
                    readiness_probe: Some(readiness_probe),
                    startup_probe: Some(startup_probe),
                    volume_mounts: Some(vec![VolumeMount {
                        name: "tmp".to_string(),
                        mount_path: "/tmp".to_string(),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }],
                ..Default::default()
            };
            assert!(audit_pod_probes(&probed_pod).is_ok());

            let exec_probe_pod = PodSpec {
                containers: vec![Container {
                    name: "agent".to_string(),
                    liveness_probe: Some(Probe {
                        exec: Some(ExecAction {
                            command: Some(vec!["sh".to_string(), "-c".to_string()]),
                        }),
                        period_seconds: Some(10),
                        timeout_seconds: Some(2),
                        failure_threshold: Some(3),
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            };
            assert!(matches!(
                audit_pod_probes(&exec_probe_pod),
                Err(ProbeError::ForbiddenShellExecProbe { .. })
            ));

            // INV-0006-04: Rollout vs. PDB Quorum Conservation
            let replicas = 2 + rng.range(10) as u32;
            let max_unavailable = rng.range(replicas as u64) as u32;
            let max_surge = if max_unavailable == 0 {
                1 + rng.range(3) as u32
            } else {
                rng.range(3) as u32
            };
            let pdb_min_available = rng.range(u64::from(replicas + 1)) as u32;

            let q1 = evaluate_rollout_quorum(&RolloutQuorumSpec {
                workload_id: format!("agent-ns/svc-{seed}-{step}"),
                replicas,
                max_unavailable,
                max_surge,
                pdb_min_available,
            });
            let q2 = evaluate_rollout_quorum(&RolloutQuorumSpec {
                workload_id: format!("agent-ns/svc-{seed}-{step}"),
                replicas,
                max_unavailable,
                max_surge,
                pdb_min_available,
            });
            assert_eq!(q1, q2);
            let expected_safe = replicas.saturating_sub(max_unavailable) >= pdb_min_available
                && (max_unavailable > 0 || max_surge > 0);
            assert_eq!(q1.is_ok(), expected_safe);
        }
    }
}
