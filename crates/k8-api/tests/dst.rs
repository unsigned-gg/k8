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
