// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `drain`: Pure zero-I/O Kubernetes Node Cordon/Drain & Eviction Safety Planner (`SPEC-0005`).
//!
//! Enforces the estate safety rule ("Never drain a node without confirming workloads can move")
//! by verifying `PodDisruptionBudget` (`policy/v1`) headroom and First-Fit Decreasing (FFD)
//! destination capacity across surviving `ready && !unschedulable` nodes (accounting for
//! `kata` runtime requirements and the `256Mi` per-pod Kata hypervisor memory overhead).

use crate::invariants::{K8sNodeSnapshot, ScheduledPodFootprint};
use crate::priority::WorkloadPriorityTier;
use crate::quota::DEFAULT_KATA_MEMORY_OVERHEAD_BYTES;
use crate::scheduling::IsolationProfile;
use crate::selector::{validate_dns1123_label, LabelError};
use k8s_openapi::api::core::v1::Node;
use k8s_openapi::api::policy::v1::Eviction;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{DeleteOptions, ObjectMeta};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Snapshot of a pod currently scheduled on the target node to be drained (`SPEC-0005`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DrainCandidatePod {
    /// Pod name (`metadata.name`).
    pub name: String,
    /// Pod namespace (`metadata.namespace`).
    pub namespace: String,
    /// CPU request in millicores.
    pub cpu_millis: u64,
    /// Container memory request in bytes (before Kata hypervisor overhead).
    pub memory_bytes: u64,
    /// Workload isolation profile (`StandardRestricted` or `KataMicroVm`).
    #[serde(default)]
    pub isolation_profile: IsolationProfile,
    /// Workload priority tier used for deterministic eviction ordering.
    #[serde(default)]
    pub priority_tier: WorkloadPriorityTier,
    /// `true` if owned by a `DaemonSet` (`apps/v1`).
    #[serde(default)]
    pub is_daemonset: bool,
    /// `true` if static kubelet mirror pod (`kubernetes.io/config.mirror`).
    #[serde(default)]
    pub is_mirror_pod: bool,
    /// `true` if pod uses unmanaged local storage (`hostPath` or non-ephemeral local dir).
    #[serde(default)]
    pub has_unmanaged_local_storage: bool,
    /// Optional matching `PodDisruptionBudget` name in the same namespace.
    #[serde(default)]
    pub pdb_name: Option<String>,
}

/// Snapshot of a `policy/v1` `PodDisruptionBudget` status (`SPEC-0005`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PdbBudgetSnapshot {
    /// PDB `metadata.name`.
    pub name: String,
    /// PDB `metadata.namespace`.
    pub namespace: String,
    /// Current `status.disruptionsAllowed`.
    pub disruptions_allowed: u32,
}

/// Input snapshot for evaluating a node cordon and drain plan (`SPEC-0005`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DrainClusterContext {
    /// Name of the Kubernetes node being cordoned and drained.
    pub target_node: String,
    /// All Kubernetes nodes in the cluster (including `target_node` and surviving nodes).
    #[serde(default)]
    pub nodes: Vec<K8sNodeSnapshot>,
    /// Pods currently scheduled on *other* nodes in the cluster.
    #[serde(default)]
    pub existing_pods_on_other_nodes: Vec<ScheduledPodFootprint>,
    /// Candidate pods currently running on `target_node`.
    #[serde(default)]
    pub drain_candidates: Vec<DrainCandidatePod>,
    /// Active `PodDisruptionBudget` status snapshots.
    #[serde(default)]
    pub pdbs: Vec<PdbBudgetSnapshot>,
    /// Whether pods with local scratch storage may be evicted.
    #[serde(default)]
    pub allow_local_storage_erasure: bool,
    /// Optional override for Kata hypervisor memory overhead per pod (defaults to `256Mi`).
    #[serde(default)]
    pub kata_memory_overhead_bytes: Option<u64>,
}

/// Reason why a pod (or the target node) blocked the drain plan (`SPEC-0005`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum DrainBlockReason {
    /// The target node name does not exist in `ctx.nodes`.
    TargetNodeNotFound(String),
    /// Pod uses unmanaged local storage and `allow_local_storage_erasure` is `false`.
    UnmanagedLocalStorage,
    /// Evicting the pod would violate its `PodDisruptionBudget` (`disruptionsAllowed == 0`).
    PdbDisruptionBudgetExhausted {
        /// Name of the exhausted `PodDisruptionBudget`.
        pdb_name: String,
    },
    /// No surviving `ready && !unschedulable` node has sufficient CPU/memory or `kata` capability.
    NoDestinationCapacity {
        /// Required CPU in millicores.
        required_cpu_millis: u64,
        /// Required effective memory in bytes (including Kata overhead if `requires_kata`).
        required_effective_memory_bytes: u64,
        /// Whether the pod requires `kata` runtime support on the destination node.
        requires_kata: bool,
    },
}

/// Planned action for an individual pod on the drained node (`SPEC-0005`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum PodEvictionAction {
    /// Pod is safe to evict via `policy/v1` `Eviction` and has reserved capacity on `destination_node`.
    EvictAndReschedule {
        /// Surviving node where the pod fits under FFD bin-packing.
        destination_node: String,
        /// Effective memory footprint in bytes (including Kata overhead when applicable).
        effective_memory_bytes: u64,
    },
    /// Static mirror pod managed by the node kubelet; skipped during API eviction.
    SkippedMirrorPod,
    /// `DaemonSet`-managed pod; remains on the node during standard drain.
    SkippedDaemonSetPod,
    /// Pod cannot be safely evicted or rescheduled.
    Blocked {
        /// Blocking reason.
        reason: DrainBlockReason,
    },
}

/// Per-pod eviction decision emitted by [`evaluate_node_drain`] (`SPEC-0005`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PodDrainDecision {
    /// Pod namespace.
    pub namespace: String,
    /// Pod name.
    pub pod_name: String,
    /// Planned action (`EvictAndReschedule`, `Skipped*`, or `Blocked`).
    pub action: PodEvictionAction,
}

/// Post-drain capacity summary for a surviving destination node (`SPEC-0005`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct NodePlacementSummary {
    /// Surviving destination node name.
    pub node_name: String,
    /// Node allocatable CPU in millicores.
    pub allocatable_cpu_millis: u64,
    /// Total requested CPU in millicores after placing evicted pods.
    pub post_drain_cpu_millis: u64,
    /// Node allocatable memory in bytes.
    pub allocatable_memory_bytes: u64,
    /// Total effective memory in bytes (including Kata overhead) after placing evicted pods.
    pub post_drain_effective_memory_bytes: u64,
    /// Number of evicted pods assigned to this destination node during the drain simulation.
    pub newly_placed_pods: u32,
}

/// Deterministic node cordon and drain evaluation report (`SPEC-0005`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DrainPlanReport {
    /// Target node evaluated for drain.
    pub target_node: String,
    /// `true` iff the target node exists and `blocked_count == 0` (`INV-0005-01`).
    pub safe_to_drain: bool,
    /// Count of pods planned for `EvictAndReschedule`.
    pub evicted_count: usize,
    /// Count of mirror or `DaemonSet` pods skipped.
    pub skipped_count: usize,
    /// Count of blocked pods (or target node missing).
    pub blocked_count: usize,
    /// Ordered per-pod decisions sorted by `(namespace, pod_name)`.
    pub pod_decisions: Vec<PodDrainDecision>,
    /// Post-drain capacity summaries for all surviving candidate destination nodes.
    pub destination_summaries: Vec<NodePlacementSummary>,
    /// Deterministic 64-bit FNV-1a hex digest over the drain plan.
    pub plan_digest: String,
}

#[derive(Debug, Clone)]
struct MutableNodeBin {
    node_name: String,
    kata_capable: bool,
    allocatable_cpu_millis: u64,
    used_cpu_millis: u64,
    allocatable_memory_bytes: u64,
    used_effective_memory_bytes: u64,
    newly_placed_pods: u32,
}

/// Evaluates whether `ctx.target_node` can be safely cordoned and drained (`SPEC-0005`).
#[must_use]
pub fn evaluate_node_drain(ctx: &DrainClusterContext) -> DrainPlanReport {
    let kata_overhead = ctx
        .kata_memory_overhead_bytes
        .unwrap_or(DEFAULT_KATA_MEMORY_OVERHEAD_BYTES);

    let target_exists = ctx.nodes.iter().any(|n| n.name == ctx.target_node);
    if !target_exists {
        let decisions = vec![PodDrainDecision {
            namespace: String::new(),
            pod_name: ctx.target_node.clone(),
            action: PodEvictionAction::Blocked {
                reason: DrainBlockReason::TargetNodeNotFound(ctx.target_node.clone()),
            },
        }];
        let digest = compute_drain_plan_digest(&ctx.target_node, false, &decisions, &[]);
        return DrainPlanReport {
            target_node: ctx.target_node.clone(),
            safe_to_drain: false,
            evicted_count: 0,
            skipped_count: 0,
            blocked_count: 1,
            pod_decisions: decisions,
            destination_summaries: Vec::new(),
            plan_digest: digest,
        };
    }

    // Build mutable destination bins for surviving ready & schedulable nodes, sorted by node name
    let mut surviving_bins: BTreeMap<String, MutableNodeBin> = BTreeMap::new();
    for node in &ctx.nodes {
        if node.name == ctx.target_node || !node.ready || node.unschedulable {
            continue;
        }
        surviving_bins.insert(
            node.name.clone(),
            MutableNodeBin {
                node_name: node.name.clone(),
                kata_capable: node.kata_runtime_capable,
                allocatable_cpu_millis: node.allocatable_cpu_millis,
                used_cpu_millis: 0,
                allocatable_memory_bytes: node.allocatable_memory_bytes,
                used_effective_memory_bytes: 0,
                newly_placed_pods: 0,
            },
        );
    }

    // Account for existing pods already running on surviving nodes
    for pod in &ctx.existing_pods_on_other_nodes {
        if let Some(bin) = surviving_bins.get_mut(&pod.node_name) {
            bin.used_cpu_millis = bin.used_cpu_millis.saturating_add(pod.cpu_millis);
            let eff_mem = match pod.isolation_profile {
                IsolationProfile::KataMicroVm => pod.memory_bytes.saturating_add(kata_overhead),
                IsolationProfile::StandardRestricted => pod.memory_bytes,
            };
            bin.used_effective_memory_bytes =
                bin.used_effective_memory_bytes.saturating_add(eff_mem);
        }
    }

    // Track remaining PDB disruption budgets keyed by (namespace, pdb_name)
    let mut pdb_budgets: BTreeMap<(String, String), u32> = ctx
        .pdbs
        .iter()
        .map(|p| ((p.namespace.clone(), p.name.clone()), p.disruptions_allowed))
        .collect();

    // Separate skipped/immediately-blocked pods from bin-packing candidates
    let mut decisions_by_key: BTreeMap<(String, String), PodDrainDecision> = BTreeMap::new();
    let mut evictable_candidates: Vec<&DrainCandidatePod> = Vec::new();

    for pod in &ctx.drain_candidates {
        let key = (pod.namespace.clone(), pod.name.clone());
        if pod.is_mirror_pod {
            decisions_by_key.insert(
                key,
                PodDrainDecision {
                    namespace: pod.namespace.clone(),
                    pod_name: pod.name.clone(),
                    action: PodEvictionAction::SkippedMirrorPod,
                },
            );
            continue;
        }
        if pod.is_daemonset {
            decisions_by_key.insert(
                key,
                PodDrainDecision {
                    namespace: pod.namespace.clone(),
                    pod_name: pod.name.clone(),
                    action: PodEvictionAction::SkippedDaemonSetPod,
                },
            );
            continue;
        }
        if pod.has_unmanaged_local_storage && !ctx.allow_local_storage_erasure {
            decisions_by_key.insert(
                key,
                PodDrainDecision {
                    namespace: pod.namespace.clone(),
                    pod_name: pod.name.clone(),
                    action: PodEvictionAction::Blocked {
                        reason: DrainBlockReason::UnmanagedLocalStorage,
                    },
                },
            );
            continue;
        }
        evictable_candidates.push(pod);
    }

    // Sort evictable pods in First-Fit Decreasing (FFD) order:
    // 1. Higher priority tier first (so critical workloads claim destination capacity first)
    // 2. Larger effective memory footprint first
    // 3. Larger CPU request first
    // 4. Deterministic tie-breaker: (namespace, name)
    evictable_candidates.sort_by(|a, b| {
        let eff_a = effective_pod_memory(a, kata_overhead);
        let eff_b = effective_pod_memory(b, kata_overhead);
        b.priority_tier
            .priority_value()
            .cmp(&a.priority_tier.priority_value())
            .then_with(|| eff_b.cmp(&eff_a))
            .then_with(|| b.cpu_millis.cmp(&a.cpu_millis))
            .then_with(|| a.namespace.cmp(&b.namespace))
            .then_with(|| a.name.cmp(&b.name))
    });

    for pod in evictable_candidates {
        let key = (pod.namespace.clone(), pod.name.clone());
        let requires_kata = pod.isolation_profile == IsolationProfile::KataMicroVm;
        let eff_mem = effective_pod_memory(pod, kata_overhead);

        // Check PDB budget before attempting placement
        if let Some(pdb_name) = &pod.pdb_name {
            let pdb_key = (pod.namespace.clone(), pdb_name.clone());
            let allowed = pdb_budgets.get(&pdb_key).copied().unwrap_or(0);
            if allowed == 0 {
                decisions_by_key.insert(
                    key,
                    PodDrainDecision {
                        namespace: pod.namespace.clone(),
                        pod_name: pod.name.clone(),
                        action: PodEvictionAction::Blocked {
                            reason: DrainBlockReason::PdbDisruptionBudgetExhausted {
                                pdb_name: pdb_name.clone(),
                            },
                        },
                    },
                );
                continue;
            }
        }

        // First-Fit Decreasing across surviving nodes sorted by node_name
        let mut chosen_node: Option<String> = None;
        for bin in surviving_bins.values_mut() {
            if requires_kata && !bin.kata_capable {
                continue;
            }
            let next_cpu = bin.used_cpu_millis.saturating_add(pod.cpu_millis);
            let next_mem = bin.used_effective_memory_bytes.saturating_add(eff_mem);
            if next_cpu <= bin.allocatable_cpu_millis && next_mem <= bin.allocatable_memory_bytes {
                bin.used_cpu_millis = next_cpu;
                bin.used_effective_memory_bytes = next_mem;
                bin.newly_placed_pods = bin.newly_placed_pods.saturating_add(1);
                chosen_node = Some(bin.node_name.clone());
                break;
            }
        }

        match chosen_node {
            Some(dest) => {
                if let Some(pdb_name) = &pod.pdb_name {
                    let pdb_key = (pod.namespace.clone(), pdb_name.clone());
                    if let Some(budget) = pdb_budgets.get_mut(&pdb_key) {
                        *budget = budget.saturating_sub(1);
                    }
                }
                decisions_by_key.insert(
                    key,
                    PodDrainDecision {
                        namespace: pod.namespace.clone(),
                        pod_name: pod.name.clone(),
                        action: PodEvictionAction::EvictAndReschedule {
                            destination_node: dest,
                            effective_memory_bytes: eff_mem,
                        },
                    },
                );
            }
            None => {
                decisions_by_key.insert(
                    key,
                    PodDrainDecision {
                        namespace: pod.namespace.clone(),
                        pod_name: pod.name.clone(),
                        action: PodEvictionAction::Blocked {
                            reason: DrainBlockReason::NoDestinationCapacity {
                                required_cpu_millis: pod.cpu_millis,
                                required_effective_memory_bytes: eff_mem,
                                requires_kata,
                            },
                        },
                    },
                );
            }
        }
    }

    let pod_decisions: Vec<PodDrainDecision> = decisions_by_key.into_values().collect();
    let evicted_count = pod_decisions
        .iter()
        .filter(|d| matches!(d.action, PodEvictionAction::EvictAndReschedule { .. }))
        .count();
    let skipped_count = pod_decisions
        .iter()
        .filter(|d| {
            matches!(
                d.action,
                PodEvictionAction::SkippedMirrorPod | PodEvictionAction::SkippedDaemonSetPod
            )
        })
        .count();
    let blocked_count = pod_decisions
        .iter()
        .filter(|d| matches!(d.action, PodEvictionAction::Blocked { .. }))
        .count();

    let destination_summaries: Vec<NodePlacementSummary> = surviving_bins
        .into_values()
        .map(|b| NodePlacementSummary {
            node_name: b.node_name,
            allocatable_cpu_millis: b.allocatable_cpu_millis,
            post_drain_cpu_millis: b.used_cpu_millis,
            allocatable_memory_bytes: b.allocatable_memory_bytes,
            post_drain_effective_memory_bytes: b.used_effective_memory_bytes,
            newly_placed_pods: b.newly_placed_pods,
        })
        .collect();

    let safe_to_drain = blocked_count == 0;
    let plan_digest = compute_drain_plan_digest(
        &ctx.target_node,
        safe_to_drain,
        &pod_decisions,
        &destination_summaries,
    );

    DrainPlanReport {
        target_node: ctx.target_node.clone(),
        safe_to_drain,
        evicted_count,
        skipped_count,
        blocked_count,
        pod_decisions,
        destination_summaries,
        plan_digest,
    }
}

fn effective_pod_memory(pod: &DrainCandidatePod, kata_overhead: u64) -> u64 {
    match pod.isolation_profile {
        IsolationProfile::KataMicroVm => pod.memory_bytes.saturating_add(kata_overhead),
        IsolationProfile::StandardRestricted => pod.memory_bytes,
    }
}

fn compute_drain_plan_digest(
    target_node: &str,
    safe_to_drain: bool,
    decisions: &[PodDrainDecision],
    summaries: &[NodePlacementSummary],
) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |bytes: &[u8]| {
        for &b in bytes {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    };
    feed(target_node.as_bytes());
    feed(if safe_to_drain {
        b":safe;"
    } else {
        b":blocked;"
    });
    for d in decisions {
        feed(d.namespace.as_bytes());
        feed(b"/");
        feed(d.pod_name.as_bytes());
        match &d.action {
            PodEvictionAction::EvictAndReschedule {
                destination_node,
                effective_memory_bytes,
            } => {
                feed(b"->");
                feed(destination_node.as_bytes());
                feed(&effective_memory_bytes.to_be_bytes());
            }
            PodEvictionAction::SkippedMirrorPod => feed(b":skip-mirror;"),
            PodEvictionAction::SkippedDaemonSetPod => feed(b":skip-ds;"),
            PodEvictionAction::Blocked { .. } => feed(b":blocked;"),
        }
    }
    for s in summaries {
        feed(s.node_name.as_bytes());
        feed(&s.post_drain_cpu_millis.to_be_bytes());
        feed(&s.post_drain_effective_memory_bytes.to_be_bytes());
    }
    format!("{hash:016x}")
}

/// Returns a copy of `node` with `spec.unschedulable` set to `unschedulable` (cordon / uncordon).
#[must_use]
pub fn set_node_unschedulable(node: &Node, unschedulable: bool) -> Node {
    let mut patched = node.clone();
    let mut spec = patched.spec.unwrap_or_default();
    spec.unschedulable = Some(unschedulable);
    patched.spec = Some(spec);
    patched
}

/// Synthesizes a typed Kubernetes `policy/v1` [`Eviction`] subresource manifest for a pod.
///
/// # Errors
/// Returns [`LabelError`] if `namespace` or `pod_name` is not a valid DNS-1123 label.
pub fn build_pod_eviction(
    namespace: &str,
    pod_name: &str,
    grace_period_seconds: Option<i64>,
) -> Result<Eviction, LabelError> {
    validate_dns1123_label(namespace)?;
    validate_dns1123_label(pod_name)?;
    Ok(Eviction {
        metadata: ObjectMeta {
            name: Some(pod_name.to_owned()),
            namespace: Some(namespace.to_owned()),
            ..Default::default()
        },
        delete_options: grace_period_seconds.map(|gp| DeleteOptions {
            grace_period_seconds: Some(gp),
            ..Default::default()
        }),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn sample_nodes() -> Vec<K8sNodeSnapshot> {
        vec![
            K8sNodeSnapshot {
                name: "cygnus-worker-01".to_owned(),
                provider_id: Some("hetzner://1".to_owned()),
                ready: true,
                unschedulable: false,
                allocatable_cpu_millis: 8_000,
                allocatable_memory_bytes: 8 * 1024 * 1024 * 1024,
                kata_runtime_capable: true,
            },
            K8sNodeSnapshot {
                name: "cygnus-worker-02".to_owned(),
                provider_id: Some("hetzner://2".to_owned()),
                ready: true,
                unschedulable: false,
                allocatable_cpu_millis: 8_000,
                allocatable_memory_bytes: 8 * 1024 * 1024 * 1024,
                kata_runtime_capable: true,
            },
        ]
    }

    #[test]
    fn drain_plan_succeeds_when_surviving_node_fits_kata_overhead_and_pdb() {
        let ctx = DrainClusterContext {
            target_node: "cygnus-worker-01".to_owned(),
            nodes: sample_nodes(),
            existing_pods_on_other_nodes: Vec::new(),
            drain_candidates: vec![
                DrainCandidatePod {
                    name: "node-exporter-abc".to_owned(),
                    namespace: "monitoring".to_owned(),
                    cpu_millis: 100,
                    memory_bytes: 128 * 1024 * 1024,
                    isolation_profile: IsolationProfile::StandardRestricted,
                    priority_tier: WorkloadPriorityTier::EstateCoordinator,
                    is_daemonset: true,
                    is_mirror_pod: false,
                    has_unmanaged_local_storage: false,
                    pdb_name: None,
                },
                DrainCandidatePod {
                    name: "agent-1".to_owned(),
                    namespace: "agents".to_owned(),
                    cpu_millis: 2_000,
                    memory_bytes: 2 * 1024 * 1024 * 1024,
                    isolation_profile: IsolationProfile::KataMicroVm,
                    priority_tier: WorkloadPriorityTier::InteractiveAgent,
                    is_daemonset: false,
                    is_mirror_pod: false,
                    has_unmanaged_local_storage: false,
                    pdb_name: Some("agent-pdb".to_owned()),
                },
            ],
            pdbs: vec![PdbBudgetSnapshot {
                name: "agent-pdb".to_owned(),
                namespace: "agents".to_owned(),
                disruptions_allowed: 1,
            }],
            allow_local_storage_erasure: false,
            kata_memory_overhead_bytes: None,
        };

        let report = evaluate_node_drain(&ctx);
        assert!(report.safe_to_drain);
        assert_eq!(report.evicted_count, 1);
        assert_eq!(report.skipped_count, 1);
        assert_eq!(report.blocked_count, 0);
        assert_eq!(
            report.destination_summaries[0].post_drain_effective_memory_bytes,
            2 * 1024 * 1024 * 1024 + DEFAULT_KATA_MEMORY_OVERHEAD_BYTES
        );
    }

    #[test]
    fn drain_plan_blocks_on_exhausted_pdb_or_missing_kata_capacity() {
        let mut nodes = sample_nodes();
        // Make surviving node lack Kata runtime capability
        nodes[1].kata_runtime_capable = false;

        let ctx = DrainClusterContext {
            target_node: "cygnus-worker-01".to_owned(),
            nodes,
            existing_pods_on_other_nodes: Vec::new(),
            drain_candidates: vec![DrainCandidatePod {
                name: "agent-kata".to_owned(),
                namespace: "agents".to_owned(),
                cpu_millis: 1_000,
                memory_bytes: 1024 * 1024 * 1024,
                isolation_profile: IsolationProfile::KataMicroVm,
                priority_tier: WorkloadPriorityTier::InteractiveAgent,
                is_daemonset: false,
                is_mirror_pod: false,
                has_unmanaged_local_storage: false,
                pdb_name: None,
            }],
            pdbs: Vec::new(),
            allow_local_storage_erasure: false,
            kata_memory_overhead_bytes: None,
        };

        let report = evaluate_node_drain(&ctx);
        assert!(!report.safe_to_drain);
        assert_eq!(report.blocked_count, 1);
        assert!(matches!(
            report.pod_decisions[0].action,
            PodEvictionAction::Blocked {
                reason: DrainBlockReason::NoDestinationCapacity {
                    requires_kata: true,
                    ..
                }
            }
        ));
    }
}
