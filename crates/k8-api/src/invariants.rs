// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Pure zero-I/O cluster invariant auditor (`SPEC-0004`).
//!
//! Verifies estate cluster health invariants across cloud/bare-metal provider node
//! inventory, Kubernetes `Node` snapshots, scheduled pod footprints (accounting for
//! per-pod Kata MicroVM hypervisor memory overhead), and `Service` endpoint readiness.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::quota::{DEFAULT_KATA_MEMORY_OVERHEAD_BYTES, DEFAULT_QUOTA_WARN_PERMILLE};
use crate::scheduling::IsolationProfile;

/// Expected node record reported by the underlying infrastructure provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderNodeRecord {
    /// Cloud or bare-metal provider instance identifier (e.g. `"hetzner://1001"`).
    pub provider_id: String,
    /// Expected Kubernetes node name (DNS-1123 label).
    pub expected_name: String,
    /// Whether this node belongs to the sandboxed agent execution pool and must support Kata.
    #[serde(default)]
    pub require_kata_runtime: bool,
}

/// Snapshot of a Kubernetes `Node` object's readiness, capacity, and runtime labels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct K8sNodeSnapshot {
    /// Node `metadata.name`.
    pub name: String,
    /// `spec.providerID` reported on the Kubernetes `Node`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    /// Whether the `Ready` node condition is `"True"`.
    pub ready: bool,
    /// Whether `spec.unschedulable` (cordon) is set.
    #[serde(default)]
    pub unschedulable: bool,
    /// Node allocatable CPU in millicores.
    pub allocatable_cpu_millis: u64,
    /// Node allocatable memory in bytes.
    pub allocatable_memory_bytes: u64,
    /// Whether the node advertises the `kata` `RuntimeClass` capability label.
    #[serde(default)]
    pub kata_runtime_capable: bool,
}

/// Resource footprint of a scheduled non-terminal Pod on a specific Kubernetes `Node`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ScheduledPodFootprint {
    /// Pod `metadata.name`.
    pub name: String,
    /// Pod `metadata.namespace`.
    pub namespace: String,
    /// Assigned `spec.nodeName`.
    pub node_name: String,
    /// Total container CPU requests/limits in millicores.
    pub cpu_millis: u64,
    /// Total container memory requests/limits in bytes (excluding Kata VM overhead).
    pub memory_bytes: u64,
    /// Pod isolation profile (`KataMicroVm` adds `DEFAULT_KATA_MEMORY_OVERHEAD_BYTES`).
    #[serde(default)]
    pub isolation_profile: IsolationProfile,
}

/// Snapshot of a Kubernetes `Service` and its ready backing endpoint count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ServiceEndpointSnapshot {
    /// Service `metadata.name`.
    pub name: String,
    /// Service `metadata.namespace`.
    pub namespace: String,
    /// Kubernetes Service type (for example `"LoadBalancer"` or `"ClusterIP"`).
    pub service_type: String,
    /// Count of ready addresses across all matching `EndpointSlice` objects.
    pub ready_endpoints: u32,
}

/// Complete point-in-time cluster inventory snapshot evaluated by [`evaluate_cluster_invariants`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClusterInventorySnapshot {
    /// Infrastructure provider node inventory.
    #[serde(default)]
    pub provider_nodes: Vec<ProviderNodeRecord>,
    /// Kubernetes `Node` snapshots.
    #[serde(default)]
    pub k8s_nodes: Vec<K8sNodeSnapshot>,
    /// Active scheduled pod footprints.
    #[serde(default)]
    pub scheduled_pods: Vec<ScheduledPodFootprint>,
    /// Service endpoint readiness snapshots.
    #[serde(default)]
    pub services: Vec<ServiceEndpointSnapshot>,
    /// Optional Kata MicroVM hypervisor memory overhead override in bytes (`256Mi` when `None`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kata_memory_overhead_bytes: Option<u64>,
    /// Memory utilization warning threshold in permille (`800` = 80.0% when `None`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_warn_permille: Option<u16>,
}

/// Severity of a cluster invariant finding.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InvariantSeverity {
    /// Advisory warning (for example high node memory utilization or cordoned node).
    Warning,
    /// Hard invariant violation that blocks cluster expansion or risky operations.
    Error,
}

/// Category of a cluster invariant finding.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InvariantCategory {
    /// Provider node is missing from Kubernetes, or Kubernetes node has no provider record.
    NodeIdentityDrift,
    /// Kubernetes node is `NotReady` or cordoned (`unschedulable`).
    NodeReadiness,
    /// Agent-pool node is missing required `kata` runtime support.
    KataRuntimeMissing,
    /// Scheduled pods plus Kata MicroVM hypervisor overhead exceed node allocatable memory.
    KataMemoryOvercommit,
    /// Scheduled pods exceed node allocatable CPU.
    NodeCpuOvercommit,
    /// Pod is assigned to a `nodeName` that does not exist in `k8s_nodes`.
    OrphanScheduledPod,
    /// `LoadBalancer` or `ClusterIP` service has zero ready endpoints.
    ServiceZeroEndpoints,
}

/// Single finding emitted by [`evaluate_cluster_invariants`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClusterInvariantFinding {
    /// Invariant category.
    pub category: InvariantCategory,
    /// Severity level (`Warning` or `Error`).
    pub severity: InvariantSeverity,
    /// Canonical resource identifier (`node/<name>`, `service/<ns>/<name>`, etc.).
    pub resource: String,
    /// Actionable human-readable diagnostic message.
    pub message: String,
}

/// Per-node CPU and Kata-adjusted memory headroom summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct NodeHeadroomSummary {
    /// Node `metadata.name`.
    pub node_name: String,
    /// Node allocatable CPU in millicores.
    pub allocatable_cpu_millis: u64,
    /// Sum of scheduled pod CPU requests in millicores.
    pub requested_cpu_millis: u64,
    /// Node allocatable memory in bytes.
    pub allocatable_memory_bytes: u64,
    /// Sum of container memory requests plus `kata_pod_count * kata_overhead_bytes`.
    pub effective_memory_bytes: u64,
    /// Count of scheduled pods on this node using `IsolationProfile::KataMicroVm`.
    pub kata_pod_count: u32,
    /// Total count of scheduled pods on this node.
    pub total_pod_count: u32,
    /// CPU utilization in permille (`0..=1000+`).
    pub cpu_utilization_permille: u64,
    /// Effective memory utilization in permille (`0..=1000+`).
    pub memory_utilization_permille: u64,
}

/// Deterministic cluster invariant audit report (`SPEC-0004`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClusterInvariantReport {
    /// `true` iff no finding has [`InvariantSeverity::Error`].
    pub healthy: bool,
    /// Number of [`InvariantSeverity::Error`] findings.
    pub error_count: usize,
    /// Number of [`InvariantSeverity::Warning`] findings.
    pub warning_count: usize,
    /// Ordered list of invariant findings (`Error` and `Warning`).
    pub findings: Vec<ClusterInvariantFinding>,
    /// Per-node CPU and Kata-adjusted memory headroom summaries sorted by node name.
    pub node_summaries: Vec<NodeHeadroomSummary>,
    /// Deterministic 64-bit FNV-1a hex digest over all findings and node summaries.
    pub report_digest: String,
}

/// Evaluates all `SPEC-0004` cluster invariants deterministically in zero I/O.
#[must_use]
pub fn evaluate_cluster_invariants(snapshot: &ClusterInventorySnapshot) -> ClusterInvariantReport {
    let mut findings = Vec::new();
    let kata_overhead = snapshot
        .kata_memory_overhead_bytes
        .unwrap_or(DEFAULT_KATA_MEMORY_OVERHEAD_BYTES);
    let warn_permille = u64::from(
        snapshot
            .memory_warn_permille
            .unwrap_or(DEFAULT_QUOTA_WARN_PERMILLE),
    );

    let k8s_by_name: BTreeMap<&str, &K8sNodeSnapshot> = snapshot
        .k8s_nodes
        .iter()
        .map(|n| (n.name.as_str(), n))
        .collect();
    let k8s_by_provider_id: BTreeMap<&str, &K8sNodeSnapshot> = snapshot
        .k8s_nodes
        .iter()
        .filter_map(|n| n.provider_id.as_deref().map(|pid| (pid, n)))
        .collect();
    let provider_by_id: BTreeMap<&str, &ProviderNodeRecord> = snapshot
        .provider_nodes
        .iter()
        .map(|p| (p.provider_id.as_str(), p))
        .collect();

    // 1. Reconcile provider nodes -> Kubernetes nodes
    for pnode in &snapshot.provider_nodes {
        match k8s_by_provider_id.get(pnode.provider_id.as_str()) {
            None => {
                findings.push(ClusterInvariantFinding {
                    category: InvariantCategory::NodeIdentityDrift,
                    severity: InvariantSeverity::Error,
                    resource: format!("provider-node/{}", pnode.provider_id),
                    message: format!(
                        "provider node `{}` (expected k8s node `{}`) is missing from Kubernetes",
                        pnode.provider_id, pnode.expected_name
                    ),
                });
            }
            Some(knode) => {
                if knode.name != pnode.expected_name {
                    findings.push(ClusterInvariantFinding {
                        category: InvariantCategory::NodeIdentityDrift,
                        severity: InvariantSeverity::Error,
                        resource: format!("node/{}", knode.name),
                        message: format!(
                            "provider ID `{}` is bound to k8s node `{}`, expected `{}`",
                            pnode.provider_id, knode.name, pnode.expected_name
                        ),
                    });
                }
                if pnode.require_kata_runtime && !knode.kata_runtime_capable {
                    findings.push(ClusterInvariantFinding {
                        category: InvariantCategory::KataRuntimeMissing,
                        severity: InvariantSeverity::Error,
                        resource: format!("node/{}", knode.name),
                        message: format!(
                            "agent-pool node `{}` does not advertise required `kata` runtime support",
                            knode.name
                        ),
                    });
                }
            }
        }
    }

    // 2. Reconcile Kubernetes nodes -> provider nodes & readiness
    let enforce_provider_check = !snapshot.provider_nodes.is_empty();
    for knode in &snapshot.k8s_nodes {
        if enforce_provider_check {
            match knode.provider_id.as_deref() {
                None => {
                    findings.push(ClusterInvariantFinding {
                        category: InvariantCategory::NodeIdentityDrift,
                        severity: InvariantSeverity::Error,
                        resource: format!("node/{}", knode.name),
                        message: format!("k8s node `{}` has no `spec.providerID`", knode.name),
                    });
                }
                Some(pid) => {
                    if !provider_by_id.contains_key(pid) {
                        findings.push(ClusterInvariantFinding {
                            category: InvariantCategory::NodeIdentityDrift,
                            severity: InvariantSeverity::Error,
                            resource: format!("node/{}", knode.name),
                            message: format!(
                                "k8s node `{}` references unknown providerID `{pid}`",
                                knode.name
                            ),
                        });
                    }
                }
            }
        }
        if !knode.ready {
            findings.push(ClusterInvariantFinding {
                category: InvariantCategory::NodeReadiness,
                severity: InvariantSeverity::Error,
                resource: format!("node/{}", knode.name),
                message: format!("k8s node `{}` is NotReady", knode.name),
            });
        } else if knode.unschedulable {
            findings.push(ClusterInvariantFinding {
                category: InvariantCategory::NodeReadiness,
                severity: InvariantSeverity::Warning,
                resource: format!("node/{}", knode.name),
                message: format!("k8s node `{}` is cordoned (unschedulable)", knode.name),
            });
        }
    }

    // 3. Audit scheduled pods and compute per-node Kata-aware headroom
    let mut pods_by_node: BTreeMap<&str, Vec<&ScheduledPodFootprint>> = BTreeMap::new();
    let known_node_names: BTreeSet<&str> = k8s_by_name.keys().copied().collect();

    for pod in &snapshot.scheduled_pods {
        if !known_node_names.contains(pod.node_name.as_str()) {
            findings.push(ClusterInvariantFinding {
                category: InvariantCategory::OrphanScheduledPod,
                severity: InvariantSeverity::Error,
                resource: format!("pod/{}/{}", pod.namespace, pod.name),
                message: format!(
                    "pod `{}/{}` is assigned to unknown node `{}`",
                    pod.namespace, pod.name, pod.node_name
                ),
            });
        } else {
            pods_by_node
                .entry(pod.node_name.as_str())
                .or_default()
                .push(pod);
        }
    }

    let mut node_summaries = Vec::with_capacity(k8s_by_name.len());
    for (&node_name, &knode) in &k8s_by_name {
        let assigned = pods_by_node
            .get(node_name)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let mut requested_cpu_millis: u64 = 0;
        let mut effective_memory_bytes: u64 = 0;
        let mut kata_pod_count: u32 = 0;

        for pod in assigned {
            requested_cpu_millis = requested_cpu_millis.saturating_add(pod.cpu_millis);
            let pod_eff_mem = match pod.isolation_profile {
                IsolationProfile::KataMicroVm => {
                    kata_pod_count = kata_pod_count.saturating_add(1);
                    pod.memory_bytes.saturating_add(kata_overhead)
                }
                IsolationProfile::StandardRestricted => pod.memory_bytes,
            };
            effective_memory_bytes = effective_memory_bytes.saturating_add(pod_eff_mem);
        }

        let cpu_permille = if knode.allocatable_cpu_millis == 0 {
            1_000
        } else {
            requested_cpu_millis.saturating_mul(1_000) / knode.allocatable_cpu_millis
        };
        let mem_permille = if knode.allocatable_memory_bytes == 0 {
            1_000
        } else {
            effective_memory_bytes.saturating_mul(1_000) / knode.allocatable_memory_bytes
        };

        if requested_cpu_millis > knode.allocatable_cpu_millis {
            findings.push(ClusterInvariantFinding {
                category: InvariantCategory::NodeCpuOvercommit,
                severity: InvariantSeverity::Error,
                resource: format!("node/{node_name}"),
                message: format!(
                    "node `{node_name}` CPU overcommitted: requested {requested_cpu_millis}m > allocatable {}m",
                    knode.allocatable_cpu_millis
                ),
            });
        }

        if effective_memory_bytes > knode.allocatable_memory_bytes {
            findings.push(ClusterInvariantFinding {
                category: InvariantCategory::KataMemoryOvercommit,
                severity: InvariantSeverity::Error,
                resource: format!("node/{node_name}"),
                message: format!(
                    "node `{node_name}` memory overcommitted (including {kata_pod_count} Kata VM overhead(s)): effective {effective_memory_bytes}B > allocatable {}B",
                    knode.allocatable_memory_bytes
                ),
            });
        } else if mem_permille >= warn_permille {
            findings.push(ClusterInvariantFinding {
                category: InvariantCategory::KataMemoryOvercommit,
                severity: InvariantSeverity::Warning,
                resource: format!("node/{node_name}"),
                message: format!(
                    "node `{node_name}` effective memory utilization is {mem_permille} permille (>= {warn_permille} warning threshold)",
                ),
            });
        }

        node_summaries.push(NodeHeadroomSummary {
            node_name: node_name.to_owned(),
            allocatable_cpu_millis: knode.allocatable_cpu_millis,
            requested_cpu_millis,
            allocatable_memory_bytes: knode.allocatable_memory_bytes,
            effective_memory_bytes,
            kata_pod_count,
            total_pod_count: u32::try_from(assigned.len()).unwrap_or(u32::MAX),
            cpu_utilization_permille: cpu_permille,
            memory_utilization_permille: mem_permille,
        });
    }

    // 4. Audit Service endpoints
    for svc in &snapshot.services {
        if svc.ready_endpoints == 0 {
            findings.push(ClusterInvariantFinding {
                category: InvariantCategory::ServiceZeroEndpoints,
                severity: InvariantSeverity::Error,
                resource: format!("service/{}/{}", svc.namespace, svc.name),
                message: format!(
                    "{} service `{}/{}` has 0 ready endpoints",
                    svc.service_type, svc.namespace, svc.name
                ),
            });
        }
    }

    let error_count = findings
        .iter()
        .filter(|f| f.severity == InvariantSeverity::Error)
        .count();
    let warning_count = findings
        .iter()
        .filter(|f| f.severity == InvariantSeverity::Warning)
        .count();
    let healthy = error_count == 0;
    let report_digest = compute_invariant_report_digest(healthy, &findings, &node_summaries);

    ClusterInvariantReport {
        healthy,
        error_count,
        warning_count,
        findings,
        node_summaries,
        report_digest,
    }
}

fn compute_invariant_report_digest(
    healthy: bool,
    findings: &[ClusterInvariantFinding],
    summaries: &[NodeHeadroomSummary],
) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |bytes: &[u8]| {
        for &b in bytes {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    };
    feed(if healthy {
        b"healthy:1;"
    } else {
        b"healthy:0;"
    });
    for f in findings {
        feed(f.resource.as_bytes());
        feed(b":");
        feed(f.message.as_bytes());
        feed(b";");
    }
    for s in summaries {
        feed(s.node_name.as_bytes());
        feed(&s.requested_cpu_millis.to_be_bytes());
        feed(&s.effective_memory_bytes.to_be_bytes());
        feed(&s.kata_pod_count.to_be_bytes());
    }
    format!("{hash:016x}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn healthy_cluster_passes_all_invariants() {
        let snapshot = ClusterInventorySnapshot {
            provider_nodes: vec![ProviderNodeRecord {
                provider_id: "hetzner://node-1".to_owned(),
                expected_name: "cygnus-worker-1".to_owned(),
                require_kata_runtime: true,
            }],
            k8s_nodes: vec![K8sNodeSnapshot {
                name: "cygnus-worker-1".to_owned(),
                provider_id: Some("hetzner://node-1".to_owned()),
                ready: true,
                unschedulable: false,
                allocatable_cpu_millis: 8_000,
                allocatable_memory_bytes: 16 * 1024 * 1024 * 1024,
                kata_runtime_capable: true,
            }],
            scheduled_pods: vec![ScheduledPodFootprint {
                name: "agent-1".to_owned(),
                namespace: "agents".to_owned(),
                node_name: "cygnus-worker-1".to_owned(),
                cpu_millis: 2_000,
                memory_bytes: 2 * 1024 * 1024 * 1024,
                isolation_profile: IsolationProfile::KataMicroVm,
            }],
            services: vec![ServiceEndpointSnapshot {
                name: "llm-gateway".to_owned(),
                namespace: "paas".to_owned(),
                service_type: "LoadBalancer".to_owned(),
                ready_endpoints: 2,
            }],
            kata_memory_overhead_bytes: None,
            memory_warn_permille: None,
        };

        let report = evaluate_cluster_invariants(&snapshot);
        assert!(report.healthy, "findings: {:?}", report.findings);
        assert!(report.findings.is_empty());
        assert_eq!(report.node_summaries.len(), 1);
        assert_eq!(
            report.node_summaries[0].effective_memory_bytes,
            2 * 1024 * 1024 * 1024 + DEFAULT_KATA_MEMORY_OVERHEAD_BYTES
        );
    }

    #[test]
    fn detects_kata_memory_overcommit_identity_drift_and_zero_endpoints() {
        let snapshot = ClusterInventorySnapshot {
            provider_nodes: vec![
                ProviderNodeRecord {
                    provider_id: "hetzner://node-1".to_owned(),
                    expected_name: "cygnus-worker-1".to_owned(),
                    require_kata_runtime: true,
                },
                ProviderNodeRecord {
                    provider_id: "hetzner://node-missing".to_owned(),
                    expected_name: "cygnus-worker-2".to_owned(),
                    require_kata_runtime: false,
                },
            ],
            k8s_nodes: vec![K8sNodeSnapshot {
                name: "cygnus-worker-1".to_owned(),
                provider_id: Some("hetzner://node-1".to_owned()),
                ready: true,
                unschedulable: false,
                allocatable_cpu_millis: 4_000,
                // 4 GiB allocatable: two 2 GiB Kata pods will exceed 4 GiB by 512 MiB Kata overhead!
                allocatable_memory_bytes: 4 * 1024 * 1024 * 1024,
                kata_runtime_capable: false,
            }],
            scheduled_pods: vec![
                ScheduledPodFootprint {
                    name: "agent-a".to_owned(),
                    namespace: "agents".to_owned(),
                    node_name: "cygnus-worker-1".to_owned(),
                    cpu_millis: 1_000,
                    memory_bytes: 2 * 1024 * 1024 * 1024,
                    isolation_profile: IsolationProfile::KataMicroVm,
                },
                ScheduledPodFootprint {
                    name: "agent-b".to_owned(),
                    namespace: "agents".to_owned(),
                    node_name: "cygnus-worker-1".to_owned(),
                    cpu_millis: 1_000,
                    memory_bytes: 2 * 1024 * 1024 * 1024,
                    isolation_profile: IsolationProfile::KataMicroVm,
                },
            ],
            services: vec![ServiceEndpointSnapshot {
                name: "tailnet-ingress".to_owned(),
                namespace: "kube-system".to_owned(),
                service_type: "LoadBalancer".to_owned(),
                ready_endpoints: 0,
            }],
            kata_memory_overhead_bytes: None,
            memory_warn_permille: None,
        };

        let report = evaluate_cluster_invariants(&snapshot);
        assert!(!report.healthy);
        assert!(report
            .findings
            .iter()
            .any(|f| f.category == InvariantCategory::NodeIdentityDrift));
        assert!(report
            .findings
            .iter()
            .any(|f| f.category == InvariantCategory::KataRuntimeMissing));
        assert!(report
            .findings
            .iter()
            .any(|f| f.category == InvariantCategory::KataMemoryOvercommit));
        assert!(report
            .findings
            .iter()
            .any(|f| f.category == InvariantCategory::ServiceZeroEndpoints));
    }
}
