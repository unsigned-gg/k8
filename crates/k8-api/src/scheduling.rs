// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Zero-I/O Kubernetes scheduling primitives: Kata microVM `runtimeClassName`, GPU and agent-pool
//! taint `Toleration`s, `TopologySpreadConstraint`s, and `PodDisruptionBudget` builders (`SPEC-0002`).

use crate::selector::{
    canonical_workload_labels, validate_dns1123_label, LabelError, LABEL_RUN_ID,
};
use k8s_openapi::api::core::v1::{Toleration, TopologySpreadConstraint};
use k8s_openapi::api::policy::v1::{PodDisruptionBudget, PodDisruptionBudgetSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{
    LabelSelector as K8sLabelSelector, ObjectMeta,
};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Kubernetes RuntimeClass name for Kata Containers hardware-virtualized microVMs.
pub const RUNTIME_CLASS_KATA: &str = "kata";

/// Standard taint key applied to NVIDIA GPU nodes.
pub const TAINT_KEY_GPU: &str = "nvidia.com/gpu";

/// Standard taint key applied to dedicated estate agent execution nodes.
pub const TAINT_KEY_AGENT_POOL: &str = "unsigned.gg/agent-pool";

/// Standard topology key for hostname-level pod spreading.
pub const TOPOLOGY_KEY_HOSTNAME: &str = "kubernetes.io/hostname";

/// Container isolation profile determining kernel vs microVM boundary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationProfile {
    /// Standard Linux namespace + `PodSecurity` `restricted` + `RuntimeDefault` seccomp container.
    #[default]
    StandardRestricted,
    /// Hardware-isolated Kata Containers microVM (`runtimeClassName: "kata"`).
    KataMicroVm,
}

impl IsolationProfile {
    /// Return the Kubernetes `PodSpec.runtime_class_name` for this isolation profile.
    #[must_use]
    pub const fn runtime_class_name(self) -> Option<&'static str> {
        match self {
            Self::StandardRestricted => None,
            Self::KataMicroVm => Some(RUNTIME_CLASS_KATA),
        }
    }
}

/// Construct deterministic Kubernetes [`Toleration`] entries for GPU and dedicated agent-pool nodes.
#[must_use]
pub fn build_workload_tolerations(gpu_count: u32, dedicated_agent_pool: bool) -> Vec<Toleration> {
    let mut tolerations = Vec::new();
    if dedicated_agent_pool {
        tolerations.push(Toleration {
            key: Some(TAINT_KEY_AGENT_POOL.to_string()),
            operator: Some("Equal".to_string()),
            value: Some("true".to_string()),
            effect: Some("NoSchedule".to_string()),
            toleration_seconds: None,
        });
    }
    if gpu_count > 0 {
        tolerations.push(Toleration {
            key: Some(TAINT_KEY_GPU.to_string()),
            operator: Some("Exists".to_string()),
            value: None,
            effect: Some("NoSchedule".to_string()),
            toleration_seconds: None,
        });
    }
    tolerations
}

/// Construct a hostname [`TopologySpreadConstraint`] to distribute quorum agent replicas across nodes.
pub fn build_hostname_spread_constraint(
    run_id: &str,
    max_skew: i32,
) -> Result<TopologySpreadConstraint, LabelError> {
    validate_dns1123_label(run_id)?;
    let clamped_skew = max_skew.max(1);
    let mut match_labels = BTreeMap::new();
    match_labels.insert(LABEL_RUN_ID.to_string(), run_id.to_string());

    Ok(TopologySpreadConstraint {
        max_skew: clamped_skew,
        topology_key: TOPOLOGY_KEY_HOSTNAME.to_string(),
        when_unsatisfiable: "ScheduleAnyway".to_string(),
        label_selector: Some(K8sLabelSelector {
            match_labels: Some(match_labels),
            match_expressions: None,
        }),
        match_label_keys: None,
        min_domains: None,
        node_affinity_policy: None,
        node_taints_policy: None,
    })
}

/// Construct a Kubernetes [`PodDisruptionBudget`] protecting active agent pods from voluntary node drains.
pub fn build_workload_pdb(
    run_id: &str,
    namespace: &str,
    agent_role: Option<&str>,
    min_available: u32,
) -> Result<PodDisruptionBudget, LabelError> {
    let labels = canonical_workload_labels(run_id, agent_role)?;
    let clamped_min = i32::try_from(min_available.max(1)).unwrap_or(1);

    Ok(PodDisruptionBudget {
        metadata: ObjectMeta {
            name: Some(format!("{run_id}-pdb")),
            namespace: Some(namespace.to_string()),
            labels: Some(labels.clone()),
            ..Default::default()
        },
        spec: Some(PodDisruptionBudgetSpec {
            min_available: Some(IntOrString::Int(clamped_min)),
            max_unavailable: None,
            selector: Some(K8sLabelSelector {
                match_labels: Some(labels),
                match_expressions: None,
            }),
            unhealthy_pod_eviction_policy: Some("IfHealthyBudget".to_string()),
        }),
        status: None,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_isolation_profile_and_tolerations() {
        assert_eq!(
            IsolationProfile::StandardRestricted.runtime_class_name(),
            None
        );
        assert_eq!(
            IsolationProfile::KataMicroVm.runtime_class_name(),
            Some("kata")
        );

        let tols = build_workload_tolerations(1, true);
        assert_eq!(tols.len(), 2);
        assert_eq!(tols[0].key.as_deref(), Some(TAINT_KEY_AGENT_POOL));
        assert_eq!(tols[1].key.as_deref(), Some(TAINT_KEY_GPU));
    }

    #[test]
    fn test_spread_constraint_and_pdb_builders() {
        let spread = build_hostname_spread_constraint("agent-run42", 1).expect("valid spread");
        assert_eq!(spread.max_skew, 1);
        assert_eq!(spread.topology_key, TOPOLOGY_KEY_HOSTNAME);

        let pdb =
            build_workload_pdb("agent-run42", "agent-ns", Some("critic"), 3).expect("valid pdb");
        assert_eq!(pdb.metadata.name.as_deref(), Some("agent-run42-pdb"));
        let spec = pdb.spec.expect("pdb spec");
        assert_eq!(spec.min_available, Some(IntOrString::Int(3)));
    }
}
