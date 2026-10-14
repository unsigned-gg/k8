// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `priority`: Kubernetes `scheduling.k8s.io/v1` `PriorityClass` tiers, preemption policy
//! contracts, and pod `terminationGracePeriodSeconds` containment (`SPEC-0005`).

use k8s_openapi::api::core::v1::PodSpec;
use k8s_openapi::api::scheduling::v1::PriorityClass;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default termination grace period (`30` seconds) for sandboxed agent workloads.
pub const DEFAULT_TERMINATION_GRACE_SECONDS: u64 = 30;

/// Maximum permitted termination grace period (`300` seconds = 5 minutes) for agent workloads
/// so terminating pods cannot stall node cordons or drains indefinitely.
pub const MAX_TERMINATION_GRACE_SECONDS: u64 = 300;

/// Reserved Kubernetes system priority class names forbidden for untrusted/agent workloads.
pub const FORBIDDEN_SYSTEM_PRIORITY_CLASSES: &[&str] =
    &["system-node-critical", "system-cluster-critical"];

/// Maximum numeric priority value (`100_000`) permitted for non-system estate workloads.
pub const MAX_WORKLOAD_PRIORITY_VALUE: i32 = 100_000;

/// Kubernetes `PreemptionPolicy` values (`scheduling.k8s.io/v1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum PreemptionBehavior {
    /// Higher-priority pending pods may preempt lower-priority running pods.
    PreemptLowerPriority,
    /// Pods in this priority class wait in the scheduling queue without preempting running work.
    Never,
}

impl PreemptionBehavior {
    /// Returns the canonical Kubernetes API string (`"PreemptLowerPriority"` or `"Never"`).
    #[must_use]
    pub const fn as_k8s_str(self) -> &'static str {
        match self {
            Self::PreemptLowerPriority => "PreemptLowerPriority",
            Self::Never => "Never",
        }
    }
}

/// Canonical estate workload priority tiers (`SPEC-0005`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum WorkloadPriorityTier {
    /// Control-plane & estate coordinator services (`value = 100_000`, `PreemptLowerPriority`).
    EstateCoordinator,
    /// Interactive operator-paired agent sessions (`value = 50_000`, `PreemptLowerPriority`).
    #[default]
    InteractiveAgent,
    /// Non-preempting batch research / evaluation jobs (`value = 10_000`, `Never`).
    BatchResearch,
    /// Opportunistic background / scavenger tasks (`value = 1_000`, `Never`).
    SpotScavenger,
}

impl WorkloadPriorityTier {
    /// Canonical `PriorityClass` resource name in Kubernetes (`k8-<tier>`).
    #[must_use]
    pub const fn class_name(self) -> &'static str {
        match self {
            Self::EstateCoordinator => "k8-estate-coordinator",
            Self::InteractiveAgent => "k8-interactive-agent",
            Self::BatchResearch => "k8-batch-research",
            Self::SpotScavenger => "k8-spot-scavenger",
        }
    }

    /// Numeric priority value (`1_000..=100_000`).
    #[must_use]
    pub const fn priority_value(self) -> i32 {
        match self {
            Self::EstateCoordinator => 100_000,
            Self::InteractiveAgent => 50_000,
            Self::BatchResearch => 10_000,
            Self::SpotScavenger => 1_000,
        }
    }

    /// Preemption behavior for this tier. Batch and scavenger tiers use `Never` to prevent
    /// peer thrashing across long-running jobs.
    #[must_use]
    pub const fn preemption_behavior(self) -> PreemptionBehavior {
        match self {
            Self::EstateCoordinator | Self::InteractiveAgent => {
                PreemptionBehavior::PreemptLowerPriority
            }
            Self::BatchResearch | Self::SpotScavenger => PreemptionBehavior::Never,
        }
    }

    /// Human-readable description included in the `PriorityClass` manifest.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::EstateCoordinator => {
                "Estate coordinator and control-plane workloads (preempts lower-priority tasks)"
            }
            Self::InteractiveAgent => {
                "Interactive operator-paired agent workloads (preempts batch/spot tasks)"
            }
            Self::BatchResearch => {
                "Non-preempting batch research and evaluation workloads (FIFO queue discipline)"
            }
            Self::SpotScavenger => {
                "Opportunistic scavenger workloads (evicted first under node pressure)"
            }
        }
    }
}

/// Validation errors for workload priority classes and termination grace periods (`SPEC-0005`).
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum PriorityError {
    /// Workload attempted to use a reserved Kubernetes system priority class.
    #[error("priorityClassName `{0}` is reserved for cluster-critical system daemons")]
    ForbiddenSystemPriorityClass(String),

    /// Explicit numeric priority in `PodSpec` exceeds `MAX_WORKLOAD_PRIORITY_VALUE`.
    #[error("explicit pod priority `{value}` exceeds maximum workload priority `{max}`")]
    ExcessivePriorityValue {
        /// Requested numeric priority value.
        value: i32,
        /// Maximum permitted numeric priority value.
        max: i32,
    },

    /// `terminationGracePeriodSeconds` is negative or zero.
    #[error("terminationGracePeriodSeconds `{0}` must be strictly positive (1..={MAX_TERMINATION_GRACE_SECONDS})")]
    NonPositiveTerminationGracePeriod(i64),

    /// `terminationGracePeriodSeconds` exceeds `max_grace_seconds`.
    #[error(
        "terminationGracePeriodSeconds `{requested}` exceeds maximum permitted `{max}` seconds"
    )]
    ExcessiveTerminationGracePeriod {
        /// Requested termination grace period in seconds.
        requested: u64,
        /// Maximum permitted termination grace period in seconds.
        max: u64,
    },
}

/// Synthesizes a typed Kubernetes `scheduling.k8s.io/v1` [`PriorityClass`] manifest for the given tier.
#[must_use]
pub fn build_priority_class(tier: WorkloadPriorityTier) -> PriorityClass {
    PriorityClass {
        metadata: ObjectMeta {
            name: Some(tier.class_name().to_owned()),
            ..Default::default()
        },
        value: Some(tier.priority_value()),
        global_default: Some(false),
        preemption_policy: Some(tier.preemption_behavior().as_k8s_str().to_owned()),
        description: Some(tier.description().to_owned()),
    }
}

/// Synthesizes all 4 canonical estate [`PriorityClass`] manifests in descending priority order.
#[must_use]
pub fn build_estate_priority_classes() -> Vec<PriorityClass> {
    vec![
        build_priority_class(WorkloadPriorityTier::EstateCoordinator),
        build_priority_class(WorkloadPriorityTier::InteractiveAgent),
        build_priority_class(WorkloadPriorityTier::BatchResearch),
        build_priority_class(WorkloadPriorityTier::SpotScavenger),
    ]
}

/// Audits a [`PodSpec`] to ensure it does not claim a forbidden `system-*` priority class,
/// does not set a numeric priority above [`MAX_WORKLOAD_PRIORITY_VALUE`], and bounds
/// `terminationGracePeriodSeconds` within `1..=max_grace_seconds` (`INV-0005-04`).
///
/// # Errors
/// Returns [`PriorityError`] if any priority or termination grace period invariant is violated.
pub fn audit_pod_priority_and_grace_period(
    pod_spec: &PodSpec,
    max_grace_seconds: u64,
) -> Result<(), PriorityError> {
    if let Some(class_name) = pod_spec.priority_class_name.as_deref() {
        let trimmed = class_name.trim();
        if FORBIDDEN_SYSTEM_PRIORITY_CLASSES.contains(&trimmed) || trimmed.starts_with("system-") {
            return Err(PriorityError::ForbiddenSystemPriorityClass(
                trimmed.to_owned(),
            ));
        }
    }

    if let Some(prio) = pod_spec.priority {
        if prio > MAX_WORKLOAD_PRIORITY_VALUE {
            return Err(PriorityError::ExcessivePriorityValue {
                value: prio,
                max: MAX_WORKLOAD_PRIORITY_VALUE,
            });
        }
    }

    if let Some(grace) = pod_spec.termination_grace_period_seconds {
        if grace <= 0 {
            return Err(PriorityError::NonPositiveTerminationGracePeriod(grace));
        }
        let grace_u64 = u64::try_from(grace).unwrap_or(u64::MAX);
        if grace_u64 > max_grace_seconds {
            return Err(PriorityError::ExcessiveTerminationGracePeriod {
                requested: grace_u64,
                max: max_grace_seconds,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn builds_estate_priority_classes_with_expected_preemption_policies() {
        let classes = build_estate_priority_classes();
        assert_eq!(classes.len(), 4);
        assert_eq!(
            classes[0].metadata.name.as_deref(),
            Some("k8-estate-coordinator")
        );
        assert_eq!(classes[0].value, Some(100_000));
        assert_eq!(
            classes[0].preemption_policy.as_deref(),
            Some("PreemptLowerPriority")
        );

        assert_eq!(
            classes[2].metadata.name.as_deref(),
            Some("k8-batch-research")
        );
        assert_eq!(classes[2].value, Some(10_000));
        assert_eq!(classes[2].preemption_policy.as_deref(), Some("Never"));
    }

    #[test]
    fn audit_rejects_system_priority_classes_and_excessive_grace_periods() {
        let mut spec = PodSpec {
            priority_class_name: Some("k8-batch-research".to_owned()),
            termination_grace_period_seconds: Some(30),
            ..Default::default()
        };
        assert!(audit_pod_priority_and_grace_period(&spec, MAX_TERMINATION_GRACE_SECONDS).is_ok());

        spec.priority_class_name = Some("system-node-critical".to_owned());
        assert_eq!(
            audit_pod_priority_and_grace_period(&spec, MAX_TERMINATION_GRACE_SECONDS),
            Err(PriorityError::ForbiddenSystemPriorityClass(
                "system-node-critical".to_owned()
            ))
        );

        spec.priority_class_name = Some("k8-interactive-agent".to_owned());
        spec.termination_grace_period_seconds = Some(600);
        assert_eq!(
            audit_pod_priority_and_grace_period(&spec, MAX_TERMINATION_GRACE_SECONDS),
            Err(PriorityError::ExcessiveTerminationGracePeriod {
                requested: 600,
                max: MAX_TERMINATION_GRACE_SECONDS,
            })
        );
    }
}
