// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Pure zero-I/O Kubernetes Validating Admission Engine (`SPEC-0003`).
//!
//! Evaluates an [`AgentWorkload`] against a deterministic multi-gate policy pipeline:
//! 1. `SpecAndLabels` — DNS-1123 workload/namespace labels and non-empty spec invariants
//! 2. `ResourceQuantities` — CPU/memory quantity parsing and bounds
//! 3. `ZeroTrustNetwork` — Non-wildcard IPv4/IPv6 CIDR egress rules and valid ports
//! 4. `LeastPrivilegeRbac` — Scoped read-only RBAC rules and zero-trust `ServiceAccount`
//! 5. `VolumeHygiene` — Bounded `emptyDir` `sizeLimit` and clean mount paths
//! 6. `NamespaceQuota` — Optional `NamespaceQuotaSpec` headroom check with Kata overhead
//! 7. `JuryConsensus` — Optional BFT [`ExecutionReceipt`] verification before admission
//!
//! Emits a deterministic [`AdmissionReviewOutcome`] with a 64-bit FNV-1a `decision_digest`.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::jury::{ExecutionReceipt, VerdictOutcome};
use crate::network::build_isolated_network_policy;
use crate::quota::{
    evaluate_quota_admission, NamespaceQuotaSpec, QuotaHeadroomReport, QuotaUsageSnapshot,
};
use crate::rbac::{build_dedicated_service_account, build_scoped_role};
use crate::selector::{canonical_workload_labels, validate_dns1123_label};
use crate::storage::{build_scratch_volume_and_mount, ScratchVolumeSpec};
use crate::{AgentWorkload, SpecValidationError};

/// Policy gate identifier in the admission pipeline (`SPEC-0003`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum AdmissionGate {
    /// Workload metadata, DNS-1123 naming, and core spec fields.
    SpecAndLabels,
    /// CPU and memory quantity bounds.
    ResourceQuantities,
    /// Zero-trust `NetworkPolicy` egress CIDR and port rules.
    ZeroTrustNetwork,
    /// Least-privilege `ServiceAccount` and `Role` rules.
    LeastPrivilegeRbac,
    /// Bounded ephemeral scratch volumes and mount path hygiene.
    VolumeHygiene,
    /// Namespace `ResourceQuota` headroom (including Kata MicroVM overhead).
    NamespaceQuota,
    /// BFT jury execution receipt verification.
    JuryConsensus,
}

/// Structured violation emitted by a failing [`AdmissionGate`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AdmissionViolation {
    /// Gate that rejected the workload.
    pub gate: AdmissionGate,
    /// Machine-readable violation code.
    pub code: String,
    /// Human-readable diagnostic message.
    pub message: String,
}

/// Optional cluster/governance context supplied to [`evaluate_workload_admission`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdmissionContext {
    /// Optional namespace quota ceiling and current usage snapshot.
    pub quota: Option<(NamespaceQuotaSpec, QuotaUsageSnapshot)>,
    /// Optional sealed BFT jury [`ExecutionReceipt`] required before admitting execution.
    pub required_receipt: Option<ExecutionReceipt>,
}

/// Deterministic admission verdict with a tamper-evident commitment digest (`SPEC-0003`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AdmissionReviewOutcome {
    /// Evaluated workload name.
    pub workload_name: String,
    /// Target Kubernetes namespace.
    pub namespace: String,
    /// `true` if and only if `violations` is empty.
    pub allowed: bool,
    /// Ordered list of policy violations across all evaluated gates.
    pub violations: Vec<AdmissionViolation>,
    /// Advisory warnings (e.g. namespace quota utilization >= warn threshold).
    pub warnings: Vec<String>,
    /// Optional namespace quota headroom report when quota governance was evaluated.
    pub quota_report: Option<QuotaHeadroomReport>,
    /// Deterministic 64-bit FNV-1a hex digest over the canonical admission verdict.
    pub decision_digest: String,
}

/// Runs all admission gates over `workload` and `ctx` in zero I/O, returning
/// a deterministic [`AdmissionReviewOutcome`] (`SPEC-0003`).
#[must_use]
pub fn evaluate_workload_admission(
    workload: &AgentWorkload,
    ctx: &AdmissionContext,
) -> AdmissionReviewOutcome {
    let workload_name = workload
        .metadata
        .name
        .clone()
        .unwrap_or_else(|| "unnamed-workload".to_owned());
    let namespace = workload
        .metadata
        .namespace
        .clone()
        .unwrap_or_else(|| "default".to_owned());

    let mut violations = Vec::new();
    let mut warnings = Vec::new();
    let mut quota_report = None;

    // Gate 1 & 2: Spec, DNS-1123 labels, and Resource quantities
    if let Err(err) = validate_dns1123_label(&workload_name) {
        violations.push(AdmissionViolation {
            gate: AdmissionGate::SpecAndLabels,
            code: "INVALID_WORKLOAD_NAME".to_owned(),
            message: err.to_string(),
        });
    }
    if let Err(err) = validate_dns1123_label(&namespace) {
        violations.push(AdmissionViolation {
            gate: AdmissionGate::SpecAndLabels,
            code: "INVALID_NAMESPACE".to_owned(),
            message: err.to_string(),
        });
    }
    if let Err(err) = workload.spec.validate() {
        let gate = match &err {
            SpecValidationError::InvalidQuantity(_) => AdmissionGate::ResourceQuantities,
            SpecValidationError::InvalidNetworkPolicy(_) => AdmissionGate::ZeroTrustNetwork,
            SpecValidationError::InvalidRbac(_) => AdmissionGate::LeastPrivilegeRbac,
            SpecValidationError::InvalidStorage(_) => AdmissionGate::VolumeHygiene,
            SpecValidationError::InvalidImage(_)
            | SpecValidationError::InvalidLabel(_)
            | SpecValidationError::InvalidTimeout(_)
            | SpecValidationError::InvalidEnvVarName(_) => AdmissionGate::SpecAndLabels,
        };
        violations.push(AdmissionViolation {
            gate,
            code: "SPEC_VALIDATION_FAILED".to_owned(),
            message: err.to_string(),
        });
    }

    let labels = canonical_workload_labels(&workload_name, workload.spec.agent_role.as_deref())
        .unwrap_or_else(|_| BTreeMap::new());

    // Gate 3: Zero-Trust NetworkPolicy
    if let Err(err) = build_isolated_network_policy(
        &workload_name,
        &namespace,
        workload.spec.agent_role.as_deref(),
        workload.spec.egress.as_ref(),
    ) {
        violations.push(AdmissionViolation {
            gate: AdmissionGate::ZeroTrustNetwork,
            code: "NETWORK_POLICY_VIOLATION".to_owned(),
            message: err.to_string(),
        });
    }

    // Gate 4: Least-Privilege RBAC
    if let Err(err) =
        build_dedicated_service_account(&workload_name, &namespace, labels.clone(), false)
    {
        violations.push(AdmissionViolation {
            gate: AdmissionGate::LeastPrivilegeRbac,
            code: "SERVICE_ACCOUNT_VIOLATION".to_owned(),
            message: err.to_string(),
        });
    }
    if !workload.spec.rbac_rules.is_empty() {
        if let Err(err) = build_scoped_role(
            &workload_name,
            &namespace,
            labels,
            &workload.spec.rbac_rules,
        ) {
            violations.push(AdmissionViolation {
                gate: AdmissionGate::LeastPrivilegeRbac,
                code: "RBAC_ROLE_VIOLATION".to_owned(),
                message: err.to_string(),
            });
        }
    }

    // Gate 5: Volume Hygiene (scratch volumes + duplicate mountPath check)
    let scratch_specs: Vec<ScratchVolumeSpec> = if workload.spec.scratch_volumes.is_empty() {
        vec![ScratchVolumeSpec::default()]
    } else {
        workload.spec.scratch_volumes.clone()
    };
    let mut seen_mount_paths = Vec::new();
    for scratch in &scratch_specs {
        if seen_mount_paths.contains(&scratch.mount_path) {
            violations.push(AdmissionViolation {
                gate: AdmissionGate::VolumeHygiene,
                code: "DUPLICATE_MOUNT_PATH".to_owned(),
                message: format!(
                    "duplicate scratch volume mountPath `{}`",
                    scratch.mount_path
                ),
            });
        } else {
            seen_mount_paths.push(scratch.mount_path.clone());
        }
        if let Err(err) = build_scratch_volume_and_mount(scratch) {
            violations.push(AdmissionViolation {
                gate: AdmissionGate::VolumeHygiene,
                code: "SCRATCH_VOLUME_VIOLATION".to_owned(),
                message: err.to_string(),
            });
        }
    }

    // Gate 6: Namespace Quota & Kata MicroVM Overhead
    if let Some((quota_spec, usage_snapshot)) = &ctx.quota {
        let cpu_str = workload.spec.cpu.as_deref().unwrap_or("500m");
        let mem_str = workload.spec.memory.as_deref().unwrap_or("512Mi");
        match evaluate_quota_admission(
            quota_spec,
            usage_snapshot,
            1,
            cpu_str,
            mem_str,
            workload.spec.isolation_profile,
        ) {
            Ok(report) => {
                warnings.extend(report.warnings.clone());
                quota_report = Some(report);
            }
            Err(err) => {
                violations.push(AdmissionViolation {
                    gate: AdmissionGate::NamespaceQuota,
                    code: "QUOTA_EXCEEDED".to_owned(),
                    message: err.to_string(),
                });
            }
        }
    }

    // Gate 7: BFT Jury Consensus Receipt
    if let Some(receipt) = &ctx.required_receipt {
        if !receipt.verify_commitment() {
            violations.push(AdmissionViolation {
                gate: AdmissionGate::JuryConsensus,
                code: "JURY_RECEIPT_TAMPERED".to_owned(),
                message: "jury ExecutionReceipt commitment verification failed".to_owned(),
            });
        } else if receipt.outcome != VerdictOutcome::Approve {
            violations.push(AdmissionViolation {
                gate: AdmissionGate::JuryConsensus,
                code: "JURY_QUORUM_REJECTED".to_owned(),
                message: format!(
                    "jury receipt outcome for workload `{}` was {:?}",
                    receipt.workload_id, receipt.outcome
                ),
            });
        }
    }

    let allowed = violations.is_empty();
    let decision_digest =
        compute_decision_digest(&workload_name, &namespace, allowed, &violations, &warnings);

    AdmissionReviewOutcome {
        workload_name,
        namespace,
        allowed,
        violations,
        warnings,
        quota_report,
        decision_digest,
    }
}

fn compute_decision_digest(
    workload_name: &str,
    namespace: &str,
    allowed: bool,
    violations: &[AdmissionViolation],
    warnings: &[String],
) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |bytes: &[u8]| {
        for &b in bytes {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    };
    feed(b"k8.unsigned.gg/admission/v1\0");
    feed(workload_name.as_bytes());
    feed(b"\0");
    feed(namespace.as_bytes());
    feed(b"\0");
    feed(&[u8::from(allowed)]);
    for v in violations {
        feed(v.code.as_bytes());
        feed(b"\0");
        feed(v.message.as_bytes());
        feed(b"\0");
    }
    for w in warnings {
        feed(w.as_bytes());
        feed(b"\0");
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use crate::network::EgressRuleSpec;
    use crate::rbac::ScopedRuleSpec;
    use crate::scheduling::IsolationProfile;
    use crate::AgentWorkloadSpec;

    use super::*;

    fn sample_workload() -> AgentWorkload {
        AgentWorkload::new(
            "eval-agent-01",
            AgentWorkloadSpec {
                image: "ghcr.io/unsigned-gg/k8-runner:v0.1.0".to_owned(),
                command: vec!["/bin/runner".to_owned()],
                args: vec![],
                env: BTreeMap::new(),
                cpu: Some("1000m".to_owned()),
                memory: Some("512Mi".to_owned()),
                gpu: None,
                timeout_seconds: Some(600),
                agent_role: Some("researcher".to_owned()),
                isolation_profile: IsolationProfile::KataMicroVm,
                egress: Some(EgressRuleSpec {
                    allow_dns: true,
                    allowed_cidrs: vec!["10.96.0.0/12".to_owned()],
                    allowed_tcp_ports: vec![443],
                }),
                scratch_volumes: vec![],
                rbac_rules: vec![ScopedRuleSpec {
                    api_group: String::new(),
                    resource: "configmaps".to_owned(),
                    resource_names: vec!["agent-cfg".to_owned()],
                    verbs: vec!["get".to_owned()],
                }],
            },
        )
    }

    #[test]
    fn admits_compliant_workload_and_produces_deterministic_digest() {
        let mut wl = sample_workload();
        wl.metadata.namespace = Some("default".to_owned());

        let signers = vec!["forseti".to_owned(), "mimir".to_owned(), "tyr".to_owned()];
        let commitment = ExecutionReceipt::compute_commitment(
            "eval-agent-01",
            1,
            VerdictOutcome::Approve,
            "deadbeef",
            &signers,
        );
        let receipt = ExecutionReceipt {
            workload_id: "eval-agent-01".to_owned(),
            round: 1,
            outcome: VerdictOutcome::Approve,
            artifact_digest: "deadbeef".to_owned(),
            signers,
            finalized_at_ms: 1_000,
            receipt_commitment: commitment,
        };

        let ctx = AdmissionContext {
            quota: Some((NamespaceQuotaSpec::default(), QuotaUsageSnapshot::default())),
            required_receipt: Some(receipt),
        };

        let out1 = evaluate_workload_admission(&wl, &ctx);
        let out2 = evaluate_workload_admission(&wl, &ctx);
        assert!(out1.allowed);
        assert!(out1.violations.is_empty());
        assert_eq!(out1.decision_digest, out2.decision_digest);
        assert!(out1.quota_report.is_some());
    }

    #[test]
    fn collects_multiple_gate_violations_deterministically() {
        let mut wl = sample_workload();
        wl.metadata.namespace = Some("default".to_owned());
        wl.spec.egress = Some(EgressRuleSpec {
            allow_dns: true,
            allowed_cidrs: vec!["0.0.0.0/0".to_owned()],
            allowed_tcp_ports: vec![443],
        });
        wl.spec.rbac_rules.push(ScopedRuleSpec {
            api_group: String::new(),
            resource: "secrets".to_owned(),
            resource_names: vec![],
            verbs: vec!["list".to_owned()],
        });

        let out = evaluate_workload_admission(&wl, &AdmissionContext::default());
        assert!(!out.allowed);
        assert!(out
            .violations
            .iter()
            .any(|v| v.gate == AdmissionGate::ZeroTrustNetwork));
        assert!(out
            .violations
            .iter()
            .any(|v| v.gate == AdmissionGate::LeastPrivilegeRbac));
    }
}
