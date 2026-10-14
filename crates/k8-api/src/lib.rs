// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `k8-api`: Wave-0 zero-I/O Kubernetes CRD schemas, resource quantities, YAML 1.2 manifests,
//! PodSecurity `restricted` invariants, and BFT jury primitives.

pub mod jury;
pub mod manifest;
pub mod quantity;
pub mod security;
pub mod selector;

pub use jury::{
    EquivocationFault, ExecutionReceipt, JuryError, JuryQuorum, JuryVote, VerdictOutcome,
};
pub use manifest::{
    from_multi_yaml_manifests, from_yaml_manifest, render_multi_yaml_manifests, to_yaml_manifest,
    ManifestError, ManifestHeader, ManifestMetadata,
};
pub use quantity::{
    CpuQuantity, MemoryQuantity, QuantityError, ResourceQuotaSpec, ResourceRequest, ResourceUsage,
};
pub use security::{
    audit_pod_spec_restricted, restricted_container_security_context,
    restricted_pod_security_context, SecurityViolation, DEFAULT_NONROOT_UID,
};
pub use selector::{
    canonical_workload_labels, validate_dns1123_label, validate_label_key, validate_label_value,
    LabelError, LabelSelector, LABEL_AGENT_ROLE, LABEL_APP_NAME, LABEL_MANAGED_BY, LABEL_RUN_ID,
};

use kube::{CustomResource, CustomResourceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Default CPU allocation (`"500m"`) when `AgentWorkloadSpec::cpu` is omitted.
pub const DEFAULT_CPU_MILLICORES: u64 = 500;

/// Default memory allocation (`512Mi`) when `AgentWorkloadSpec::memory` is omitted.
pub const DEFAULT_MEMORY_BYTES: u64 = 512 * 1024 * 1024;

/// Maximum permitted workload timeout (`86_400` seconds = 24 hours).
pub const MAX_TIMEOUT_SECONDS: u64 = 86_400;

/// Validation errors returned by [`AgentWorkloadSpec::validate`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SpecValidationError {
    /// Container image string is empty or contains whitespace.
    #[error("container image '{0}' must be non-empty and free of whitespace")]
    InvalidImage(String),

    /// CPU or memory quantity failed Kubernetes quantity validation.
    #[error("invalid resource quantity in workload spec: {0}")]
    InvalidQuantity(#[from] QuantityError),

    /// Agent role or label failed RFC 1123 DNS validation.
    #[error("invalid label or agent_role in workload spec: {0}")]
    InvalidLabel(#[from] LabelError),

    /// Timeout is zero or exceeds [`MAX_TIMEOUT_SECONDS`].
    #[error("timeout_seconds ({0}) must be between 1 and {MAX_TIMEOUT_SECONDS}")]
    InvalidTimeout(u64),

    /// Environment variable name is empty or contains `=`.
    #[error("environment variable name '{0}' is invalid")]
    InvalidEnvVarName(String),
}

/// Custom Resource Definition for an autonomous agent workload (`agent.unsigned.gg/v1alpha1`).
#[derive(
    CustomResource, Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq, JsonSchema,
)]
#[kube(
    group = "agent.unsigned.gg",
    version = "v1alpha1",
    kind = "AgentWorkload",
    namespaced,
    status = "AgentWorkloadStatus",
    shortname = "aw",
    printcolumn = r#"{"name":"Status", "type":"string", "description":"Status of workload", "jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Image", "type":"string", "description":"Container image", "jsonPath":".spec.image"}"#,
    printcolumn = r#"{"name":"Age", "type":"date", "jsonPath":".metadata.creationTimestamp"}"#
)]
pub struct AgentWorkloadSpec {
    /// Container image to execute.
    pub image: String,

    /// Optional command overrides.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,

    /// Arguments to the command.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,

    /// Environment variables.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,

    /// CPU request/limit (for example `"2000m"` or `"2"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,

    /// Memory request/limit (for example `"4Gi"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,

    /// GPU limit if applicable (for example `1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<u32>,

    /// Execution timeout in seconds (`1..=86_400`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,

    /// Active agent role label (for example `"researcher"`, `"critic"`, `"builder"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_role: Option<String>,
}

impl AgentWorkloadSpec {
    /// Validate all fields of the workload specification fail-closed before cluster dispatch.
    pub fn validate(&self) -> Result<ResourceRequest, SpecValidationError> {
        let trimmed = self.image.trim();
        if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
            return Err(SpecValidationError::InvalidImage(self.image.clone()));
        }

        for key in self.env.keys() {
            if key.trim().is_empty() || key.contains('=') {
                return Err(SpecValidationError::InvalidEnvVarName(key.clone()));
            }
        }

        if let Some(role) = &self.agent_role {
            validate_dns1123_label(role)?;
        }

        if let Some(timeout) = self.timeout_seconds {
            if timeout == 0 || timeout > MAX_TIMEOUT_SECONDS {
                return Err(SpecValidationError::InvalidTimeout(timeout));
            }
        }

        let cpu = match &self.cpu {
            Some(raw) => raw.parse::<CpuQuantity>()?,
            None => CpuQuantity::from_millicores(DEFAULT_CPU_MILLICORES),
        };

        let memory = match &self.memory {
            Some(raw) => raw.parse::<MemoryQuantity>()?,
            None => MemoryQuantity::from_bytes(DEFAULT_MEMORY_BYTES),
        };

        Ok(ResourceRequest {
            cpu,
            memory,
            gpu: self.gpu.unwrap_or(0),
        })
    }
}

impl AgentWorkload {
    /// Render the canonical `CustomResourceDefinition` YAML 1.2 document for `AgentWorkload`.
    pub fn crd_yaml() -> Result<String, ManifestError> {
        to_yaml_manifest(&Self::crd())
    }
}

/// Execution lifecycle phase for an [`AgentWorkload`].
#[derive(Serialize, Deserialize, Default, Clone, Copy, Debug, PartialEq, Eq, JsonSchema)]
pub enum WorkloadPhase {
    /// Workload has been accepted but no pod is running yet.
    #[default]
    Pending,
    /// Workload container is actively executing.
    Running,
    /// Workload completed with exit code `0`.
    Succeeded,
    /// Workload failed with a non-zero exit code or deadline breach.
    Failed,
    /// Workload was explicitly terminated by an operator or controller.
    Terminated,
}

/// Structured Kubernetes status condition attached to an [`AgentWorkloadStatus`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadCondition {
    /// Condition type (for example `"Ready"`, `"Sandboxed"`, `"JuryVerified"`).
    pub type_: String,
    /// Condition status (`"True"`, `"False"`, or `"Unknown"`).
    pub status: String,
    /// Machine-readable UpperCamelCase reason token.
    pub reason: String,
    /// Human-readable diagnostic message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// ISO-8601 timestamp of the last transition.
    pub last_transition_time: String,
}

/// Status block of an [`AgentWorkload`].
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct AgentWorkloadStatus {
    /// Current lifecycle phase.
    pub phase: WorkloadPhase,

    /// Pod or Job name backing this workload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_name: Option<String>,

    /// Exit code if execution completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,

    /// Diagnostic message or error explanation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Start timestamp (ISO-8601).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,

    /// Completion timestamp (ISO-8601).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,

    /// Standard Kubernetes condition observations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<WorkloadCondition>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_workload_phase_default() {
        assert_eq!(WorkloadPhase::default(), WorkloadPhase::Pending);
    }

    #[test]
    fn test_agent_workload_crd_metadata_and_yaml() {
        let crd = AgentWorkload::crd();
        assert_eq!(crd.spec.group, "agent.unsigned.gg");
        assert_eq!(crd.spec.names.kind, "AgentWorkload");
        assert_eq!(crd.spec.names.short_names, Some(vec!["aw".to_string()]));

        let yaml = AgentWorkload::crd_yaml().expect("render CRD YAML via serde-saphyr");
        assert!(yaml.contains("agent.unsigned.gg"));
        assert!(yaml.contains("AgentWorkload"));
    }

    #[test]
    fn test_spec_validation_and_serialization_roundtrip() {
        let mut env = BTreeMap::new();
        env.insert("AGENT_ROLE".to_string(), "arbitrator".to_string());

        let spec = AgentWorkloadSpec {
            image: "ghcr.io/unsigned-gg/agent:latest".to_string(),
            command: vec!["agent".to_string()],
            args: vec!["--verify".to_string()],
            env,
            cpu: Some("2000m".to_string()),
            memory: Some("4Gi".to_string()),
            gpu: Some(1),
            timeout_seconds: Some(3600),
            agent_role: Some("researcher".to_string()),
        };

        let req = spec.validate().expect("valid spec");
        assert_eq!(req.cpu.millicores(), 2_000);
        assert_eq!(req.memory.bytes(), 4 * 1024 * 1024 * 1024);
        assert_eq!(req.gpu, 1);

        let yaml = to_yaml_manifest(&spec).expect("serialize YAML");
        let parsed: AgentWorkloadSpec = from_yaml_manifest(&yaml).expect("deserialize YAML");
        assert_eq!(parsed, spec);
    }

    #[test]
    fn test_spec_validation_rejects_malformed_inputs() {
        let bad_image = AgentWorkloadSpec {
            image: "   ".to_string(),
            ..Default::default()
        };
        assert!(matches!(
            bad_image.validate(),
            Err(SpecValidationError::InvalidImage(_))
        ));

        let bad_role = AgentWorkloadSpec {
            image: "ghcr.io/unsigned-gg/agent:latest".to_string(),
            agent_role: Some("Invalid_Role".to_string()),
            ..Default::default()
        };
        assert!(matches!(
            bad_role.validate(),
            Err(SpecValidationError::InvalidLabel(_))
        ));

        let bad_timeout = AgentWorkloadSpec {
            image: "ghcr.io/unsigned-gg/agent:latest".to_string(),
            timeout_seconds: Some(0),
            ..Default::default()
        };
        assert!(matches!(
            bad_timeout.validate(),
            Err(SpecValidationError::InvalidTimeout(0))
        ));
    }

    #[test]
    fn test_status_serialization_roundtrip() {
        let status = AgentWorkloadStatus {
            phase: WorkloadPhase::Running,
            pod_name: Some("agent-run-1".to_string()),
            exit_code: None,
            message: Some("Execution active".to_string()),
            started_at: Some("2026-10-12T00:00:00Z".to_string()),
            completed_at: None,
            conditions: vec![WorkloadCondition {
                type_: "Sandboxed".to_string(),
                status: "True".to_string(),
                reason: "PodSecurityRestricted".to_string(),
                message: None,
                last_transition_time: "2026-10-12T00:00:00Z".to_string(),
            }],
        };

        let json = serde_json::to_string(&status).expect("serialize status");
        let parsed: AgentWorkloadStatus = serde_json::from_str(&json).expect("deserialize status");
        assert_eq!(parsed, status);
    }
}
