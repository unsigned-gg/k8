// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `k8-api`: Typed API specifications and CRDs for autonomous agent workloads on Kubernetes.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Custom Resource Definition for an autonomous agent workload.
#[derive(CustomResource, Serialize, Deserialize, Default, Clone, Debug, JsonSchema)]
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

    /// CPU limit (e.g. "2000m" or "2").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,

    /// Memory limit (e.g. "4Gi").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,

    /// GPU limit if applicable (e.g. "1").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<u32>,

    /// Execution timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,

    /// Active agent role label (e.g. "researcher", "critic", "builder").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_role: Option<String>,
}

/// Execution phase for an AgentWorkload.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub enum WorkloadPhase {
    #[default]
    Pending,
    Running,
    Succeeded,
    Failed,
    Terminated,
}

/// Status block of an AgentWorkload.
#[derive(Serialize, Deserialize, Default, Clone, Debug, JsonSchema)]
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

    /// Start timestamp (ISO8601).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,

    /// Completion timestamp (ISO8601).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    #[test]
    fn test_workload_phase_default() {
        assert_eq!(WorkloadPhase::default(), WorkloadPhase::Pending);
    }

    #[test]
    fn test_agent_workload_crd_metadata() {
        let crd = AgentWorkload::crd();
        assert_eq!(crd.spec.group, "agent.unsigned.gg");
        assert_eq!(crd.spec.names.kind, "AgentWorkload");
        assert_eq!(crd.spec.names.short_names, Some(vec!["aw".to_string()]));
    }

    #[test]
    fn test_spec_serialization_roundtrip() {
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

        let json = serde_json::to_string(&spec).expect("serialize spec");
        let parsed: AgentWorkloadSpec = serde_json::from_str(&json).expect("deserialize spec");

        assert_eq!(parsed.image, spec.image);
        assert_eq!(parsed.command, spec.command);
        assert_eq!(parsed.args, spec.args);
        assert_eq!(
            parsed.env.get("AGENT_ROLE"),
            Some(&"arbitrator".to_string())
        );
        assert_eq!(parsed.cpu, Some("2000m".to_string()));
        assert_eq!(parsed.memory, Some("4Gi".to_string()));
        assert_eq!(parsed.gpu, Some(1));
        assert_eq!(parsed.timeout_seconds, Some(3600));
        assert_eq!(parsed.agent_role, Some("researcher".to_string()));
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
        };

        let json = serde_json::to_string(&status).expect("serialize status");
        let parsed: AgentWorkloadStatus = serde_json::from_str(&json).expect("deserialize status");

        assert_eq!(parsed.phase, WorkloadPhase::Running);
        assert_eq!(parsed.pod_name, Some("agent-run-1".to_string()));
        assert_eq!(parsed.message, Some("Execution active".to_string()));
    }
}
