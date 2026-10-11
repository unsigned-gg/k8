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
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub enum WorkloadPhase {
    Pending,
    Running,
    Succeeded,
    Failed,
    Terminated,
}

impl Default for WorkloadPhase {
    fn default() -> Self {
        Self::Pending
    }
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
