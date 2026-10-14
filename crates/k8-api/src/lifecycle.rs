// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Zero-I/O Kubernetes `OwnerReference` construction, finalizer state transitions,
//! and monotonic `WorkloadCondition` algebra (`SPEC-0002`).

use crate::{AgentWorkload, WorkloadCondition};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use thiserror::Error;

/// Canonical Kubernetes finalizer guarding child Job and NetworkPolicy cleanup for `AgentWorkload`.
pub const FINALIZER_WORKLOAD_CLEANUP: &str = "agent.unsigned.gg/workload-cleanup";

/// Canonical API version for `AgentWorkload` custom resources.
pub const AGENT_WORKLOAD_API_VERSION: &str = "agent.unsigned.gg/v1alpha1";

/// Canonical Kind for `AgentWorkload` custom resources.
pub const AGENT_WORKLOAD_KIND: &str = "AgentWorkload";

/// Condition type indicating that the workload specification passed validation.
pub const CONDITION_ACCEPTED: &str = "Accepted";

/// Condition type indicating that `PodSecurity` `restricted` and `NetworkPolicy` invariants are active.
pub const CONDITION_SANDBOXED: &str = "Sandboxed";

/// Condition type indicating that the backing Kubernetes `Job` has been dispatched.
pub const CONDITION_DISPATCHED: &str = "JobDispatched";

/// Condition type indicating that the `3f + 1` Byzantine jury quorum verified the workload output.
pub const CONDITION_JURY_VERIFIED: &str = "JuryVerified";

/// Top-level Kubernetes readiness condition type.
pub const CONDITION_READY: &str = "Ready";

/// Errors returned by Kubernetes lifecycle and ownership primitives.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    /// Required metadata field (`metadata.name` or `metadata.uid`) is missing or empty.
    #[error("required Kubernetes ObjectMeta field '{0}' is missing or empty")]
    MissingMetadataField(&'static str),
}

/// Construct a controller [`OwnerReference`] pointing to `workload` with foreground deletion blocking.
pub fn controller_owner_reference(
    workload: &AgentWorkload,
) -> Result<OwnerReference, LifecycleError> {
    let name = workload
        .metadata
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(LifecycleError::MissingMetadataField("metadata.name"))?;

    let uid = workload
        .metadata
        .uid
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(LifecycleError::MissingMetadataField("metadata.uid"))?;

    Ok(OwnerReference {
        api_version: AGENT_WORKLOAD_API_VERSION.to_string(),
        kind: AGENT_WORKLOAD_KIND.to_string(),
        name: name.to_string(),
        uid: uid.to_string(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    })
}

/// Check whether `meta` carries a controller [`OwnerReference`] matching `owner_uid`.
#[must_use]
pub fn has_controller_owner_reference(meta: &ObjectMeta, owner_uid: &str) -> bool {
    meta.owner_references.as_ref().is_some_and(|refs| {
        refs.iter().any(|r| {
            r.uid == owner_uid
                && r.kind == AGENT_WORKLOAD_KIND
                && r.controller == Some(true)
                && r.block_owner_deletion == Some(true)
        })
    })
}

/// Return `true` if `meta` is marked for deletion (`deletionTimestamp` is present).
#[must_use]
pub fn is_deleting(meta: &ObjectMeta) -> bool {
    meta.deletion_timestamp.is_some()
}

/// Return `true` if `meta` contains [`FINALIZER_WORKLOAD_CLEANUP`].
#[must_use]
pub fn has_cleanup_finalizer(meta: &ObjectMeta) -> bool {
    meta.finalizers
        .as_ref()
        .is_some_and(|list| list.iter().any(|f| f == FINALIZER_WORKLOAD_CLEANUP))
}

/// Ensure [`FINALIZER_WORKLOAD_CLEANUP`] is present in `meta.finalizers`.
///
/// Returns `true` if the finalizer was inserted, or `false` if it was already present.
pub fn ensure_cleanup_finalizer(meta: &mut ObjectMeta) -> bool {
    if has_cleanup_finalizer(meta) {
        return false;
    }
    let list = meta.finalizers.get_or_insert_with(Vec::new);
    list.push(FINALIZER_WORKLOAD_CLEANUP.to_string());
    true
}

/// Remove [`FINALIZER_WORKLOAD_CLEANUP`] from `meta.finalizers`.
///
/// Returns `true` if the finalizer was removed, or `false` if it was not present.
pub fn remove_cleanup_finalizer(meta: &mut ObjectMeta) -> bool {
    let Some(list) = meta.finalizers.as_mut() else {
        return false;
    };
    let before = list.len();
    list.retain(|f| f != FINALIZER_WORKLOAD_CLEANUP);
    let removed = list.len() != before;
    if list.is_empty() {
        meta.finalizers = None;
    }
    removed
}

/// Upsert a [`WorkloadCondition`] into `conditions`, preserving `last_transition_time` when
/// `status` is unchanged (`SPEC-0002` Invariant 1) and maintaining deterministic lexicographical order.
pub fn upsert_condition(conditions: &mut Vec<WorkloadCondition>, next: WorkloadCondition) {
    if let Some(existing) = conditions.iter_mut().find(|c| c.type_ == next.type_) {
        if existing.status == next.status {
            existing.reason = next.reason;
            existing.message = next.message;
        } else {
            *existing = next;
        }
    } else {
        conditions.push(next);
        conditions.sort_by(|a, b| a.type_.cmp(&b.type_));
    }
}

/// Find a condition by `type_` in `conditions`.
#[must_use]
pub fn find_condition<'a>(
    conditions: &'a [WorkloadCondition],
    type_: &str,
) -> Option<&'a WorkloadCondition> {
    conditions.iter().find(|c| c.type_ == type_)
}

/// Return `true` if `conditions` contains a condition of `type_` with `status == "True"`.
#[must_use]
pub fn is_condition_true(conditions: &[WorkloadCondition], type_: &str) -> bool {
    find_condition(conditions, type_).is_some_and(|c| c.status == "True")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::AgentWorkloadSpec;

    fn sample_workload(name: Option<&str>, uid: Option<&str>) -> AgentWorkload {
        AgentWorkload {
            metadata: ObjectMeta {
                name: name.map(str::to_string),
                uid: uid.map(str::to_string),
                ..Default::default()
            },
            spec: AgentWorkloadSpec {
                image: "ghcr.io/unsigned-gg/agent:latest".to_string(),
                ..Default::default()
            },
            status: None,
        }
    }

    #[test]
    fn test_controller_owner_reference_success_and_missing_fields() {
        let wl = sample_workload(Some("aw-alpha"), Some("uid-1234"));
        let owner = controller_owner_reference(&wl).expect("valid owner ref");
        assert_eq!(owner.api_version, AGENT_WORKLOAD_API_VERSION);
        assert_eq!(owner.kind, AGENT_WORKLOAD_KIND);
        assert_eq!(owner.name, "aw-alpha");
        assert_eq!(owner.uid, "uid-1234");
        assert_eq!(owner.controller, Some(true));
        assert_eq!(owner.block_owner_deletion, Some(true));

        let child_meta = ObjectMeta {
            owner_references: Some(vec![owner]),
            ..Default::default()
        };
        assert!(has_controller_owner_reference(&child_meta, "uid-1234"));
        assert!(!has_controller_owner_reference(&child_meta, "uid-other"));

        let missing_uid = sample_workload(Some("aw-alpha"), None);
        assert_eq!(
            controller_owner_reference(&missing_uid),
            Err(LifecycleError::MissingMetadataField("metadata.uid"))
        );
    }

    #[test]
    fn test_finalizer_state_transitions_idempotent() {
        let mut meta = ObjectMeta::default();
        assert!(!has_cleanup_finalizer(&meta));
        assert!(ensure_cleanup_finalizer(&mut meta));
        assert!(has_cleanup_finalizer(&meta));
        assert!(!ensure_cleanup_finalizer(&mut meta));

        assert!(remove_cleanup_finalizer(&mut meta));
        assert!(!has_cleanup_finalizer(&meta));
        assert!(meta.finalizers.is_none());
        assert!(!remove_cleanup_finalizer(&mut meta));
    }

    #[test]
    fn test_upsert_condition_preserves_transition_time_when_status_unchanged() {
        let mut conditions = Vec::new();
        upsert_condition(
            &mut conditions,
            WorkloadCondition {
                type_: CONDITION_READY.to_string(),
                status: "False".to_string(),
                reason: "CreatingJob".to_string(),
                message: Some("Job dispatch in progress".to_string()),
                last_transition_time: "2026-10-14T00:00:00Z".to_string(),
            },
        );
        assert!(!is_condition_true(&conditions, CONDITION_READY));

        // Same status ("False"), new reason and later timestamp -> timestamp MUST stay 00:00:00Z
        upsert_condition(
            &mut conditions,
            WorkloadCondition {
                type_: CONDITION_READY.to_string(),
                status: "False".to_string(),
                reason: "PodPending".to_string(),
                message: Some("Waiting for container startup".to_string()),
                last_transition_time: "2026-10-14T00:05:00Z".to_string(),
            },
        );
        let ready = find_condition(&conditions, CONDITION_READY).expect("Ready present");
        assert_eq!(ready.reason, "PodPending");
        assert_eq!(ready.last_transition_time, "2026-10-14T00:00:00Z");

        // Status changes to "True" -> timestamp MUST advance to 00:10:00Z
        upsert_condition(
            &mut conditions,
            WorkloadCondition {
                type_: CONDITION_READY.to_string(),
                status: "True".to_string(),
                reason: "PodRunning".to_string(),
                message: None,
                last_transition_time: "2026-10-14T00:10:00Z".to_string(),
            },
        );
        assert!(is_condition_true(&conditions, CONDITION_READY));
        let ready_after = find_condition(&conditions, CONDITION_READY).expect("Ready present");
        assert_eq!(ready_after.last_transition_time, "2026-10-14T00:10:00Z");
    }
}
