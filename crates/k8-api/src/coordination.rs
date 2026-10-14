// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Pure zero-I/O Kubernetes controller coordination, leader-election `Lease` state machine,
//! deterministic exponential backoff, and structured `Event` synthesis (`SPEC-0004`).

use std::collections::BTreeMap;

use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::api::core::v1::{Event, ObjectReference};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::ResourceExt;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::selector::{validate_dns1123_label, LabelError};
use crate::AgentWorkload;

/// Default controller `Lease` duration in seconds (`15s`).
pub const DEFAULT_LEASE_DURATION_SECONDS: u32 = 15;

/// Annotation key storing the virtual monotonic acquire timestamp in milliseconds.
pub const ANNOTATION_LEASE_ACQUIRE_MS: &str = "agent.unsigned.gg/acquire-time-ms";

/// Annotation key storing the virtual monotonic renew timestamp in milliseconds.
pub const ANNOTATION_LEASE_RENEW_MS: &str = "agent.unsigned.gg/renew-time-ms";

/// Errors returned by controller coordination, lease election, or event builders.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CoordinationError {
    /// Resource name, namespace, or candidate holder identity failed DNS-1123 validation.
    #[error("invalid coordination identifier: {0}")]
    InvalidIdentifier(#[from] LabelError),

    /// Lease duration must be between 1 and 3,600 seconds.
    #[error("lease_duration_seconds ({0}) must be between 1 and 3600")]
    InvalidLeaseDuration(u32),

    /// Event reason or message is empty.
    #[error("event field `{0}` must not be empty")]
    EmptyEventField(&'static str),
}

/// Point-in-time state of a `coordination.k8s.io/v1` `Lease` object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LeaseStateSnapshot {
    /// Lease `metadata.name` (DNS-1123 label).
    pub lease_name: String,
    /// Lease `metadata.namespace` (DNS-1123 label).
    pub namespace: String,
    /// Current leader holder identity (`None` when unheld).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_identity: Option<String>,
    /// Lease duration in seconds.
    pub lease_duration_seconds: u32,
    /// Virtual monotonic timestamp (ms) when the current holder acquired the lease.
    pub acquire_time_ms: u64,
    /// Virtual monotonic timestamp (ms) when the current holder last renewed the lease.
    pub renew_time_ms: u64,
    /// Total count of leader transitions (`spec.leaseTransitions`).
    pub lease_transitions: u32,
}

impl LeaseStateSnapshot {
    /// Returns the virtual monotonic expiration timestamp in milliseconds (`renew_time_ms + duration_ms`).
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        let duration_ms = (self.lease_duration_seconds as u64).saturating_mul(1_000);
        self.renew_time_ms.saturating_add(duration_ms)
    }

    /// Returns `true` if the lease is expired at `now_ms` (`now_ms >= expires_at_ms()`).
    #[must_use]
    pub const fn is_expired_at(&self, now_ms: u64) -> bool {
        self.holder_identity.is_none() || now_ms >= self.expires_at_ms()
    }
}

/// Deterministic decision of [`evaluate_lease_transition`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LeaseDecision {
    /// Candidate acquired an unheld lease for the first time.
    Acquire,
    /// Existing leader renewed its own active or expired lease without incrementing `lease_transitions`.
    Renew,
    /// Candidate preempted an expired lease previously held by another replica, incrementing `lease_transitions`.
    PreemptExpired {
        /// Identity of the previous expired holder.
        previous_holder: String,
    },
    /// Lease is actively held by another replica and has not expired at `now_ms`.
    Standby {
        /// Current active leader identity.
        holder: String,
        /// Milliseconds remaining until lease expiration.
        remaining_ms: u64,
    },
}

/// Outcome of a pure leader-election transition evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LeaseTransitionOutcome {
    /// Decision taken at `now_ms`.
    pub decision: LeaseDecision,
    /// Resulting `LeaseStateSnapshot` after applying the decision.
    pub next_state: LeaseStateSnapshot,
    /// `true` iff `candidate_id` is the active leader after this transition.
    pub is_leader: bool,
}

/// Evaluates a pure zero-I/O leader-election transition for `candidate_id` at `now_ms` (`SPEC-0004`).
///
/// # Errors
///
/// Returns [`CoordinationError`] if `lease_name`, `namespace`, or `candidate_id` is not a valid
/// RFC 1123 DNS label, or if `lease_duration_seconds` is outside `1..=3600`.
pub fn evaluate_lease_transition(
    lease_name: &str,
    namespace: &str,
    current: Option<&LeaseStateSnapshot>,
    candidate_id: &str,
    now_ms: u64,
    lease_duration_seconds: u32,
) -> Result<LeaseTransitionOutcome, CoordinationError> {
    validate_dns1123_label(lease_name)?;
    validate_dns1123_label(namespace)?;
    validate_dns1123_label(candidate_id)?;
    if lease_duration_seconds == 0 || lease_duration_seconds > 3_600 {
        return Err(CoordinationError::InvalidLeaseDuration(
            lease_duration_seconds,
        ));
    }

    match current {
        None => {
            let next_state = LeaseStateSnapshot {
                lease_name: lease_name.to_owned(),
                namespace: namespace.to_owned(),
                holder_identity: Some(candidate_id.to_owned()),
                lease_duration_seconds,
                acquire_time_ms: now_ms,
                renew_time_ms: now_ms,
                lease_transitions: 0,
            };
            Ok(LeaseTransitionOutcome {
                decision: LeaseDecision::Acquire,
                next_state,
                is_leader: true,
            })
        }
        Some(state) => match state.holder_identity.as_deref() {
            None => {
                let next_state = LeaseStateSnapshot {
                    lease_name: lease_name.to_owned(),
                    namespace: namespace.to_owned(),
                    holder_identity: Some(candidate_id.to_owned()),
                    lease_duration_seconds,
                    acquire_time_ms: now_ms,
                    renew_time_ms: now_ms,
                    lease_transitions: state.lease_transitions.saturating_add(1),
                };
                Ok(LeaseTransitionOutcome {
                    decision: LeaseDecision::Acquire,
                    next_state,
                    is_leader: true,
                })
            }
            Some(holder) if holder == candidate_id => {
                let next_state = LeaseStateSnapshot {
                    lease_name: lease_name.to_owned(),
                    namespace: namespace.to_owned(),
                    holder_identity: Some(candidate_id.to_owned()),
                    lease_duration_seconds,
                    acquire_time_ms: state.acquire_time_ms,
                    renew_time_ms: now_ms.max(state.renew_time_ms),
                    lease_transitions: state.lease_transitions,
                };
                Ok(LeaseTransitionOutcome {
                    decision: LeaseDecision::Renew,
                    next_state,
                    is_leader: true,
                })
            }
            Some(holder) => {
                let expires_at = state.expires_at_ms();
                if now_ms >= expires_at {
                    let next_state = LeaseStateSnapshot {
                        lease_name: lease_name.to_owned(),
                        namespace: namespace.to_owned(),
                        holder_identity: Some(candidate_id.to_owned()),
                        lease_duration_seconds,
                        acquire_time_ms: now_ms,
                        renew_time_ms: now_ms,
                        lease_transitions: state.lease_transitions.saturating_add(1),
                    };
                    Ok(LeaseTransitionOutcome {
                        decision: LeaseDecision::PreemptExpired {
                            previous_holder: holder.to_owned(),
                        },
                        next_state,
                        is_leader: true,
                    })
                } else {
                    Ok(LeaseTransitionOutcome {
                        decision: LeaseDecision::Standby {
                            holder: holder.to_owned(),
                            remaining_ms: expires_at.saturating_sub(now_ms),
                        },
                        next_state: state.clone(),
                        is_leader: false,
                    })
                }
            }
        },
    }
}

/// Synthesizes a typed Kubernetes `coordination.k8s.io/v1` `Lease` resource from a [`LeaseStateSnapshot`].
///
/// # Errors
///
/// Returns [`CoordinationError`] if `lease_name`, `namespace`, or `holder_identity` is invalid.
pub fn build_controller_lease(state: &LeaseStateSnapshot) -> Result<Lease, CoordinationError> {
    validate_dns1123_label(&state.lease_name)?;
    validate_dns1123_label(&state.namespace)?;
    if let Some(holder) = &state.holder_identity {
        validate_dns1123_label(holder)?;
    }
    if state.lease_duration_seconds == 0 || state.lease_duration_seconds > 3_600 {
        return Err(CoordinationError::InvalidLeaseDuration(
            state.lease_duration_seconds,
        ));
    }

    let mut annotations = BTreeMap::new();
    annotations.insert(
        ANNOTATION_LEASE_ACQUIRE_MS.to_owned(),
        state.acquire_time_ms.to_string(),
    );
    annotations.insert(
        ANNOTATION_LEASE_RENEW_MS.to_owned(),
        state.renew_time_ms.to_string(),
    );

    let duration_i32 = i32::try_from(state.lease_duration_seconds).unwrap_or(3_600);
    let transitions_i32 = i32::try_from(state.lease_transitions).unwrap_or(i32::MAX);

    Ok(Lease {
        metadata: ObjectMeta {
            name: Some(state.lease_name.clone()),
            namespace: Some(state.namespace.clone()),
            annotations: Some(annotations),
            ..Default::default()
        },
        spec: Some(LeaseSpec {
            holder_identity: state.holder_identity.clone(),
            lease_duration_seconds: Some(duration_i32),
            lease_transitions: Some(transitions_i32),
            ..Default::default()
        }),
    })
}

/// Deterministic exponential backoff policy for controller error requeue scheduling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BackoffPolicy {
    /// Initial retry delay in milliseconds (e.g. `1_000` = 1s).
    pub base_delay_ms: u64,
    /// Hard upper ceiling in milliseconds (e.g. `300_000` = 5m).
    pub max_delay_ms: u64,
    /// Maximum bit shift exponent (`0..=20`, default `10`).
    pub max_exponent: u32,
    /// Deterministic additive jitter ceiling in permille of the computed base delay (`0..=500`).
    pub jitter_permille: u16,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            base_delay_ms: 1_000,
            max_delay_ms: 300_000,
            max_exponent: 10,
            jitter_permille: 100,
        }
    }
}

/// Computes a deterministic controller requeue delay in milliseconds with seeded `SplitMix64` jitter.
#[must_use]
pub const fn compute_requeue_delay_ms(
    policy: &BackoffPolicy,
    failure_count: u32,
    jitter_seed: u64,
) -> u64 {
    let shift = if failure_count > policy.max_exponent {
        policy.max_exponent
    } else {
        failure_count
    };
    let shift_capped = if shift > 30 { 30 } else { shift };
    let multiplier = 1_u64 << shift_capped;
    let raw_delay = policy.base_delay_ms.saturating_mul(multiplier);
    let capped_base = if raw_delay > policy.max_delay_ms {
        policy.max_delay_ms
    } else {
        raw_delay
    };

    if policy.jitter_permille == 0 {
        return capped_base;
    }

    // Deterministic SplitMix64 mix on (jitter_seed ^ failure_count)
    let mut z = jitter_seed
        .wrapping_add((failure_count as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15))
        .wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    let rand_u64 = z ^ (z >> 31);

    let max_jitter_permille = if policy.jitter_permille > 500 {
        500_u64
    } else {
        policy.jitter_permille as u64
    };
    let chosen_permille = rand_u64 % (max_jitter_permille + 1);
    let jitter_ms = capped_base.saturating_mul(chosen_permille) / 1_000;
    let with_jitter = capped_base.saturating_add(jitter_ms);
    if with_jitter > policy.max_delay_ms {
        policy.max_delay_ms
    } else {
        with_jitter
    }
}

/// Severity type of a Kubernetes controller `Event`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum EventSeverity {
    /// Normal informational lifecycle transition (`"Normal"`).
    Normal,
    /// Warning or admission/policy rejection (`"Warning"`).
    Warning,
}

impl EventSeverity {
    /// Returns the canonical Kubernetes `Event.type` string (`"Normal"` or `"Warning"`).
    #[must_use]
    pub const fn as_k8s_str(self) -> &'static str {
        match self {
            Self::Normal => "Normal",
            Self::Warning => "Warning",
        }
    }
}

/// Specification for synthesizing a structured Kubernetes `core/v1::Event` for an [`AgentWorkload`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WorkloadEventSpec {
    /// Short CamelCase machine reason (e.g. `"AdmissionDenied"`, `"ChildJobApplied"`).
    pub reason: String,
    /// Human-readable event description.
    pub message: String,
    /// Event severity (`Normal` or `Warning`).
    pub severity: EventSeverity,
    /// Controller component name (e.g. `"k8-orchestrator"`).
    pub reporting_controller: String,
    /// Controller replica instance ID (e.g. `"k8-orchestrator-0"`).
    pub reporting_instance: String,
    /// Action taken by the controller (e.g. `"Reconcile"`, `"Admit"`).
    pub action: String,
}

/// Synthesizes a deterministic Kubernetes `core/v1::Event` referencing `workload` (`SPEC-0004`).
///
/// # Errors
///
/// Returns [`CoordinationError`] if `workload` lacks a valid DNS-1123 name or if `reason`/`message`
/// is empty.
pub fn build_workload_event(
    workload: &AgentWorkload,
    spec: &WorkloadEventSpec,
) -> Result<Event, CoordinationError> {
    let name = workload.name_any();
    validate_dns1123_label(&name)?;
    let namespace = workload.namespace().unwrap_or_else(|| "default".to_owned());
    validate_dns1123_label(&namespace)?;

    if spec.reason.trim().is_empty() {
        return Err(CoordinationError::EmptyEventField("reason"));
    }
    if spec.message.trim().is_empty() {
        return Err(CoordinationError::EmptyEventField("message"));
    }

    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in name
        .as_bytes()
        .iter()
        .chain(spec.reason.as_bytes())
        .chain(spec.message.as_bytes())
    {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    let suffix = format!("{:08x}", (hash & 0xffff_ffff) as u32);
    let event_name = format!("{name}.{suffix}");

    Ok(Event {
        metadata: ObjectMeta {
            name: Some(event_name),
            namespace: Some(namespace.clone()),
            ..Default::default()
        },
        involved_object: ObjectReference {
            api_version: Some("agent.unsigned.gg/v1alpha1".to_owned()),
            kind: Some("AgentWorkload".to_owned()),
            name: Some(name),
            namespace: Some(namespace),
            uid: workload.metadata.uid.clone(),
            resource_version: workload.metadata.resource_version.clone(),
            ..Default::default()
        },
        reason: Some(spec.reason.clone()),
        message: Some(spec.message.clone()),
        type_: Some(spec.severity.as_k8s_str().to_owned()),
        reporting_component: Some(spec.reporting_controller.clone()),
        reporting_instance: Some(spec.reporting_instance.clone()),
        action: Some(spec.action.clone()),
        ..Default::default()
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::AgentWorkloadSpec;

    #[test]
    fn lease_election_enforces_mutual_exclusion_and_preemption() {
        // 1. Initial acquire by replica-a at t=1000ms for 15s (expires at 16000ms)
        let out1 = evaluate_lease_transition(
            "k8-controller-lock",
            "kube-system",
            None,
            "replica-a",
            1_000,
            15,
        )
        .unwrap();
        assert!(out1.is_leader);
        assert_eq!(out1.decision, LeaseDecision::Acquire);
        assert_eq!(out1.next_state.lease_transitions, 0);

        // 2. Competing replica-b at t=5000ms must stand by
        let out2 = evaluate_lease_transition(
            "k8-controller-lock",
            "kube-system",
            Some(&out1.next_state),
            "replica-b",
            5_000,
            15,
        )
        .unwrap();
        assert!(!out2.is_leader);
        assert_eq!(
            out2.decision,
            LeaseDecision::Standby {
                holder: "replica-a".to_owned(),
                remaining_ms: 11_000,
            }
        );

        // 3. Leader replica-a renews at t=10000ms (transitions stays 0, expires at 25000ms)
        let out3 = evaluate_lease_transition(
            "k8-controller-lock",
            "kube-system",
            Some(&out2.next_state),
            "replica-a",
            10_000,
            15,
        )
        .unwrap();
        assert!(out3.is_leader);
        assert_eq!(out3.decision, LeaseDecision::Renew);
        assert_eq!(out3.next_state.lease_transitions, 0);
        assert_eq!(out3.next_state.expires_at_ms(), 25_000);

        // 4. At t=25000ms lease expires; replica-b preempts and increments lease_transitions to 1
        let out4 = evaluate_lease_transition(
            "k8-controller-lock",
            "kube-system",
            Some(&out3.next_state),
            "replica-b",
            25_000,
            15,
        )
        .unwrap();
        assert!(out4.is_leader);
        assert_eq!(
            out4.decision,
            LeaseDecision::PreemptExpired {
                previous_holder: "replica-a".to_owned(),
            }
        );
        assert_eq!(out4.next_state.lease_transitions, 1);

        let lease_obj = build_controller_lease(&out4.next_state).unwrap();
        assert_eq!(
            lease_obj.spec.as_ref().unwrap().holder_identity.as_deref(),
            Some("replica-b")
        );
        assert_eq!(lease_obj.spec.as_ref().unwrap().lease_transitions, Some(1));
    }

    #[test]
    fn backoff_and_workload_event_builder_are_deterministic() {
        let policy = BackoffPolicy::default();
        let d0 = compute_requeue_delay_ms(&policy, 0, 42);
        let d3 = compute_requeue_delay_ms(&policy, 3, 42);
        let d20 = compute_requeue_delay_ms(&policy, 20, 42);
        assert!((1_000..=1_100).contains(&d0));
        assert!((8_000..=8_800).contains(&d3));
        assert_eq!(d20, policy.max_delay_ms);

        let mut wl = AgentWorkload::new(
            "agent-ev",
            AgentWorkloadSpec {
                image: "ghcr.io/unsigned-gg/agent:v1".to_owned(),
                ..Default::default()
            },
        );
        wl.metadata.namespace = Some("agents".to_owned());
        let ev = build_workload_event(
            &wl,
            &WorkloadEventSpec {
                reason: "AdmissionDenied".to_owned(),
                message: "Namespace quota exceeded".to_owned(),
                severity: EventSeverity::Warning,
                reporting_controller: "k8-orchestrator".to_owned(),
                reporting_instance: "k8-orchestrator-0".to_owned(),
                action: "Admit".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(ev.type_.as_deref(), Some("Warning"));
        assert_eq!(ev.involved_object.name.as_deref(), Some("agent-ev"));
    }
}
