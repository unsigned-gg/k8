// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Pure zero-I/O `AgentWorkload` controller reconciliation state machine (`SPEC-0002`).
//!
//! Separates cluster state transitions $T: S \times E \to (S, \text{Effects})$ from network I/O,
//! satisfying Barbara Liskov's behavioral subtyping and deterministic verification invariants.

use crate::Orchestrator;
use k8_api::{
    build_dedicated_service_account, build_isolated_network_policy, build_scoped_role,
    build_scoped_role_binding, build_workload_event, canonical_workload_labels,
    controller_owner_reference, evaluate_workload_admission, has_cleanup_finalizer, is_deleting,
    upsert_condition, AdmissionContext, AgentWorkload, AgentWorkloadStatus, EventSeverity,
    ExecutionReceipt, VerdictOutcome, WorkloadCondition, WorkloadEventSpec, WorkloadPhase,
    CONDITION_ACCEPTED, CONDITION_DISPATCHED, CONDITION_JURY_VERIFIED, CONDITION_READY,
    CONDITION_SANDBOXED,
};
use k8_core::{K8Error, Result};
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::{Event, ServiceAccount};
use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::api::rbac::v1::{Role, RoleBinding};

/// Snapshot of cluster and BFT jury observations supplied to [`reconcile_workload_pure`].
#[derive(Debug, Clone, Default)]
pub struct ReconcileObservation {
    /// Currently observed child Kubernetes [`Job`], if it exists in the namespace.
    pub observed_job: Option<Job>,
    /// Sealed $2f + 1$ BFT [`ExecutionReceipt`] from the jury quorum, if jury verification is enabled.
    pub jury_receipt: Option<ExecutionReceipt>,
    /// Whether this workload requires a BFT jury quorum receipt before transitioning to `Succeeded`.
    pub require_jury_quorum: bool,
    /// Optional 7-gate [`AdmissionContext`] evaluated before child resource dispatch (`SPEC-0004`).
    pub admission_ctx: Option<AdmissionContext>,
    /// Current ISO-8601 controller timestamp used for new condition transitions.
    pub now_iso8601: String,
}

/// Deterministic side-effect command emitted by [`reconcile_workload_pure`].
#[derive(Debug, Clone, PartialEq)]
pub enum ReconcileEffect {
    /// Patch the `AgentWorkload` metadata to register `agent.unsigned.gg/workload-cleanup`.
    EnsureFinalizer,
    /// Server-Side Apply the workload's dedicated zero-trust [`ServiceAccount`].
    ApplyServiceAccount(Box<ServiceAccount>),
    /// Server-Side Apply the workload's least-privilege [`Role`].
    ApplyRole(Box<Role>),
    /// Server-Side Apply the workload's [`RoleBinding`].
    ApplyRoleBinding(Box<RoleBinding>),
    /// Server-Side Apply the workload's zero-trust [`NetworkPolicy`].
    ApplyNetworkPolicy(Box<NetworkPolicy>),
    /// Server-Side Apply the workload's sandboxed child [`Job`].
    ApplyChildJob(Box<Job>),
    /// Delete the child [`Job`] with foreground cascading propagation.
    DeleteChildJob(String),
    /// Emit a structured Kubernetes [`Event`] referencing the workload.
    EmitEvent(Box<Event>),
    /// Server-Side Apply the updated [`AgentWorkloadStatus`] subresource.
    PatchWorkloadStatus(AgentWorkloadStatus),
    /// Remove `agent.unsigned.gg/workload-cleanup` from the `AgentWorkload` metadata.
    RemoveFinalizer,
}

/// Output plan computed by [`reconcile_workload_pure`].
#[derive(Debug, Clone, PartialEq)]
pub struct ReconcilePlan {
    /// Computed target lifecycle phase for the workload.
    pub next_phase: WorkloadPhase,
    /// Ordered sequence of cluster effects to execute.
    pub effects: Vec<ReconcileEffect>,
    /// Optional requeue interval in seconds (`None` when terminal).
    pub requeue_after_secs: Option<u64>,
}

/// Pure, zero-I/O reconciliation state machine for an [`AgentWorkload`] (`SPEC-0002` & `SPEC-0004`).
pub fn reconcile_workload_pure(
    workload: &AgentWorkload,
    obs: &ReconcileObservation,
) -> Result<ReconcilePlan> {
    let run_id = workload
        .metadata
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| K8Error::Config("AgentWorkload metadata.name is required".to_string()))?;

    let namespace = workload.metadata.namespace.as_deref().unwrap_or("default");

    // 1. Deletion lifecycle branch (REQ-0002-04)
    if is_deleting(&workload.metadata) {
        let mut effects = Vec::new();
        if has_cleanup_finalizer(&workload.metadata) {
            if obs.observed_job.is_some() {
                effects.push(ReconcileEffect::DeleteChildJob(run_id.to_string()));
            }
            let mut status = workload.status.clone().unwrap_or_default();
            status.phase = WorkloadPhase::Terminated;
            status.completed_at = Some(obs.now_iso8601.clone());
            upsert_condition(
                &mut status.conditions,
                WorkloadCondition {
                    type_: CONDITION_READY.to_string(),
                    status: "False".to_string(),
                    reason: "WorkloadDeleting".to_string(),
                    message: Some("Cleaning up child Job and releasing finalizer".to_string()),
                    last_transition_time: obs.now_iso8601.clone(),
                },
            );
            effects.push(ReconcileEffect::PatchWorkloadStatus(status));
            effects.push(ReconcileEffect::RemoveFinalizer);
        }
        return Ok(ReconcilePlan {
            next_phase: WorkloadPhase::Terminated,
            effects,
            requeue_after_secs: None,
        });
    }

    // 2. Finalizer registration branch
    if !has_cleanup_finalizer(&workload.metadata) {
        return Ok(ReconcilePlan {
            next_phase: WorkloadPhase::Pending,
            effects: vec![ReconcileEffect::EnsureFinalizer],
            requeue_after_secs: Some(1),
        });
    }

    // 2b. Optional 7-gate admission check before dispatching child resources (SPEC-0004)
    if let Some(adm_ctx) = &obs.admission_ctx {
        let outcome = evaluate_workload_admission(workload, adm_ctx);
        if !outcome.allowed {
            let reason_summary = outcome
                .violations
                .iter()
                .map(|v| format!("[{:?}:{}] {}", v.gate, v.code, v.message))
                .collect::<Vec<_>>()
                .join("; ");
            let mut status = workload.status.clone().unwrap_or_default();
            status.phase = WorkloadPhase::Failed;
            status.completed_at = Some(obs.now_iso8601.clone());
            status.message = Some(reason_summary.clone());
            upsert_condition(
                &mut status.conditions,
                WorkloadCondition {
                    type_: CONDITION_ACCEPTED.to_string(),
                    status: "False".to_string(),
                    reason: "AdmissionDenied".to_string(),
                    message: Some(reason_summary.clone()),
                    last_transition_time: obs.now_iso8601.clone(),
                },
            );
            upsert_condition(
                &mut status.conditions,
                WorkloadCondition {
                    type_: CONDITION_READY.to_string(),
                    status: "False".to_string(),
                    reason: "AdmissionDenied".to_string(),
                    message: None,
                    last_transition_time: obs.now_iso8601.clone(),
                },
            );
            let mut effects = Vec::new();
            if let Ok(event) = build_workload_event(
                workload,
                &WorkloadEventSpec {
                    reason: "AdmissionDenied".to_string(),
                    message: reason_summary,
                    severity: EventSeverity::Warning,
                    reporting_controller: "k8-orchestrator".to_string(),
                    reporting_instance: "k8-orchestrator-0".to_string(),
                    action: "Admit".to_string(),
                },
            ) {
                effects.push(ReconcileEffect::EmitEvent(Box::new(event)));
            }
            effects.push(ReconcileEffect::PatchWorkloadStatus(status));
            return Ok(ReconcilePlan {
                next_phase: WorkloadPhase::Failed,
                effects,
                requeue_after_secs: None,
            });
        }
    }

    // 3. Validate spec & synthesize owner-referenced NetworkPolicy and Job
    let owner_ref = controller_owner_reference(workload).ok();
    let mut netpol = build_isolated_network_policy(
        run_id,
        namespace,
        workload.spec.agent_role.as_deref(),
        workload.spec.egress.as_ref(),
    )
    .map_err(k8_api::SpecValidationError::from)?;
    if let Some(owner) = &owner_ref {
        netpol.metadata.owner_references = Some(vec![owner.clone()]);
    }

    let job = Orchestrator::build_validated_job_with_owner(
        run_id,
        namespace,
        &workload.spec,
        owner_ref.clone(),
    )?;

    let mut status = workload.status.clone().unwrap_or_default();
    status.pod_name = Some(run_id.to_string());

    upsert_condition(
        &mut status.conditions,
        WorkloadCondition {
            type_: CONDITION_ACCEPTED.to_string(),
            status: "True".to_string(),
            reason: "SpecValidated".to_string(),
            message: None,
            last_transition_time: obs.now_iso8601.clone(),
        },
    );
    upsert_condition(
        &mut status.conditions,
        WorkloadCondition {
            type_: CONDITION_SANDBOXED.to_string(),
            status: "True".to_string(),
            reason: "PodSecurityRestrictedAndZeroTrustNetPol".to_string(),
            message: None,
            last_transition_time: obs.now_iso8601.clone(),
        },
    );

    // 4. Initial dispatch when child Job has not been observed yet
    let Some(observed_job) = &obs.observed_job else {
        status.phase = WorkloadPhase::Pending;
        if status.started_at.is_none() {
            status.started_at = Some(obs.now_iso8601.clone());
        }
        upsert_condition(
            &mut status.conditions,
            WorkloadCondition {
                type_: CONDITION_DISPATCHED.to_string(),
                status: "True".to_string(),
                reason: "ChildJobApplied".to_string(),
                message: None,
                last_transition_time: obs.now_iso8601.clone(),
            },
        );
        upsert_condition(
            &mut status.conditions,
            WorkloadCondition {
                type_: CONDITION_READY.to_string(),
                status: "False".to_string(),
                reason: "AwaitingPodStart".to_string(),
                message: None,
                last_transition_time: obs.now_iso8601.clone(),
            },
        );

        let mut effects = Vec::new();
        if !workload.spec.rbac_rules.is_empty() {
            let labels = canonical_workload_labels(run_id, workload.spec.agent_role.as_deref())
                .map_err(k8_api::SpecValidationError::from)?;
            let mut sa = build_dedicated_service_account(run_id, namespace, labels.clone(), true)
                .map_err(k8_api::SpecValidationError::from)?;
            let mut role =
                build_scoped_role(run_id, namespace, labels.clone(), &workload.spec.rbac_rules)
                    .map_err(k8_api::SpecValidationError::from)?;
            let mut rb = build_scoped_role_binding(run_id, namespace, labels)
                .map_err(k8_api::SpecValidationError::from)?;
            if let Some(owner) = &owner_ref {
                sa.metadata.owner_references = Some(vec![owner.clone()]);
                role.metadata.owner_references = Some(vec![owner.clone()]);
                rb.metadata.owner_references = Some(vec![owner.clone()]);
            }
            effects.push(ReconcileEffect::ApplyServiceAccount(Box::new(sa)));
            effects.push(ReconcileEffect::ApplyRole(Box::new(role)));
            effects.push(ReconcileEffect::ApplyRoleBinding(Box::new(rb)));
        }
        effects.push(ReconcileEffect::ApplyNetworkPolicy(Box::new(netpol)));
        effects.push(ReconcileEffect::ApplyChildJob(Box::new(job)));
        effects.push(ReconcileEffect::PatchWorkloadStatus(status));

        return Ok(ReconcilePlan {
            next_phase: WorkloadPhase::Pending,
            effects,
            requeue_after_secs: Some(5),
        });
    };

    // 5. Evaluate observed child Job phase + BFT Jury Quorum state
    let raw_phase = Orchestrator::evaluate_job_phase(observed_job);
    let (next_phase, requeue_after_secs) = match raw_phase {
        WorkloadPhase::Pending => {
            upsert_condition(
                &mut status.conditions,
                WorkloadCondition {
                    type_: CONDITION_READY.to_string(),
                    status: "False".to_string(),
                    reason: "PodPending".to_string(),
                    message: None,
                    last_transition_time: obs.now_iso8601.clone(),
                },
            );
            (WorkloadPhase::Pending, Some(5))
        }
        WorkloadPhase::Running => {
            upsert_condition(
                &mut status.conditions,
                WorkloadCondition {
                    type_: CONDITION_READY.to_string(),
                    status: "True".to_string(),
                    reason: "PodRunning".to_string(),
                    message: None,
                    last_transition_time: obs.now_iso8601.clone(),
                },
            );
            (WorkloadPhase::Running, Some(10))
        }
        WorkloadPhase::Failed | WorkloadPhase::Terminated => {
            status.exit_code = Some(1);
            status.completed_at = Some(obs.now_iso8601.clone());
            upsert_condition(
                &mut status.conditions,
                WorkloadCondition {
                    type_: CONDITION_READY.to_string(),
                    status: "False".to_string(),
                    reason: "JobFailed".to_string(),
                    message: Some("Child Job reported failed pods".to_string()),
                    last_transition_time: obs.now_iso8601.clone(),
                },
            );
            (raw_phase, None)
        }
        WorkloadPhase::Succeeded => {
            status.exit_code = Some(0);
            if obs.require_jury_quorum {
                match &obs.jury_receipt {
                    Some(receipt) if receipt.outcome == VerdictOutcome::Approve => {
                        status.completed_at = Some(obs.now_iso8601.clone());
                        status.receipt_digest = Some(receipt.receipt_commitment.clone());
                        upsert_condition(
                            &mut status.conditions,
                            WorkloadCondition {
                                type_: CONDITION_JURY_VERIFIED.to_string(),
                                status: "True".to_string(),
                                reason: "QuorumApproved".to_string(),
                                message: Some(format!(
                                    "Committed receipt {}",
                                    receipt.receipt_commitment
                                )),
                                last_transition_time: obs.now_iso8601.clone(),
                            },
                        );
                        upsert_condition(
                            &mut status.conditions,
                            WorkloadCondition {
                                type_: CONDITION_READY.to_string(),
                                status: "False".to_string(),
                                reason: "Completed".to_string(),
                                message: None,
                                last_transition_time: obs.now_iso8601.clone(),
                            },
                        );
                        (WorkloadPhase::Succeeded, None)
                    }
                    Some(receipt) => {
                        status.completed_at = Some(obs.now_iso8601.clone());
                        status.receipt_digest = Some(receipt.receipt_commitment.clone());
                        upsert_condition(
                            &mut status.conditions,
                            WorkloadCondition {
                                type_: CONDITION_JURY_VERIFIED.to_string(),
                                status: "False".to_string(),
                                reason: "ByzantineSplitDispute".to_string(),
                                message: Some(format!(
                                    "Jury quorum rejected or abstained ({:?})",
                                    receipt.outcome
                                )),
                                last_transition_time: obs.now_iso8601.clone(),
                            },
                        );
                        upsert_condition(
                            &mut status.conditions,
                            WorkloadCondition {
                                type_: CONDITION_READY.to_string(),
                                status: "False".to_string(),
                                reason: "JuryRejected".to_string(),
                                message: None,
                                last_transition_time: obs.now_iso8601.clone(),
                            },
                        );
                        (WorkloadPhase::Failed, None)
                    }
                    None => {
                        upsert_condition(
                            &mut status.conditions,
                            WorkloadCondition {
                                type_: CONDITION_JURY_VERIFIED.to_string(),
                                status: "Unknown".to_string(),
                                reason: "AwaitingQuorumVotes".to_string(),
                                message: Some("Waiting for 2f+1 jury receipt".to_string()),
                                last_transition_time: obs.now_iso8601.clone(),
                            },
                        );
                        (WorkloadPhase::Running, Some(5))
                    }
                }
            } else {
                status.completed_at = Some(obs.now_iso8601.clone());
                upsert_condition(
                    &mut status.conditions,
                    WorkloadCondition {
                        type_: CONDITION_READY.to_string(),
                        status: "False".to_string(),
                        reason: "Completed".to_string(),
                        message: None,
                        last_transition_time: obs.now_iso8601.clone(),
                    },
                );
                (WorkloadPhase::Succeeded, None)
            }
        }
    };

    status.phase = next_phase;
    let mut effects = Vec::new();
    if workload.status.as_ref() != Some(&status) {
        effects.push(ReconcileEffect::PatchWorkloadStatus(status));
    }

    Ok(ReconcilePlan {
        next_phase,
        effects,
        requeue_after_secs,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use k8_api::{
        ensure_cleanup_finalizer, find_condition, AgentWorkloadSpec, JuryQuorum, JuryVote,
    };
    use k8s_openapi::api::batch::v1::JobStatus;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};
    use k8s_openapi::jiff::Timestamp;
    use std::collections::BTreeSet;

    fn base_workload() -> AgentWorkload {
        let mut meta = ObjectMeta {
            name: Some("agent-w1".to_string()),
            namespace: Some("agent-ns".to_string()),
            uid: Some("uid-w1-999".to_string()),
            ..Default::default()
        };
        ensure_cleanup_finalizer(&mut meta);
        AgentWorkload {
            metadata: meta,
            spec: AgentWorkloadSpec {
                image: "ghcr.io/unsigned-gg/agent:latest".to_string(),
                ..Default::default()
            },
            status: None,
        }
    }

    #[test]
    fn test_reconcile_registers_finalizer_first() {
        let mut wl = base_workload();
        wl.metadata.finalizers = None;
        let obs = ReconcileObservation {
            now_iso8601: "2026-10-14T00:00:00Z".to_string(),
            ..Default::default()
        };
        let plan = reconcile_workload_pure(&wl, &obs).expect("reconcile");
        assert_eq!(plan.effects, vec![ReconcileEffect::EnsureFinalizer]);
        assert_eq!(plan.requeue_after_secs, Some(1));
    }

    #[test]
    fn test_reconcile_dispatches_netpol_and_job_with_owner_references() {
        let wl = base_workload();
        let obs = ReconcileObservation {
            now_iso8601: "2026-10-14T00:01:00Z".to_string(),
            ..Default::default()
        };
        let plan = reconcile_workload_pure(&wl, &obs).expect("reconcile");
        assert_eq!(plan.next_phase, WorkloadPhase::Pending);
        assert_eq!(plan.effects.len(), 3);
        assert!(matches!(
            plan.effects[0],
            ReconcileEffect::ApplyNetworkPolicy(_)
        ));
        assert!(matches!(plan.effects[1], ReconcileEffect::ApplyChildJob(_)));
    }

    #[test]
    fn test_reconcile_jury_quorum_commit_and_dispute_paths() {
        let wl = base_workload();
        let succeeded_job = Job {
            status: Some(JobStatus {
                succeeded: Some(1),
                ..Default::default()
            }),
            ..Default::default()
        };

        let roster: BTreeSet<String> = ["arb-0", "arb-1", "arb-2", "arb-3"]
            .into_iter()
            .map(String::from)
            .collect();
        let mut quorum =
            JuryQuorum::new("agent-w1", 1, 1, roster.clone()).expect("4-node BFT quorum");
        for arb in ["arb-0", "arb-1", "arb-2"] {
            let _ = quorum
                .record_vote(JuryVote {
                    workload_id: "agent-w1".to_string(),
                    round: 1,
                    arbiter_id: arb.to_string(),
                    outcome: VerdictOutcome::Approve,
                    artifact_digest: "blake3:deadbeef".to_string(),
                    timestamp_ms: 1_700_000_000_000,
                })
                .expect("record vote");
        }
        let receipt = quorum.finalize_receipt(1_700_000_000_100).expect("receipt");

        let obs_commit = ReconcileObservation {
            observed_job: Some(succeeded_job.clone()),
            jury_receipt: Some(receipt),
            require_jury_quorum: true,
            admission_ctx: None,
            now_iso8601: "2026-10-14T00:05:00Z".to_string(),
        };
        let plan_commit = reconcile_workload_pure(&wl, &obs_commit).expect("reconcile commit");
        assert_eq!(plan_commit.next_phase, WorkloadPhase::Succeeded);
        assert_eq!(plan_commit.requeue_after_secs, None);
        assert!(matches!(
            &plan_commit.effects[0],
            ReconcileEffect::PatchWorkloadStatus(_)
        ));
        if let ReconcileEffect::PatchWorkloadStatus(st) = &plan_commit.effects[0] {
            assert!(st.receipt_digest.is_some());
            let jv = find_condition(&st.conditions, CONDITION_JURY_VERIFIED).expect("jv");
            assert_eq!(jv.status, "True");
        }

        // Rejection / dispute path (REQ-0002-06)
        let mut reject_quorum =
            JuryQuorum::new("agent-w1", 1, 1, roster).expect("4-node BFT quorum");
        for arb in ["arb-0", "arb-1", "arb-2"] {
            let _ = reject_quorum
                .record_vote(JuryVote {
                    workload_id: "agent-w1".to_string(),
                    round: 1,
                    arbiter_id: arb.to_string(),
                    outcome: VerdictOutcome::Reject,
                    artifact_digest: "blake3:corrupt".to_string(),
                    timestamp_ms: 1_700_000_000_000,
                })
                .expect("record vote");
        }
        let reject_receipt = reject_quorum
            .finalize_receipt(1_700_000_000_200)
            .expect("reject receipt");

        let obs_reject = ReconcileObservation {
            observed_job: Some(succeeded_job),
            jury_receipt: Some(reject_receipt),
            require_jury_quorum: true,
            admission_ctx: None,
            now_iso8601: "2026-10-14T00:06:00Z".to_string(),
        };
        let plan_reject = reconcile_workload_pure(&wl, &obs_reject).expect("reconcile reject");
        assert_eq!(plan_reject.next_phase, WorkloadPhase::Failed);
    }

    #[test]
    fn test_reconcile_deletion_cleans_up_job_and_removes_finalizer() {
        let mut wl = base_workload();
        wl.metadata.deletion_timestamp = Some(Time(Timestamp::UNIX_EPOCH));
        let obs = ReconcileObservation {
            observed_job: Some(Job::default()),
            now_iso8601: "2026-10-14T00:10:00Z".to_string(),
            ..Default::default()
        };
        let plan = reconcile_workload_pure(&wl, &obs).expect("reconcile delete");
        assert_eq!(plan.next_phase, WorkloadPhase::Terminated);
        assert_eq!(
            plan.effects[0],
            ReconcileEffect::DeleteChildJob("agent-w1".to_string())
        );
        assert_eq!(plan.effects[2], ReconcileEffect::RemoveFinalizer);
    }

    #[test]
    fn test_reconcile_admission_denied_transitions_to_failed_and_emits_warning_event() {
        let mut wl = base_workload();
        wl.spec.cpu = Some("16000m".to_string());
        let obs = ReconcileObservation {
            admission_ctx: Some(AdmissionContext {
                quota: Some((
                    k8_api::NamespaceQuotaSpec {
                        max_cpu_millis: 4_000,
                        max_memory_bytes: 8 * 1024 * 1024 * 1024,
                        max_pods: 4,
                        warn_threshold_permille: 800,
                    },
                    k8_api::QuotaUsageSnapshot::default(),
                )),
                required_receipt: None,
            }),
            now_iso8601: "2026-10-14T00:12:00Z".to_string(),
            ..Default::default()
        };

        let plan = reconcile_workload_pure(&wl, &obs).expect("reconcile admission denied");
        assert_eq!(plan.next_phase, WorkloadPhase::Failed);
        assert_eq!(plan.requeue_after_secs, None);
        assert_eq!(plan.effects.len(), 2);
        assert!(matches!(plan.effects[0], ReconcileEffect::EmitEvent(_)));
        assert!(matches!(
            plan.effects[1],
            ReconcileEffect::PatchWorkloadStatus(_)
        ));
        if let ReconcileEffect::PatchWorkloadStatus(st) = &plan.effects[1] {
            let acc = find_condition(&st.conditions, CONDITION_ACCEPTED).expect("accepted");
            assert_eq!(acc.status, "False");
            assert_eq!(acc.reason, "AdmissionDenied");
        }
    }

    #[test]
    fn test_reconcile_synthesizes_owner_referenced_rbac_when_rules_present() {
        let mut wl = base_workload();
        wl.spec.rbac_rules = vec![k8_api::ScopedRuleSpec {
            api_group: String::new(),
            resource: "configmaps".to_string(),
            resource_names: vec!["agent-cfg".to_string()],
            verbs: vec!["get".to_string()],
        }];
        let obs = ReconcileObservation {
            now_iso8601: "2026-10-14T00:15:00Z".to_string(),
            ..Default::default()
        };
        let plan = reconcile_workload_pure(&wl, &obs).expect("reconcile rbac");
        assert_eq!(plan.next_phase, WorkloadPhase::Pending);
        assert_eq!(plan.effects.len(), 6);
        assert!(matches!(
            plan.effects[0],
            ReconcileEffect::ApplyServiceAccount(_)
        ));
        assert!(matches!(plan.effects[1], ReconcileEffect::ApplyRole(_)));
        assert!(matches!(
            plan.effects[2],
            ReconcileEffect::ApplyRoleBinding(_)
        ));
    }
}
