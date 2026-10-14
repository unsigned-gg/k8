// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `probes`: Pure zero-I/O Kubernetes Probe Timing, Non-Shell Handler Auditing, and
//! `RollingUpdate` vs. `PodDisruptionBudget` Quorum Conservation (`SPEC-0006`).
//!
//! Enforces:
//! - Probe timing soundness (`1 <= timeoutSeconds <= periodSeconds`, `failureThreshold >= 1`,
//!   `successThreshold == 1` for liveness/startup probes) (`INV-0006-03`).
//! - Zero shell-spawned `exec` probes (`sh`, `bash`, `/bin/sh`, `/bin/bash`, `dash`, `zsh`) (`INV-0006-03`).
//! - Startup window dominance (`startup.failureThreshold * startup.periodSeconds >= liveness.failureThreshold * liveness.periodSeconds`) (`INV-0006-03`).
//! - `RollingUpdate` (`maxUnavailable`, `maxSurge`) vs. `PodDisruptionBudget` (`minAvailable`) quorum conservation (`INV-0006-04`).

use k8s_openapi::api::core::v1::{Container, HTTPGetAction, PodSpec, Probe};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Shell binaries forbidden as `exec` probe entrypoints (`INV-0006-03`).
pub const FORBIDDEN_PROBE_SHELLS: &[&str] = &[
    "sh",
    "bash",
    "/bin/sh",
    "/bin/bash",
    "dash",
    "/bin/dash",
    "zsh",
    "/bin/zsh",
    "ash",
    "/bin/ash",
];

/// Errors returned during probe synthesis, pod probe auditing, or rollout quorum evaluation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProbeError {
    /// HTTP probe path does not start with `/`.
    #[error("HTTP probe path `{0}` must start with `/`")]
    InvalidHttpPath(String),

    /// HTTP probe port is `0`.
    #[error("HTTP probe port must be in 1..=65535 (got 0)")]
    ZeroProbePort,

    /// Probe has no handler action (`httpGet`, `tcpSocket`, `grpc`, or `exec`) configured.
    #[error("container `{container}` `{probe_kind}` probe has no handler action configured")]
    MissingProbeHandler {
        /// Container name.
        container: String,
        /// Probe kind (`startupProbe`, `readinessProbe`, or `livenessProbe`).
        probe_kind: &'static str,
    },

    /// `exec` probe invokes a forbidden shell binary (`INV-0006-03`).
    #[error("container `{container}` `{probe_kind}` exec probe invokes forbidden shell `{binary}`; use httpGet, grpc, or a direct binary entrypoint")]
    ForbiddenShellExecProbe {
        /// Container name.
        container: String,
        /// Probe kind.
        probe_kind: &'static str,
        /// Shell binary found.
        binary: String,
    },

    /// Probe timing parameter (`periodSeconds`, `timeoutSeconds`, `failureThreshold`, or `initialDelaySeconds`) is invalid.
    #[error("container `{container}` `{probe_kind}` has invalid timing parameter: {detail}")]
    InvalidProbeTiming {
        /// Container name.
        container: String,
        /// Probe kind.
        probe_kind: &'static str,
        /// Explanation of the timing violation.
        detail: String,
    },

    /// `livenessProbe` or `startupProbe` specifies `successThreshold != 1`.
    #[error(
        "container `{container}` `{probe_kind}` must have `successThreshold == 1` (got {actual})"
    )]
    InvalidNonReadinessSuccessThreshold {
        /// Container name.
        container: String,
        /// Probe kind (`startupProbe` or `livenessProbe`).
        probe_kind: &'static str,
        /// Configured `successThreshold`.
        actual: i32,
    },

    /// `startupProbe` window is shorter than `livenessProbe` window (`INV-0006-03`).
    #[error("container `{container}` startupProbe window ({startup_window_secs}s) is shorter than livenessProbe window ({liveness_window_secs}s)")]
    StartupWindowShorterThanLiveness {
        /// Container name.
        container: String,
        /// Total startup probe budget (`failureThreshold * periodSeconds`).
        startup_window_secs: i64,
        /// Total liveness probe budget (`failureThreshold * periodSeconds`).
        liveness_window_secs: i64,
    },

    /// `RolloutQuorumSpec` has `replicas == 0`.
    #[error("rollout quorum requires `replicas >= 1` (got 0)")]
    ZeroRolloutReplicas,

    /// `RolloutQuorumSpec` sets both `max_unavailable == 0` and `max_surge == 0`, stalling rollouts.
    #[error(
        "rolling update with `max_unavailable == 0` and `max_surge == 0` cannot make progress"
    )]
    StalledRollingUpdateParameters,

    /// `RolloutQuorumSpec` `max_unavailable` exceeds `replicas`.
    #[error(
        "rolling update `max_unavailable` ({max_unavailable}) exceeds `replicas` ({replicas})"
    )]
    MaxUnavailableExceedsReplicas {
        /// Desired replicas.
        replicas: u32,
        /// Configured `maxUnavailable`.
        max_unavailable: u32,
    },

    /// `RollingUpdate` drops available replicas below `PodDisruptionBudget` `minAvailable` (`INV-0006-04`).
    #[error("rolling update min_ready ({min_ready}) drops below PodDisruptionBudget minAvailable ({pdb_min_available}) for replicas={replicas}, max_unavailable={max_unavailable}")]
    RolloutBreachesPdbQuorum {
        /// Desired replicas.
        replicas: u32,
        /// Configured `maxUnavailable`.
        max_unavailable: u32,
        /// Resulting `replicas - max_unavailable`.
        min_ready: u32,
        /// Required `PodDisruptionBudget` `minAvailable`.
        pdb_min_available: u32,
    },
}

/// Specification for synthesizing a validated HTTP `GET` [`Probe`] (`SPEC-0006`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HttpProbeSpec {
    /// HTTP path starting with `/` (e.g. `"/healthz"` or `"/readyz"`).
    pub path: String,
    /// Target container port (`1..=65535`).
    pub port: u16,
    /// Initial delay before first probe in seconds (`>= 0`).
    pub initial_delay_seconds: i32,
    /// Probe interval in seconds (`>= 1`).
    pub period_seconds: i32,
    /// Probe timeout in seconds (`1..=period_seconds`).
    pub timeout_seconds: i32,
    /// Consecutive failures before marking unhealthy (`>= 1`).
    pub failure_threshold: i32,
    /// Consecutive successes before marking healthy (`1` for startup/liveness).
    pub success_threshold: i32,
}

impl Default for HttpProbeSpec {
    fn default() -> Self {
        Self {
            path: "/healthz".to_owned(),
            port: 8080,
            initial_delay_seconds: 0,
            period_seconds: 10,
            timeout_seconds: 2,
            failure_threshold: 3,
            success_threshold: 1,
        }
    }
}

/// Synthesizes a validated Kubernetes `core/v1` [`Probe`] with an `httpGet` handler (`SPEC-0006`).
///
/// # Errors
/// Returns [`ProbeError`] if the HTTP path, port, or timing parameters violate `INV-0006-03`.
pub fn build_http_get_probe(spec: &HttpProbeSpec) -> Result<Probe, ProbeError> {
    if !spec.path.starts_with('/') {
        return Err(ProbeError::InvalidHttpPath(spec.path.clone()));
    }
    if spec.port == 0 {
        return Err(ProbeError::ZeroProbePort);
    }
    let probe = Probe {
        http_get: Some(HTTPGetAction {
            path: Some(spec.path.clone()),
            port: IntOrString::Int(i32::from(spec.port)),
            scheme: Some("HTTP".to_owned()),
            ..Default::default()
        }),
        initial_delay_seconds: Some(spec.initial_delay_seconds),
        period_seconds: Some(spec.period_seconds),
        timeout_seconds: Some(spec.timeout_seconds),
        failure_threshold: Some(spec.failure_threshold),
        success_threshold: Some(spec.success_threshold),
        ..Default::default()
    };
    audit_single_probe("builder", "httpGet", &probe, false)?;
    Ok(probe)
}

fn audit_single_probe(
    container_name: &str,
    probe_kind: &'static str,
    probe: &Probe,
    require_unit_success_threshold: bool,
) -> Result<i64, ProbeError> {
    let has_handler = probe.http_get.is_some()
        || probe.tcp_socket.is_some()
        || probe.grpc.is_some()
        || probe.exec.is_some();
    if !has_handler {
        return Err(ProbeError::MissingProbeHandler {
            container: container_name.to_owned(),
            probe_kind,
        });
    }

    if let Some(http) = &probe.http_get {
        if let Some(path) = &http.path {
            if !path.starts_with('/') {
                return Err(ProbeError::InvalidHttpPath(path.clone()));
            }
        }
    }

    if let Some(exec) = &probe.exec {
        let cmd = exec.command.as_deref().unwrap_or(&[]);
        if cmd.is_empty() {
            return Err(ProbeError::MissingProbeHandler {
                container: container_name.to_owned(),
                probe_kind,
            });
        }
        let first = cmd[0].trim();
        if FORBIDDEN_PROBE_SHELLS.contains(&first) {
            return Err(ProbeError::ForbiddenShellExecProbe {
                container: container_name.to_owned(),
                probe_kind,
                binary: first.to_owned(),
            });
        }
    }

    let initial_delay = probe.initial_delay_seconds.unwrap_or(0);
    if initial_delay < 0 {
        return Err(ProbeError::InvalidProbeTiming {
            container: container_name.to_owned(),
            probe_kind,
            detail: format!("initialDelaySeconds ({initial_delay}) must be >= 0"),
        });
    }

    let period = probe.period_seconds.unwrap_or(10);
    if period <= 0 {
        return Err(ProbeError::InvalidProbeTiming {
            container: container_name.to_owned(),
            probe_kind,
            detail: format!("periodSeconds ({period}) must be >= 1"),
        });
    }

    let timeout = probe.timeout_seconds.unwrap_or(1);
    if timeout <= 0 || timeout > period {
        return Err(ProbeError::InvalidProbeTiming {
            container: container_name.to_owned(),
            probe_kind,
            detail: format!("timeoutSeconds ({timeout}) must be in 1..=periodSeconds ({period})"),
        });
    }

    let failure_threshold = probe.failure_threshold.unwrap_or(3);
    if failure_threshold <= 0 {
        return Err(ProbeError::InvalidProbeTiming {
            container: container_name.to_owned(),
            probe_kind,
            detail: format!("failureThreshold ({failure_threshold}) must be >= 1"),
        });
    }

    let success_threshold = probe.success_threshold.unwrap_or(1);
    if success_threshold <= 0 {
        return Err(ProbeError::InvalidProbeTiming {
            container: container_name.to_owned(),
            probe_kind,
            detail: format!("successThreshold ({success_threshold}) must be >= 1"),
        });
    }
    if require_unit_success_threshold && success_threshold != 1 {
        return Err(ProbeError::InvalidNonReadinessSuccessThreshold {
            container: container_name.to_owned(),
            probe_kind,
            actual: success_threshold,
        });
    }

    Ok(i64::from(failure_threshold).saturating_mul(i64::from(period)))
}

fn audit_container_probes(container: &Container) -> Result<(), ProbeError> {
    let startup_window = if let Some(sp) = &container.startup_probe {
        Some(audit_single_probe(
            &container.name,
            "startupProbe",
            sp,
            true,
        )?)
    } else {
        None
    };

    if let Some(rp) = &container.readiness_probe {
        audit_single_probe(&container.name, "readinessProbe", rp, false)?;
    }

    let liveness_window = if let Some(lp) = &container.liveness_probe {
        Some(audit_single_probe(
            &container.name,
            "livenessProbe",
            lp,
            true,
        )?)
    } else {
        None
    };

    if let (Some(sw), Some(lw)) = (startup_window, liveness_window) {
        if sw < lw {
            return Err(ProbeError::StartupWindowShorterThanLiveness {
                container: container.name.clone(),
                startup_window_secs: sw,
                liveness_window_secs: lw,
            });
        }
    }

    Ok(())
}

/// Audits all containers in a [`PodSpec`] for probe timing and handler invariants (`INV-0006-03`).
///
/// # Errors
/// Returns [`ProbeError`] on the first invalid probe configuration found.
pub fn audit_pod_probes(pod_spec: &PodSpec) -> Result<(), ProbeError> {
    for container in &pod_spec.containers {
        audit_container_probes(container)?;
    }
    Ok(())
}

/// Input specification for evaluating `RollingUpdate` vs. `PodDisruptionBudget` quorum conservation (`SPEC-0006`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RolloutQuorumSpec {
    /// Workload identifier (`<namespace>/<name>`).
    pub workload_id: String,
    /// Target steady-state replica count (`>= 1`).
    pub replicas: u32,
    /// Maximum unavailable pods permitted during `RollingUpdate`.
    pub max_unavailable: u32,
    /// Maximum surge pods permitted above `replicas` during `RollingUpdate`.
    pub max_surge: u32,
    /// Minimum available pods required by the governing `PodDisruptionBudget` (`policy/v1`).
    pub pdb_min_available: u32,
}

/// Deterministic rollout vs. PDB quorum evaluation report (`SPEC-0006`, `INV-0006-04`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RolloutQuorumReport {
    /// Workload identifier (`<namespace>/<name>`).
    pub workload_id: String,
    /// Steady-state replica count.
    pub replicas: u32,
    /// Minimum ready replicas guaranteed during a `RollingUpdate` (`replicas - max_unavailable`).
    pub min_ready_during_rollout: u32,
    /// Peak pod count during a `RollingUpdate` (`replicas + max_surge`).
    pub max_total_pods_during_rollout: u32,
    /// Governing `PodDisruptionBudget` `minAvailable`.
    pub pdb_min_available: u32,
    /// Remaining voluntary disruption budget slack during a rollout (`min_ready_during_rollout - pdb_min_available`).
    pub concurrent_drain_slack: u32,
    /// Deterministic 64-bit FNV-1a hex digest of the quorum report.
    pub report_digest: String,
}

/// Verifies that a `RollingUpdate` strategy (`max_unavailable`, `max_surge`) preserves the
/// governing `PodDisruptionBudget` (`pdb_min_available`) and computes concurrent node-drain slack (`INV-0006-04`).
///
/// # Errors
/// Returns [`ProbeError`] if `replicas == 0`, both `max_unavailable == 0 && max_surge == 0`,
/// or `replicas - max_unavailable < pdb_min_available`.
pub fn evaluate_rollout_quorum(
    spec: &RolloutQuorumSpec,
) -> Result<RolloutQuorumReport, ProbeError> {
    if spec.replicas == 0 {
        return Err(ProbeError::ZeroRolloutReplicas);
    }
    if spec.max_unavailable == 0 && spec.max_surge == 0 {
        return Err(ProbeError::StalledRollingUpdateParameters);
    }
    if spec.max_unavailable > spec.replicas {
        return Err(ProbeError::MaxUnavailableExceedsReplicas {
            replicas: spec.replicas,
            max_unavailable: spec.max_unavailable,
        });
    }

    let min_ready = spec.replicas - spec.max_unavailable;
    if min_ready < spec.pdb_min_available {
        return Err(ProbeError::RolloutBreachesPdbQuorum {
            replicas: spec.replicas,
            max_unavailable: spec.max_unavailable,
            min_ready,
            pdb_min_available: spec.pdb_min_available,
        });
    }

    let max_total = spec.replicas.saturating_add(spec.max_surge);
    let slack = min_ready - spec.pdb_min_available;

    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let payload = format!(
        "{}:{}:{}:{}:{}:{}",
        spec.workload_id, spec.replicas, min_ready, max_total, spec.pdb_min_available, slack
    );
    for b in payload.as_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }

    Ok(RolloutQuorumReport {
        workload_id: spec.workload_id.clone(),
        replicas: spec.replicas,
        min_ready_during_rollout: min_ready,
        max_total_pods_during_rollout: max_total,
        pdb_min_available: spec.pdb_min_available,
        concurrent_drain_slack: slack,
        report_digest: format!("{hash:016x}"),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::ExecAction;

    #[test]
    fn http_probe_builder_and_auditor_reject_shell_exec_and_inverted_windows() {
        let startup = build_http_get_probe(&HttpProbeSpec {
            path: "/healthz".to_owned(),
            port: 8080,
            initial_delay_seconds: 0,
            period_seconds: 5,
            timeout_seconds: 2,
            failure_threshold: 12, // 60s window
            success_threshold: 1,
        })
        .unwrap();
        let liveness = build_http_get_probe(&HttpProbeSpec {
            path: "/healthz".to_owned(),
            port: 8080,
            initial_delay_seconds: 0,
            period_seconds: 10,
            timeout_seconds: 2,
            failure_threshold: 3, // 30s window
            success_threshold: 1,
        })
        .unwrap();

        let good_pod = PodSpec {
            containers: vec![Container {
                name: "agent".to_owned(),
                startup_probe: Some(startup.clone()),
                liveness_probe: Some(liveness.clone()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(audit_pod_probes(&good_pod).is_ok());

        // Inverted window: startup (30s) < liveness (60s)
        let inverted_pod = PodSpec {
            containers: vec![Container {
                name: "agent".to_owned(),
                startup_probe: Some(liveness),
                liveness_probe: Some(startup),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(matches!(
            audit_pod_probes(&inverted_pod),
            Err(ProbeError::StartupWindowShorterThanLiveness { .. })
        ));

        // Shell exec probe rejected
        let shell_pod = PodSpec {
            containers: vec![Container {
                name: "agent".to_owned(),
                readiness_probe: Some(Probe {
                    exec: Some(ExecAction {
                        command: Some(vec![
                            "/bin/sh".to_owned(),
                            "-c".to_owned(),
                            "curl localhost".to_owned(),
                        ]),
                    }),
                    period_seconds: Some(10),
                    timeout_seconds: Some(2),
                    failure_threshold: Some(3),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(matches!(
            audit_pod_probes(&shell_pod),
            Err(ProbeError::ForbiddenShellExecProbe { .. })
        ));
    }

    #[test]
    fn rollout_quorum_enforces_pdb_floor_and_computes_drain_slack() {
        let ok_spec = RolloutQuorumSpec {
            workload_id: "agents/coordinator".to_owned(),
            replicas: 5,
            max_unavailable: 1,
            max_surge: 1,
            pdb_min_available: 3,
        };
        let report = evaluate_rollout_quorum(&ok_spec).unwrap();
        assert_eq!(report.min_ready_during_rollout, 4);
        assert_eq!(report.concurrent_drain_slack, 1);

        let breach_spec = RolloutQuorumSpec {
            workload_id: "agents/coordinator".to_owned(),
            replicas: 3,
            max_unavailable: 2,
            max_surge: 1,
            pdb_min_available: 2,
        };
        assert!(matches!(
            evaluate_rollout_quorum(&breach_spec),
            Err(ProbeError::RolloutBreachesPdbQuorum { .. })
        ));
    }
}
