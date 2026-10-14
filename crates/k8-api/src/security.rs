// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Kubernetes PodSecurity `restricted` profile builders and deterministic pod spec auditor.

use k8s_openapi::api::core::v1::{
    Capabilities, PodSecurityContext, PodSpec, SeccompProfile, SecurityContext,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default unprivileged non-root UID/GID (`nonroot` in distroless images).
pub const DEFAULT_NONROOT_UID: i64 = 65_532;

/// Violations detected when auditing a [`PodSpec`] against the Kubernetes `restricted` profile.
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SecurityViolation {
    /// Host namespace sharing (`hostNetwork`, `hostPID`, or `hostIPC`) is enabled.
    #[error("host namespace sharing '{0}' is forbidden under PodSecurity restricted")]
    HostNamespaceEnabled(String),

    /// ServiceAccount token auto-mounting is not explicitly disabled (`automountServiceAccountToken: false`).
    #[error("automountServiceAccountToken must be explicitly set to false for sandboxed agents")]
    ServiceAccountTokenMounted,

    /// Pod-level `runAsNonRoot: true` is missing.
    #[error("pod securityContext.runAsNonRoot must be true")]
    PodRunAsNonRootMissing,

    /// Container lacks a `securityContext`.
    #[error("container '{0}' is missing securityContext")]
    ContainerSecurityContextMissing(String),

    /// Container allows privilege escalation or omits `allowPrivilegeEscalation: false`.
    #[error("container '{0}' must set allowPrivilegeEscalation: false")]
    PrivilegeEscalationAllowed(String),

    /// Container runs in privileged mode.
    #[error("container '{0}' cannot set privileged: true")]
    PrivilegedContainer(String),

    /// Container root filesystem is writable (`readOnlyRootFilesystem` is not `true`).
    #[error("container '{0}' must set readOnlyRootFilesystem: true")]
    WritableRootFilesystem(String),

    /// Container omits `runAsNonRoot: true` or specifies root UID `0`.
    #[error("container '{0}' must run as a non-root user (UID != 0)")]
    ContainerRunsAsRoot(String),

    /// Container does not drop `"ALL"` Linux capabilities.
    #[error("container '{0}' must drop ALL Linux capabilities")]
    CapabilitiesNotDropped(String),

    /// Seccomp profile is neither `RuntimeDefault` nor `Localhost`.
    #[error("container '{0}' must enforce RuntimeDefault or Localhost seccompProfile")]
    SeccompProfileMissing(String),
}

/// Construct a hardened [`PodSecurityContext`] compliant with Kubernetes PodSecurity `restricted`.
#[must_use]
pub fn restricted_pod_security_context() -> PodSecurityContext {
    PodSecurityContext {
        run_as_non_root: Some(true),
        run_as_user: Some(DEFAULT_NONROOT_UID),
        run_as_group: Some(DEFAULT_NONROOT_UID),
        fs_group: Some(DEFAULT_NONROOT_UID),
        seccomp_profile: Some(SeccompProfile {
            localhost_profile: None,
            type_: "RuntimeDefault".to_string(),
        }),
        ..Default::default()
    }
}

/// Construct a hardened container [`SecurityContext`] compliant with Kubernetes PodSecurity `restricted`.
#[must_use]
pub fn restricted_container_security_context() -> SecurityContext {
    SecurityContext {
        allow_privilege_escalation: Some(false),
        privileged: Some(false),
        read_only_root_filesystem: Some(true),
        run_as_non_root: Some(true),
        run_as_user: Some(DEFAULT_NONROOT_UID),
        run_as_group: Some(DEFAULT_NONROOT_UID),
        capabilities: Some(Capabilities {
            add: None,
            drop: Some(vec!["ALL".to_string()]),
        }),
        seccomp_profile: Some(SeccompProfile {
            localhost_profile: None,
            type_: "RuntimeDefault".to_string(),
        }),
        ..Default::default()
    }
}

/// Audit a [`PodSpec`] against the Kubernetes PodSecurity `restricted` baseline and agent sandbox rules.
pub fn audit_pod_spec_restricted(pod_spec: &PodSpec) -> Result<(), Vec<SecurityViolation>> {
    let mut violations = Vec::new();

    if pod_spec.host_network == Some(true) {
        violations.push(SecurityViolation::HostNamespaceEnabled(
            "hostNetwork".to_string(),
        ));
    }
    if pod_spec.host_pid == Some(true) {
        violations.push(SecurityViolation::HostNamespaceEnabled(
            "hostPID".to_string(),
        ));
    }
    if pod_spec.host_ipc == Some(true) {
        violations.push(SecurityViolation::HostNamespaceEnabled(
            "hostIPC".to_string(),
        ));
    }
    if pod_spec.automount_service_account_token != Some(false) {
        violations.push(SecurityViolation::ServiceAccountTokenMounted);
    }

    let pod_seccomp_valid = pod_spec
        .security_context
        .as_ref()
        .and_then(|sc| sc.seccomp_profile.as_ref())
        .is_some_and(|sp| sp.type_ == "RuntimeDefault" || sp.type_ == "Localhost");

    let pod_non_root = pod_spec
        .security_context
        .as_ref()
        .and_then(|sc| sc.run_as_non_root)
        == Some(true);
    if !pod_non_root {
        violations.push(SecurityViolation::PodRunAsNonRootMissing);
    }

    let all_containers = pod_spec
        .containers
        .iter()
        .chain(pod_spec.init_containers.iter().flatten());

    for container in all_containers {
        let name = &container.name;
        let Some(sc) = &container.security_context else {
            violations.push(SecurityViolation::ContainerSecurityContextMissing(
                name.clone(),
            ));
            continue;
        };

        if sc.allow_privilege_escalation != Some(false) {
            violations.push(SecurityViolation::PrivilegeEscalationAllowed(name.clone()));
        }
        if sc.privileged == Some(true) {
            violations.push(SecurityViolation::PrivilegedContainer(name.clone()));
        }
        if sc.read_only_root_filesystem != Some(true) {
            violations.push(SecurityViolation::WritableRootFilesystem(name.clone()));
        }
        if sc.run_as_non_root != Some(true) || sc.run_as_user == Some(0) {
            violations.push(SecurityViolation::ContainerRunsAsRoot(name.clone()));
        }

        let drops_all = sc
            .capabilities
            .as_ref()
            .and_then(|c| c.drop.as_ref())
            .is_some_and(|drops| drops.iter().any(|d| d.eq_ignore_ascii_case("ALL")));
        if !drops_all {
            violations.push(SecurityViolation::CapabilitiesNotDropped(name.clone()));
        }

        let container_seccomp_valid = sc
            .seccomp_profile
            .as_ref()
            .is_some_and(|sp| sp.type_ == "RuntimeDefault" || sp.type_ == "Localhost");
        if !pod_seccomp_valid && !container_seccomp_valid {
            violations.push(SecurityViolation::SeccompProfileMissing(name.clone()));
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::Container;

    #[test]
    fn test_restricted_builders_pass_audit() {
        let pod_spec = PodSpec {
            automount_service_account_token: Some(false),
            security_context: Some(restricted_pod_security_context()),
            containers: vec![Container {
                name: "agent".to_string(),
                security_context: Some(restricted_container_security_context()),
                ..Default::default()
            }],
            ..Default::default()
        };

        assert!(audit_pod_spec_restricted(&pod_spec).is_ok());
    }

    #[test]
    fn test_unhardened_pod_spec_rejected() {
        let pod_spec = PodSpec {
            host_network: Some(true),
            containers: vec![Container {
                name: "unsafe-agent".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };

        let errs = audit_pod_spec_restricted(&pod_spec).expect_err("must reject unsafe pod");
        assert!(errs.contains(&SecurityViolation::HostNamespaceEnabled(
            "hostNetwork".to_string()
        )));
        assert!(errs.contains(&SecurityViolation::ServiceAccountTokenMounted));
        assert!(errs.contains(&SecurityViolation::PodRunAsNonRootMissing));
        assert!(
            errs.contains(&SecurityViolation::ContainerSecurityContextMissing(
                "unsafe-agent".to_string()
            ))
        );
    }
}
