// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Zero-trust Kubernetes `NetworkPolicy` synthesis and fail-closed CIDR egress auditing (`SPEC-0002`).

use crate::selector::{canonical_workload_labels, LabelError};
use k8s_openapi::api::networking::v1::{
    IPBlock, NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicyPeer, NetworkPolicyPort,
    NetworkPolicySpec,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{
    LabelSelector as K8sLabelSelector, ObjectMeta,
};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Declarative zero-trust egress specification for an isolated agent Pod.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EgressRuleSpec {
    /// Permit UDP and TCP port 53 for cluster DNS resolution.
    pub allow_dns: bool,
    /// Explicit non-wildcard IPv4/IPv6 CIDR blocks allowed for outbound traffic.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_cidrs: Vec<String>,
    /// Explicit TCP destination ports allowed for the configured `allowed_cidrs`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_tcp_ports: Vec<u16>,
}

impl Default for EgressRuleSpec {
    fn default() -> Self {
        Self {
            allow_dns: true,
            allowed_cidrs: Vec::new(),
            allowed_tcp_ports: Vec::new(),
        }
    }
}

/// Validation errors returned when constructing or auditing a zero-trust [`NetworkPolicy`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NetworkPolicyError {
    /// Workload run ID or role failed RFC 1123 DNS label validation.
    #[error("invalid label in NetworkPolicy: {0}")]
    InvalidLabel(#[from] LabelError),

    /// Wildcard CIDR (`0.0.0.0/0` or `::/0`) is forbidden in zero-trust agent egress rules.
    #[error("wildcard CIDR '{0}' is forbidden in zero-trust NetworkPolicy egress")]
    UnrestrictedCidrForbidden(String),

    /// CIDR string is malformed or has an out-of-range prefix length.
    #[error("invalid CIDR block '{0}'")]
    InvalidCidrFormat(String),

    /// TCP port `0` is invalid in Kubernetes `NetworkPolicyPort`.
    #[error("invalid TCP port 0 in NetworkPolicy egress")]
    InvalidPortZero,
}

fn is_valid_ipv4_literal(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.into_iter().all(|p| p.parse::<u8>().is_ok())
}

fn is_valid_ipv6_literal(s: &str) -> bool {
    if !s.contains(':') {
        return false;
    }
    let double_colons = s.matches("::").count();
    if double_colons > 1 {
        return false;
    }
    for seg in s.split(':').filter(|seg| !seg.is_empty()) {
        if seg.len() > 4 || u16::from_str_radix(seg, 16).is_err() {
            return false;
        }
    }
    let total_groups = s.split(':').filter(|seg| !seg.is_empty()).count();
    if double_colons == 1 {
        total_groups <= 7
    } else {
        total_groups == 8
    }
}

/// Validate a CIDR string fail-closed, rejecting `0.0.0.0/0` and `::/0` (`SPEC-0002` REQ-0002-03).
pub fn validate_non_wildcard_cidr(cidr: &str) -> Result<(), NetworkPolicyError> {
    let trimmed = cidr.trim();
    if trimmed == "0.0.0.0/0" || trimmed == "::/0" {
        return Err(NetworkPolicyError::UnrestrictedCidrForbidden(
            trimmed.to_string(),
        ));
    }
    let Some((addr_str, prefix_str)) = trimmed.split_once('/') else {
        return Err(NetworkPolicyError::InvalidCidrFormat(cidr.to_string()));
    };
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| NetworkPolicyError::InvalidCidrFormat(cidr.to_string()))?;

    if is_valid_ipv4_literal(addr_str) {
        if prefix == 0 {
            Err(NetworkPolicyError::UnrestrictedCidrForbidden(
                trimmed.to_string(),
            ))
        } else if prefix <= 32 {
            Ok(())
        } else {
            Err(NetworkPolicyError::InvalidCidrFormat(cidr.to_string()))
        }
    } else if is_valid_ipv6_literal(addr_str) {
        if prefix == 0 {
            Err(NetworkPolicyError::UnrestrictedCidrForbidden(
                trimmed.to_string(),
            ))
        } else if prefix <= 128 {
            Ok(())
        } else {
            Err(NetworkPolicyError::InvalidCidrFormat(cidr.to_string()))
        }
    } else {
        Err(NetworkPolicyError::InvalidCidrFormat(cidr.to_string()))
    }
}

/// Construct a zero-trust Kubernetes [`NetworkPolicy`] for `run_id` that denies all ingress and
/// restricts egress to optional cluster DNS (port 53) and validated CIDR blocks.
pub fn build_isolated_network_policy(
    run_id: &str,
    namespace: &str,
    agent_role: Option<&str>,
    egress_spec: Option<&EgressRuleSpec>,
) -> Result<NetworkPolicy, NetworkPolicyError> {
    let labels = canonical_workload_labels(run_id, agent_role)?;
    let default_egress = EgressRuleSpec::default();
    let spec = egress_spec.unwrap_or(&default_egress);

    for cidr in &spec.allowed_cidrs {
        validate_non_wildcard_cidr(cidr)?;
    }
    for &port in &spec.allowed_tcp_ports {
        if port == 0 {
            return Err(NetworkPolicyError::InvalidPortZero);
        }
    }

    let mut egress_rules = Vec::new();

    if spec.allow_dns {
        egress_rules.push(NetworkPolicyEgressRule {
            ports: Some(vec![
                NetworkPolicyPort {
                    protocol: Some("UDP".to_string()),
                    port: Some(IntOrString::Int(53)),
                    end_port: None,
                },
                NetworkPolicyPort {
                    protocol: Some("TCP".to_string()),
                    port: Some(IntOrString::Int(53)),
                    end_port: None,
                },
            ]),
            to: None,
        });
    }

    if !spec.allowed_cidrs.is_empty() {
        let peers: Vec<NetworkPolicyPeer> = spec
            .allowed_cidrs
            .iter()
            .map(|cidr| NetworkPolicyPeer {
                ip_block: Some(IPBlock {
                    cidr: cidr.trim().to_string(),
                    except: None,
                }),
                namespace_selector: None,
                pod_selector: None,
            })
            .collect();

        let ports = if spec.allowed_tcp_ports.is_empty() {
            None
        } else {
            Some(
                spec.allowed_tcp_ports
                    .iter()
                    .map(|&p| NetworkPolicyPort {
                        protocol: Some("TCP".to_string()),
                        port: Some(IntOrString::Int(i32::from(p))),
                        end_port: None,
                    })
                    .collect(),
            )
        };

        egress_rules.push(NetworkPolicyEgressRule {
            ports,
            to: Some(peers),
        });
    }

    Ok(NetworkPolicy {
        metadata: ObjectMeta {
            name: Some(format!("{run_id}-netpol")),
            namespace: Some(namespace.to_string()),
            labels: Some(labels.clone()),
            ..Default::default()
        },
        spec: Some(NetworkPolicySpec {
            pod_selector: Some(K8sLabelSelector {
                match_labels: Some(labels),
                match_expressions: None,
            }),
            policy_types: Some(vec!["Ingress".to_string(), "Egress".to_string()]),
            ingress: None,
            egress: if egress_rules.is_empty() {
                None
            } else {
                Some(egress_rules)
            },
        }),
    })
}

/// Audit a Kubernetes [`NetworkPolicy`] against zero-trust isolation invariants.
pub fn audit_network_policy_zero_trust(policy: &NetworkPolicy) -> Result<(), Vec<String>> {
    let mut violations = Vec::new();
    let Some(spec) = &policy.spec else {
        violations.push("NetworkPolicy.spec is missing".to_string());
        return Err(violations);
    };

    let types = spec.policy_types.as_deref().unwrap_or(&[]);
    if !types.iter().any(|t| t == "Ingress") || !types.iter().any(|t| t == "Egress") {
        violations.push(
            "NetworkPolicy.spec.policyTypes must include both Ingress and Egress".to_string(),
        );
    }

    if spec.ingress.as_ref().is_some_and(|rules| !rules.is_empty()) {
        violations.push(
            "NetworkPolicy.spec.ingress must be empty for default-deny inbound isolation"
                .to_string(),
        );
    }

    if let Some(egress_rules) = &spec.egress {
        for rule in egress_rules {
            if let Some(peers) = &rule.to {
                for peer in peers {
                    if let Some(block) = &peer.ip_block {
                        if let Err(err) = validate_non_wildcard_cidr(&block.cidr) {
                            violations.push(err.to_string());
                        }
                    }
                }
            }
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

    #[test]
    fn test_build_and_audit_isolated_network_policy() {
        let egress = EgressRuleSpec {
            allow_dns: true,
            allowed_cidrs: vec!["10.42.0.0/16".to_string(), "fd00:10:42::/48".to_string()],
            allowed_tcp_ports: vec![443, 7437],
        };

        let policy = build_isolated_network_policy(
            "agent-net1234",
            "agent-ns",
            Some("researcher"),
            Some(&egress),
        )
        .expect("build network policy");

        assert_eq!(
            policy.metadata.name.as_deref(),
            Some("agent-net1234-netpol")
        );
        assert!(audit_network_policy_zero_trust(&policy).is_ok());
    }

    #[test]
    fn test_rejects_wildcard_cidrs_and_invalid_ports() {
        assert!(matches!(
            validate_non_wildcard_cidr("0.0.0.0/0"),
            Err(NetworkPolicyError::UnrestrictedCidrForbidden(_))
        ));
        assert!(matches!(
            validate_non_wildcard_cidr("::/0"),
            Err(NetworkPolicyError::UnrestrictedCidrForbidden(_))
        ));
        assert!(matches!(
            validate_non_wildcard_cidr("192.168.1.1/33"),
            Err(NetworkPolicyError::InvalidCidrFormat(_))
        ));

        let bad_egress = EgressRuleSpec {
            allow_dns: false,
            allowed_cidrs: vec!["10.0.0.0/8".to_string()],
            allowed_tcp_ports: vec![0],
        };
        assert_eq!(
            build_isolated_network_policy("agent-net1234", "default", None, Some(&bad_egress)),
            Err(NetworkPolicyError::InvalidPortZero)
        );
    }
}
