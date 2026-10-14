//! Least-privilege Kubernetes `ServiceAccount`, `Role`, and `RoleBinding`
//! synthesis and static RBAC security auditing (`SPEC-0003`).
//!
//! Enforces:
//! - Dedicated per-workload `ServiceAccount` with `automountServiceAccountToken: Some(false)`
//!   by default so autonomous agents never inherit ambient Kubernetes API credentials.
//! - Scoped namespace-local `Role` and `RoleBinding` synthesis with explicit
//!   `apiGroups`, `resources`, `resourceNames`, and read-only verbs (`get`, `list`, `watch`).
//! - Static RBAC auditing (`audit_role_least_privilege`) that rejects wildcard groups,
//!   wildcard resources, wildcard verbs, privilege-escalation verbs (`escalate`, `bind`,
//!   `impersonate`), and unscoped `secrets` access.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::ServiceAccount;
use k8s_openapi::api::rbac::v1::{PolicyRule, Role, RoleBinding, RoleRef, Subject};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::selector::{validate_dns1123_label, LabelError};

/// Allowed read-only verbs for least-privilege agent workload roles.
pub const ALLOWED_READ_ONLY_VERBS: &[&str] = &["get", "list", "watch"];

/// Privilege-escalation verbs forbidden in any workload or namespace role.
pub const FORBIDDEN_ESCALATION_VERBS: &[&str] = &[
    "escalate",
    "bind",
    "impersonate",
    "create",
    "update",
    "patch",
    "delete",
    "deletecollection",
];

/// Declarative least-privilege rule for a workload-scoped `Role`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ScopedRuleSpec {
    /// Explicit API group (e.g., `""` for core, `"batch"`, `"k8.unsigned.gg"`). Must not be `"*"`.
    pub api_group: String,
    /// Explicit plural resource name (e.g., `"configmaps"`, `"pods"`). Must not be `"*"`.
    pub resource: String,
    /// Explicit resource names this rule applies to. Required when `resource == "secrets"`.
    #[serde(default)]
    pub resource_names: Vec<String>,
    /// Allowed read-only verbs (`"get"`, `"list"`, `"watch"`).
    pub verbs: Vec<String>,
}

/// Errors returned during RBAC synthesis or static auditing (`SPEC-0003`).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RbacError {
    /// Invalid workload, namespace, or resource DNS label.
    #[error("invalid RBAC identifier: {0}")]
    InvalidIdentifier(#[from] LabelError),
    /// `ServiceAccount` enables `automountServiceAccountToken` when zero-trust requires `false`.
    #[error("service account `{name}` must explicitly set automountServiceAccountToken: false")]
    AutomountTokenEnabled {
        /// Name of the violating `ServiceAccount`.
        name: String,
    },
    /// `Role` contains zero rules or an empty verb set.
    #[error("role rule #{rule_index} has an empty {field} list")]
    EmptyRuleField {
        /// 0-based index of the rule.
        rule_index: usize,
        /// Field that was empty.
        field: &'static str,
    },
    /// Wildcard `"*"` found in `apiGroups`, `resources`, or `verbs`.
    #[error("role rule #{rule_index} contains forbidden wildcard `*` in {field}")]
    WildcardForbidden {
        /// 0-based index of the rule.
        rule_index: usize,
        /// Field containing the wildcard.
        field: &'static str,
    },
    /// Forbidden mutating or privilege-escalation verb found in a workload `Role`.
    #[error(
        "role rule #{rule_index} contains forbidden verb `{verb}` (only get/list/watch allowed)"
    )]
    ForbiddenVerb {
        /// 0-based index of the rule.
        rule_index: usize,
        /// Disallowed verb.
        verb: String,
    },
    /// Rule grants access to `secrets` without explicit `resourceNames` or with `list`/`watch`.
    #[error("role rule #{rule_index} accesses `secrets` without explicit resourceNames and `get`-only verb")]
    UnscopedSecretAccess {
        /// 0-based index of the rule.
        rule_index: usize,
    },
    /// Rule contains `nonResourceURLs`, which are cluster-scoped and forbidden in namespace roles.
    #[error(
        "role rule #{rule_index} specifies nonResourceURLs which are forbidden in workload roles"
    )]
    NonResourceUrlsForbidden {
        /// 0-based index of the rule.
        rule_index: usize,
    },
}

/// Synthesizes a dedicated per-workload Kubernetes `ServiceAccount` with
/// `automountServiceAccountToken` explicitly set to `Some(automount_token)`
/// (default `false` for zero-trust agent sandboxes).
///
/// # Errors
///
/// Returns [`RbacError::InvalidIdentifier`] if `workload_name` or `namespace`
/// is not a valid RFC 1123 DNS label.
pub fn build_dedicated_service_account(
    workload_name: &str,
    namespace: &str,
    labels: BTreeMap<String, String>,
    automount_token: bool,
) -> Result<ServiceAccount, RbacError> {
    validate_dns1123_label(workload_name)?;
    validate_dns1123_label(namespace)?;

    Ok(ServiceAccount {
        metadata: ObjectMeta {
            name: Some(format!("{workload_name}-sa")),
            namespace: Some(namespace.to_owned()),
            labels: Some(labels),
            ..Default::default()
        },
        automount_service_account_token: Some(automount_token),
        ..Default::default()
    })
}

/// Audits a Kubernetes `ServiceAccount` to ensure `automountServiceAccountToken`
/// is explicitly set to `Some(false)`.
///
/// # Errors
///
/// Returns [`RbacError::AutomountTokenEnabled`] if `automount_service_account_token`
/// is `None` or `Some(true)`.
pub fn audit_service_account_zero_trust(sa: &ServiceAccount) -> Result<(), RbacError> {
    if sa.automount_service_account_token != Some(false) {
        let name = sa
            .metadata
            .name
            .clone()
            .unwrap_or_else(|| "<unnamed>".to_owned());
        return Err(RbacError::AutomountTokenEnabled { name });
    }
    Ok(())
}

/// Synthesizes a namespace-scoped least-privilege `Role` and validates it against
/// [`audit_role_least_privilege`].
///
/// # Errors
///
/// Returns [`RbacError`] if identifiers are invalid or any [`ScopedRuleSpec`]
/// violates least-privilege invariants.
pub fn build_scoped_role(
    workload_name: &str,
    namespace: &str,
    labels: BTreeMap<String, String>,
    specs: &[ScopedRuleSpec],
) -> Result<Role, RbacError> {
    validate_dns1123_label(workload_name)?;
    validate_dns1123_label(namespace)?;

    let mut rules = Vec::with_capacity(specs.len());
    for spec in specs {
        let resource_names = if spec.resource_names.is_empty() {
            None
        } else {
            Some(spec.resource_names.clone())
        };
        rules.push(PolicyRule {
            api_groups: Some(vec![spec.api_group.clone()]),
            resources: Some(vec![spec.resource.clone()]),
            resource_names,
            verbs: spec.verbs.clone(),
            non_resource_urls: None,
        });
    }

    let role = Role {
        metadata: ObjectMeta {
            name: Some(format!("{workload_name}-role")),
            namespace: Some(namespace.to_owned()),
            labels: Some(labels),
            ..Default::default()
        },
        rules: Some(rules),
    };

    audit_role_least_privilege(&role)?;
    Ok(role)
}

/// Synthesizes a `RoleBinding` binding `<workload_name>-role` to `<workload_name>-sa`
/// in `namespace`.
///
/// # Errors
///
/// Returns [`RbacError::InvalidIdentifier`] if `workload_name` or `namespace`
/// is not a valid RFC 1123 DNS label.
pub fn build_scoped_role_binding(
    workload_name: &str,
    namespace: &str,
    labels: BTreeMap<String, String>,
) -> Result<RoleBinding, RbacError> {
    validate_dns1123_label(workload_name)?;
    validate_dns1123_label(namespace)?;

    Ok(RoleBinding {
        metadata: ObjectMeta {
            name: Some(format!("{workload_name}-rb")),
            namespace: Some(namespace.to_owned()),
            labels: Some(labels),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: Some("rbac.authorization.k8s.io".to_owned()),
            kind: "Role".to_owned(),
            name: format!("{workload_name}-role"),
        },
        subjects: Some(vec![Subject {
            api_group: Some(String::new()),
            kind: "ServiceAccount".to_owned(),
            name: format!("{workload_name}-sa"),
            namespace: Some(namespace.to_owned()),
        }]),
    })
}

/// Audits a Kubernetes `Role` for strict least-privilege compliance (`SPEC-0003`).
///
/// Rejects:
/// - Empty `apiGroups`, `resources`, or `verbs` in any rule
/// - Wildcard `"*"` in `apiGroups`, `resources`, or `verbs`
/// - Any verb outside [`ALLOWED_READ_ONLY_VERBS`] (`get`, `list`, `watch`)
/// - Any rule touching `"secrets"` unless `resourceNames` is non-empty and the
///   only verb is `"get"` (preventing secret enumeration via `list` or `watch`)
/// - Any rule specifying `nonResourceURLs`
///
/// # Errors
///
/// Returns the first [`RbacError`] encountered.
pub fn audit_role_least_privilege(role: &Role) -> Result<(), RbacError> {
    let rules = role.rules.as_deref().unwrap_or(&[]);
    for (rule_index, rule) in rules.iter().enumerate() {
        if rule
            .non_resource_urls
            .as_ref()
            .is_some_and(|urls| !urls.is_empty())
        {
            return Err(RbacError::NonResourceUrlsForbidden { rule_index });
        }

        let api_groups = rule.api_groups.as_deref().unwrap_or(&[]);
        if api_groups.is_empty() {
            return Err(RbacError::EmptyRuleField {
                rule_index,
                field: "apiGroups",
            });
        }
        if api_groups.iter().any(|g| g == "*") {
            return Err(RbacError::WildcardForbidden {
                rule_index,
                field: "apiGroups",
            });
        }

        let resources = rule.resources.as_deref().unwrap_or(&[]);
        if resources.is_empty() {
            return Err(RbacError::EmptyRuleField {
                rule_index,
                field: "resources",
            });
        }
        if resources.iter().any(|r| r == "*") {
            return Err(RbacError::WildcardForbidden {
                rule_index,
                field: "resources",
            });
        }

        if rule.verbs.is_empty() {
            return Err(RbacError::EmptyRuleField {
                rule_index,
                field: "verbs",
            });
        }
        if rule.verbs.iter().any(|v| v == "*") {
            return Err(RbacError::WildcardForbidden {
                rule_index,
                field: "verbs",
            });
        }

        for verb in &rule.verbs {
            if !ALLOWED_READ_ONLY_VERBS.contains(&verb.as_str()) {
                return Err(RbacError::ForbiddenVerb {
                    rule_index,
                    verb: verb.clone(),
                });
            }
        }

        // Special invariant for secrets: must have non-empty resourceNames and only "get" verb.
        let touches_secrets = resources
            .iter()
            .any(|r| r == "secrets" || r.starts_with("secrets/"));
        if touches_secrets {
            let has_explicit_names = rule
                .resource_names
                .as_ref()
                .is_some_and(|names| !names.is_empty() && names.iter().all(|n| !n.is_empty()));
            let only_get_verb = rule.verbs.len() == 1 && rule.verbs[0] == "get";
            if !has_explicit_names || !only_get_verb {
                return Err(RbacError::UnscopedSecretAccess { rule_index });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedicated_service_account_disables_automount_by_default() {
        let sa = build_dedicated_service_account("trainer-01", "default", BTreeMap::new(), false);
        assert!(sa.is_ok());
        let Ok(sa) = sa else { return };
        assert_eq!(sa.metadata.name.as_deref(), Some("trainer-01-sa"));
        assert_eq!(sa.automount_service_account_token, Some(false));
        assert!(audit_service_account_zero_trust(&sa).is_ok());

        let mut bad_sa = sa;
        bad_sa.automount_service_account_token = Some(true);
        assert_eq!(
            audit_service_account_zero_trust(&bad_sa),
            Err(RbacError::AutomountTokenEnabled {
                name: "trainer-01-sa".to_owned(),
            })
        );
    }

    #[test]
    fn scoped_role_accepts_least_privilege_rules_and_named_secret_get() {
        let specs = vec![
            ScopedRuleSpec {
                api_group: String::new(),
                resource: "configmaps".to_owned(),
                resource_names: vec!["trainer-config".to_owned()],
                verbs: vec!["get".to_owned(), "watch".to_owned()],
            },
            ScopedRuleSpec {
                api_group: String::new(),
                resource: "secrets".to_owned(),
                resource_names: vec!["trainer-model-key".to_owned()],
                verbs: vec!["get".to_owned()],
            },
        ];

        let role = build_scoped_role("trainer-01", "default", BTreeMap::new(), &specs);
        assert!(role.is_ok());

        let rb = build_scoped_role_binding("trainer-01", "default", BTreeMap::new());
        assert!(rb.is_ok());
        let Ok(rb) = rb else { return };
        assert_eq!(rb.role_ref.name, "trainer-01-role");
    }

    #[test]
    fn audit_role_rejects_wildcards_escalation_and_unscoped_secrets() {
        // 1. Wildcard verb
        let wildcard_verb = vec![ScopedRuleSpec {
            api_group: String::new(),
            resource: "pods".to_owned(),
            resource_names: vec![],
            verbs: vec!["*".to_owned()],
        }];
        assert_eq!(
            build_scoped_role("trainer-01", "default", BTreeMap::new(), &wildcard_verb),
            Err(RbacError::WildcardForbidden {
                rule_index: 0,
                field: "verbs",
            })
        );

        // 2. Escalation verb
        let escalate_verb = vec![ScopedRuleSpec {
            api_group: "rbac.authorization.k8s.io".to_owned(),
            resource: "roles".to_owned(),
            resource_names: vec![],
            verbs: vec!["escalate".to_owned()],
        }];
        assert_eq!(
            build_scoped_role("trainer-01", "default", BTreeMap::new(), &escalate_verb),
            Err(RbacError::ForbiddenVerb {
                rule_index: 0,
                verb: "escalate".to_owned(),
            })
        );

        // 3. Unscoped secrets list
        let secret_list = vec![ScopedRuleSpec {
            api_group: String::new(),
            resource: "secrets".to_owned(),
            resource_names: vec![],
            verbs: vec!["get".to_owned(), "list".to_owned()],
        }];
        assert_eq!(
            build_scoped_role("trainer-01", "default", BTreeMap::new(), &secret_list),
            Err(RbacError::UnscopedSecretAccess { rule_index: 0 })
        );
    }
}
