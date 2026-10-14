// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `drift`: Pure zero-I/O Kubernetes Immutable Field & StatefulSet `volumeClaimTemplates`
//! Drift Detector (`SPEC-0005`).
//!
//! Detects mutations to immutable fields on `StatefulSet` (`apps/v1`), `Job` (`batch/v1`),
//! and `PersistentVolumeClaim` (`core/v1`) before Server-Side Apply (`Patch::Apply`) so
//! controllers can route changes to `--cascade=orphan` PVC expansion, `DeleteAndRecreate`,
//! or fail-closed rejection instead of wedging on `422 Unprocessable Entity (Invalid)`.

use crate::quantity::MemoryQuantity;
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::PersistentVolumeClaim;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Remediation strategy selected by the immutable drift detector (`SPEC-0005`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum DriftRemediationStrategy {
    /// No immutable fields changed; safe to apply directly via Server-Side Apply (`Patch::Apply`).
    InPlaceApply,
    /// `StatefulSet` `volumeClaimTemplates` storage request increased while all other immutable
    /// fields remained identical (`INV-0005-03`). Requires patching underlying PVCs and recreating
    /// the `StatefulSet` with `PropagationPolicy::Orphan` (`--cascade=orphan`).
    OrphanRecreateWithPvcExpand,
    /// Immutable `Job` template/selector/completion fields changed; requires deleting the existing
    /// `Job` (`PropagationPolicy::Background`) and recreating it.
    DeleteAndRecreate,
    /// Mutation violates Kubernetes immutability invariants (e.g. PVC storage shrinkage, mutated
    /// `StatefulSet.spec.serviceName` / `selector` / `storageClassName`) and must be rejected fail-closed.
    RejectedForbiddenMutation,
}

/// Classification of an individual immutable field drift finding (`SPEC-0005`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum DriftKind {
    /// An immutable scalar or selector field (`serviceName`, `selector`, `storageClassName`, `accessModes`) changed.
    ForbiddenImmutableField {
        /// JSONPath-style field path.
        field_path: String,
        /// Live cluster value.
        live_value: String,
        /// Desired manifest value.
        desired_value: String,
    },
    /// Attempted to shrink a PVC or `volumeClaimTemplate` storage request (`INV-0005-03`).
    ForbiddenStorageShrinkage {
        /// Field path (`spec.resources.requests.storage` or template equivalent).
        field_path: String,
        /// Live storage capacity in bytes.
        live_bytes: u64,
        /// Desired (smaller) storage capacity in bytes.
        desired_bytes: u64,
    },
    /// `StatefulSet` `volumeClaimTemplates` added, removed, or renamed a template entry.
    ForbiddenVolumeClaimTemplateTopologyChange {
        /// Description of the template list change.
        detail: String,
    },
    /// `StatefulSet` `volumeClaimTemplate` storage request increased monotonically.
    VolumeClaimTemplateStorageExpanded {
        /// Name of the `volumeClaimTemplate`.
        template_name: String,
        /// Previous storage request in bytes.
        live_bytes: u64,
        /// Expanded storage request in bytes.
        desired_bytes: u64,
    },
    /// `Job` immutable field (`spec.completions`, `spec.completionMode`, `spec.selector`, or container image) changed.
    ImmutableJobFieldChanged {
        /// JSONPath-style field path.
        field_path: String,
        /// Live cluster value.
        live_value: String,
        /// Desired manifest value.
        desired_value: String,
    },
}

/// Deterministic immutable drift report for a Kubernetes resource (`SPEC-0005`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ImmutableDriftReport {
    /// Resource kind and name (`<Kind>/<namespace>/<name>`).
    pub resource_id: String,
    /// Selected remediation strategy (`InPlaceApply`, `OrphanRecreateWithPvcExpand`, `DeleteAndRecreate`, or `RejectedForbiddenMutation`).
    pub strategy: DriftRemediationStrategy,
    /// Ordered list of immutable drift findings.
    pub findings: Vec<DriftKind>,
    /// Deterministic 64-bit FNV-1a hex digest over the drift report.
    pub report_digest: String,
}

/// Audits a live vs. desired Kubernetes [`StatefulSet`] for immutable field and
/// `volumeClaimTemplates` drift (`SPEC-0005`, `INV-0005-03`).
#[must_use]
pub fn audit_statefulset_immutable_drift(
    live: &StatefulSet,
    desired: &StatefulSet,
) -> ImmutableDriftReport {
    let ns = desired
        .metadata
        .namespace
        .as_deref()
        .or(live.metadata.namespace.as_deref())
        .unwrap_or("default");
    let name = desired
        .metadata
        .name
        .as_deref()
        .or(live.metadata.name.as_deref())
        .unwrap_or("unnamed");
    let resource_id = format!("StatefulSet/{ns}/{name}");

    let mut findings = Vec::new();
    let mut has_forbidden = false;
    let mut has_vct_expansion = false;

    if let (Some(live_spec), Some(desired_spec)) = (&live.spec, &desired.spec) {
        if live_spec.service_name != desired_spec.service_name {
            has_forbidden = true;
            findings.push(DriftKind::ForbiddenImmutableField {
                field_path: "spec.serviceName".to_owned(),
                live_value: live_spec.service_name.clone().unwrap_or_default(),
                desired_value: desired_spec.service_name.clone().unwrap_or_default(),
            });
        }

        if live_spec.pod_management_policy != desired_spec.pod_management_policy {
            has_forbidden = true;
            findings.push(DriftKind::ForbiddenImmutableField {
                field_path: "spec.podManagementPolicy".to_owned(),
                live_value: live_spec.pod_management_policy.clone().unwrap_or_default(),
                desired_value: desired_spec
                    .pod_management_policy
                    .clone()
                    .unwrap_or_default(),
            });
        }

        if live_spec.selector != desired_spec.selector {
            has_forbidden = true;
            findings.push(DriftKind::ForbiddenImmutableField {
                field_path: "spec.selector".to_owned(),
                live_value: format!("{:?}", live_spec.selector.match_labels),
                desired_value: format!("{:?}", desired_spec.selector.match_labels),
            });
        }

        let live_vcts = live_spec.volume_claim_templates.as_deref().unwrap_or(&[]);
        let desired_vcts = desired_spec
            .volume_claim_templates
            .as_deref()
            .unwrap_or(&[]);

        let live_map: BTreeMap<&str, &PersistentVolumeClaim> = live_vcts
            .iter()
            .filter_map(|pvc| pvc.metadata.name.as_deref().map(|n| (n, pvc)))
            .collect();
        let desired_map: BTreeMap<&str, &PersistentVolumeClaim> = desired_vcts
            .iter()
            .filter_map(|pvc| pvc.metadata.name.as_deref().map(|n| (n, pvc)))
            .collect();

        if live_vcts.len() != desired_vcts.len()
            || live_map.keys().collect::<Vec<_>>() != desired_map.keys().collect::<Vec<_>>()
        {
            has_forbidden = true;
            findings.push(DriftKind::ForbiddenVolumeClaimTemplateTopologyChange {
                detail: format!(
                    "live templates {:?} != desired templates {:?}",
                    live_map.keys().collect::<Vec<_>>(),
                    desired_map.keys().collect::<Vec<_>>()
                ),
            });
        } else {
            for (tpl_name, live_pvc) in &live_map {
                if let Some(desired_pvc) = desired_map.get(tpl_name) {
                    audit_pvc_pair(
                        live_pvc,
                        desired_pvc,
                        &format!("spec.volumeClaimTemplates[{tpl_name}]"),
                        Some(tpl_name),
                        &mut findings,
                        &mut has_forbidden,
                        &mut has_vct_expansion,
                    );
                }
            }
        }
    }

    let strategy = if has_forbidden {
        DriftRemediationStrategy::RejectedForbiddenMutation
    } else if has_vct_expansion {
        DriftRemediationStrategy::OrphanRecreateWithPvcExpand
    } else {
        DriftRemediationStrategy::InPlaceApply
    };

    let report_digest = compute_drift_digest(&resource_id, strategy, &findings);
    ImmutableDriftReport {
        resource_id,
        strategy,
        findings,
        report_digest,
    }
}

/// Audits a live vs. desired Kubernetes [`PersistentVolumeClaim`] for immutable field mutations
/// and storage shrinkage (`SPEC-0005`, `INV-0005-03`).
#[must_use]
pub fn audit_pvc_mutation(
    live: &PersistentVolumeClaim,
    desired: &PersistentVolumeClaim,
) -> ImmutableDriftReport {
    let ns = desired
        .metadata
        .namespace
        .as_deref()
        .or(live.metadata.namespace.as_deref())
        .unwrap_or("default");
    let name = desired
        .metadata
        .name
        .as_deref()
        .or(live.metadata.name.as_deref())
        .unwrap_or("unnamed");
    let resource_id = format!("PersistentVolumeClaim/{ns}/{name}");

    let mut findings = Vec::new();
    let mut has_forbidden = false;
    let mut unused_expansion = false;

    audit_pvc_pair(
        live,
        desired,
        "spec",
        None,
        &mut findings,
        &mut has_forbidden,
        &mut unused_expansion,
    );

    let strategy = if has_forbidden {
        DriftRemediationStrategy::RejectedForbiddenMutation
    } else {
        DriftRemediationStrategy::InPlaceApply
    };

    let report_digest = compute_drift_digest(&resource_id, strategy, &findings);
    ImmutableDriftReport {
        resource_id,
        strategy,
        findings,
        report_digest,
    }
}

fn audit_pvc_pair(
    live: &PersistentVolumeClaim,
    desired: &PersistentVolumeClaim,
    prefix: &str,
    vct_template_name: Option<&str>,
    findings: &mut Vec<DriftKind>,
    has_forbidden: &mut bool,
    has_vct_expansion: &mut bool,
) {
    let (Some(live_spec), Some(desired_spec)) = (&live.spec, &desired.spec) else {
        return;
    };

    if live_spec.storage_class_name != desired_spec.storage_class_name {
        *has_forbidden = true;
        findings.push(DriftKind::ForbiddenImmutableField {
            field_path: format!("{prefix}.storageClassName"),
            live_value: live_spec.storage_class_name.clone().unwrap_or_default(),
            desired_value: desired_spec.storage_class_name.clone().unwrap_or_default(),
        });
    }

    if live_spec.access_modes != desired_spec.access_modes {
        *has_forbidden = true;
        findings.push(DriftKind::ForbiddenImmutableField {
            field_path: format!("{prefix}.accessModes"),
            live_value: format!("{:?}", live_spec.access_modes),
            desired_value: format!("{:?}", desired_spec.access_modes),
        });
    }

    if live_spec.volume_mode != desired_spec.volume_mode {
        *has_forbidden = true;
        findings.push(DriftKind::ForbiddenImmutableField {
            field_path: format!("{prefix}.volumeMode"),
            live_value: live_spec.volume_mode.clone().unwrap_or_default(),
            desired_value: desired_spec.volume_mode.clone().unwrap_or_default(),
        });
    }

    if live_spec.volume_name.is_some() && live_spec.volume_name != desired_spec.volume_name {
        *has_forbidden = true;
        findings.push(DriftKind::ForbiddenImmutableField {
            field_path: format!("{prefix}.volumeName"),
            live_value: live_spec.volume_name.clone().unwrap_or_default(),
            desired_value: desired_spec.volume_name.clone().unwrap_or_default(),
        });
    }

    let live_storage_bytes = extract_storage_bytes(live);
    let desired_storage_bytes = extract_storage_bytes(desired);
    if let (Some(live_b), Some(desired_b)) = (live_storage_bytes, desired_storage_bytes) {
        if desired_b < live_b {
            *has_forbidden = true;
            findings.push(DriftKind::ForbiddenStorageShrinkage {
                field_path: format!("{prefix}.resources.requests.storage"),
                live_bytes: live_b,
                desired_bytes: desired_b,
            });
        } else if desired_b > live_b {
            if let Some(tpl) = vct_template_name {
                *has_vct_expansion = true;
                findings.push(DriftKind::VolumeClaimTemplateStorageExpanded {
                    template_name: tpl.to_owned(),
                    live_bytes: live_b,
                    desired_bytes: desired_b,
                });
            }
        }
    }
}

fn extract_storage_bytes(pvc: &PersistentVolumeClaim) -> Option<u64> {
    let raw = pvc
        .spec
        .as_ref()?
        .resources
        .as_ref()?
        .requests
        .as_ref()?
        .get("storage")?
        .0
        .as_str();
    raw.parse::<MemoryQuantity>()
        .ok()
        .map(MemoryQuantity::bytes)
}

/// Audits a live vs. desired Kubernetes [`Job`] (`batch/v1`) for immutable field drift
/// that requires `DeleteAndRecreate` instead of in-place Server-Side Apply (`SPEC-0005`).
#[must_use]
pub fn audit_job_immutable_drift(live: &Job, desired: &Job) -> ImmutableDriftReport {
    let ns = desired
        .metadata
        .namespace
        .as_deref()
        .or(live.metadata.namespace.as_deref())
        .unwrap_or("default");
    let name = desired
        .metadata
        .name
        .as_deref()
        .or(live.metadata.name.as_deref())
        .unwrap_or("unnamed");
    let resource_id = format!("Job/{ns}/{name}");

    let mut findings = Vec::new();
    if let (Some(live_spec), Some(desired_spec)) = (&live.spec, &desired.spec) {
        if live_spec.completion_mode != desired_spec.completion_mode {
            findings.push(DriftKind::ImmutableJobFieldChanged {
                field_path: "spec.completionMode".to_owned(),
                live_value: live_spec.completion_mode.clone().unwrap_or_default(),
                desired_value: desired_spec.completion_mode.clone().unwrap_or_default(),
            });
        }
        if live_spec.completions != desired_spec.completions {
            findings.push(DriftKind::ImmutableJobFieldChanged {
                field_path: "spec.completions".to_owned(),
                live_value: format!("{:?}", live_spec.completions),
                desired_value: format!("{:?}", desired_spec.completions),
            });
        }
        if live_spec.selector != desired_spec.selector {
            findings.push(DriftKind::ImmutableJobFieldChanged {
                field_path: "spec.selector".to_owned(),
                live_value: format!("{:?}", live_spec.selector),
                desired_value: format!("{:?}", desired_spec.selector),
            });
        }

        let live_images: Vec<&str> = live_spec
            .template
            .spec
            .as_ref()
            .map(|ps| {
                ps.containers
                    .iter()
                    .filter_map(|c| c.image.as_deref())
                    .collect()
            })
            .unwrap_or_default();
        let desired_images: Vec<&str> = desired_spec
            .template
            .spec
            .as_ref()
            .map(|ps| {
                ps.containers
                    .iter()
                    .filter_map(|c| c.image.as_deref())
                    .collect()
            })
            .unwrap_or_default();
        if live_images != desired_images {
            findings.push(DriftKind::ImmutableJobFieldChanged {
                field_path: "spec.template.spec.containers[*].image".to_owned(),
                live_value: live_images.join(","),
                desired_value: desired_images.join(","),
            });
        }
    }

    let strategy = if findings.is_empty() {
        DriftRemediationStrategy::InPlaceApply
    } else {
        DriftRemediationStrategy::DeleteAndRecreate
    };
    let report_digest = compute_drift_digest(&resource_id, strategy, &findings);
    ImmutableDriftReport {
        resource_id,
        strategy,
        findings,
        report_digest,
    }
}

fn compute_drift_digest(
    resource_id: &str,
    strategy: DriftRemediationStrategy,
    findings: &[DriftKind],
) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |bytes: &[u8]| {
        for &b in bytes {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    };
    feed(resource_id.as_bytes());
    let strat_tag: &[u8] = match strategy {
        DriftRemediationStrategy::InPlaceApply => b":in-place;",
        DriftRemediationStrategy::OrphanRecreateWithPvcExpand => b":orphan-expand;",
        DriftRemediationStrategy::DeleteAndRecreate => b":recreate;",
        DriftRemediationStrategy::RejectedForbiddenMutation => b":rejected;",
    };
    feed(strat_tag);
    for f in findings {
        let repr = format!("{f:?}");
        feed(repr.as_bytes());
    }
    format!("{hash:016x}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use k8s_openapi::api::apps::v1::StatefulSetSpec;
    use k8s_openapi::api::core::v1::{PersistentVolumeClaimSpec, VolumeResourceRequirements};
    use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};

    fn sample_sts(storage: &str, service_name: &str) -> StatefulSet {
        let mut reqs = BTreeMap::new();
        reqs.insert("storage".to_owned(), Quantity(storage.to_owned()));
        StatefulSet {
            metadata: ObjectMeta {
                name: Some("reverie-db".to_owned()),
                namespace: Some("agents".to_owned()),
                ..Default::default()
            },
            spec: Some(StatefulSetSpec {
                service_name: Some(service_name.to_owned()),
                selector: LabelSelector {
                    match_labels: Some(BTreeMap::from([(
                        "app".to_owned(),
                        "reverie-db".to_owned(),
                    )])),
                    ..Default::default()
                },
                volume_claim_templates: Some(vec![PersistentVolumeClaim {
                    metadata: ObjectMeta {
                        name: Some("data".to_owned()),
                        ..Default::default()
                    },
                    spec: Some(PersistentVolumeClaimSpec {
                        storage_class_name: Some("hcloud-volumes".to_owned()),
                        access_modes: Some(vec!["ReadWriteOnce".to_owned()]),
                        resources: Some(VolumeResourceRequirements {
                            requests: Some(reqs),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn statefulset_vct_expansion_selects_orphan_recreate_and_shrink_is_rejected() {
        let live = sample_sts("10Gi", "reverie-headless");
        let expanded = sample_sts("20Gi", "reverie-headless");
        let shrunk = sample_sts("5Gi", "reverie-headless");
        let renamed_svc = sample_sts("20Gi", "other-headless");

        let r_same = audit_statefulset_immutable_drift(&live, &live);
        assert_eq!(r_same.strategy, DriftRemediationStrategy::InPlaceApply);

        let r_exp = audit_statefulset_immutable_drift(&live, &expanded);
        assert_eq!(
            r_exp.strategy,
            DriftRemediationStrategy::OrphanRecreateWithPvcExpand
        );

        let r_shrunk = audit_statefulset_immutable_drift(&live, &shrunk);
        assert_eq!(
            r_shrunk.strategy,
            DriftRemediationStrategy::RejectedForbiddenMutation
        );

        let r_svc = audit_statefulset_immutable_drift(&live, &renamed_svc);
        assert_eq!(
            r_svc.strategy,
            DriftRemediationStrategy::RejectedForbiddenMutation
        );
    }
}
