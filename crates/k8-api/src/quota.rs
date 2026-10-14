// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Namespace `ResourceQuota`, `LimitRange`, and Kata MicroVM memory-overhead
//! admission governance (`SPEC-0003`).
//!
//! Enforces:
//! - Exact integer arithmetic for CPU (millicores), memory (bytes), and utilization
//!   ratios in permille (`0..=1000+`, where `800` = `80.0%`).
//! - Automatic accounting for per-pod Kata MicroVM hypervisor/guest-kernel memory
//!   overhead ([`DEFAULT_KATA_MEMORY_OVERHEAD_BYTES`], `256Mi`) when
//!   [`IsolationProfile::KataMicroVm`] is active.
//! - Deterministic synthesis of `core/v1::ResourceQuota` and `core/v1::LimitRange`.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{
    LimitRange, LimitRangeItem, LimitRangeSpec, ResourceQuota, ResourceQuotaSpec,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::quantity::{CpuQuantity, MemoryQuantity, QuantityError};
use crate::scheduling::IsolationProfile;
use crate::selector::{validate_dns1123_label, LabelError};

/// Default per-pod hypervisor + guest kernel memory overhead for `runtimeClassName: "kata"` (`256Mi`).
pub const DEFAULT_KATA_MEMORY_OVERHEAD_BYTES: u64 = 256 * 1024 * 1024;

/// Default quota warning threshold in permille (`800` = `80.0%`).
pub const DEFAULT_QUOTA_WARN_PERMILLE: u16 = 800;

/// Declarative hard ceiling specification for a Kubernetes namespace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct NamespaceQuotaSpec {
    /// Hard ceiling on total CPU limits/requests in millicores (`1000` = `1` core).
    pub max_cpu_millis: u64,
    /// Hard ceiling on total memory limits/requests in bytes.
    pub max_memory_bytes: u64,
    /// Hard ceiling on total active Pod count in the namespace.
    pub max_pods: u32,
    /// Warning threshold in permille (`1..=1000`, e.g. `800` for `80.0%`).
    pub warn_threshold_permille: u16,
}

impl Default for NamespaceQuotaSpec {
    fn default() -> Self {
        Self {
            max_cpu_millis: 16_000,
            max_memory_bytes: 32 * 1024 * 1024 * 1024,
            max_pods: 64,
            warn_threshold_permille: DEFAULT_QUOTA_WARN_PERMILLE,
        }
    }
}

/// Snapshot of current resource consumption in a Kubernetes namespace.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QuotaUsageSnapshot {
    /// Currently allocated CPU in millicores.
    pub used_cpu_millis: u64,
    /// Currently allocated memory in bytes.
    pub used_memory_bytes: u64,
    /// Currently active Pod count.
    pub used_pods: u32,
}

/// Deterministic integer headroom and utilization report produced by [`evaluate_quota_admission`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QuotaHeadroomReport {
    /// Total projected CPU usage in millicores after admitting the workload.
    pub projected_cpu_millis: u64,
    /// Total projected memory usage in bytes (including Kata overhead) after admitting the workload.
    pub projected_memory_bytes: u64,
    /// Total projected active pods after admitting the workload.
    pub projected_pods: u32,
    /// Total Kata MicroVM memory overhead in bytes added across all workload replicas.
    pub kata_overhead_bytes: u64,
    /// Projected CPU utilization in permille (`0..=1000`).
    pub cpu_utilization_permille: u64,
    /// Projected memory utilization in permille (`0..=1000`).
    pub memory_utilization_permille: u64,
    /// Projected Pod count utilization in permille (`0..=1000`).
    pub pods_utilization_permille: u64,
    /// Warning messages emitted when any resource crosses `warn_threshold_permille`.
    pub warnings: Vec<String>,
}

/// Errors returned during namespace quota synthesis or admission evaluation (`SPEC-0003`).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum QuotaError {
    /// Invalid DNS label for quota or namespace.
    #[error("invalid quota identifier: {0}")]
    InvalidIdentifier(#[from] LabelError),
    /// Invalid resource quantity string.
    #[error("invalid resource quantity in quota evaluation: {0}")]
    InvalidQuantity(#[from] QuantityError),
    /// Quota ceiling configured with zero capacity.
    #[error("namespace quota ceiling for `{resource}` must be strictly positive")]
    ZeroQuotaCeiling {
        /// Resource name (`cpu`, `memory`, or `pods`).
        resource: &'static str,
    },
    /// Arithmetic overflow when summing replica demands.
    #[error("quota arithmetic overflow while computing `{resource}` demand")]
    ArithmeticOverflow {
        /// Resource name.
        resource: &'static str,
    },
    /// Projected resource usage exceeds the namespace hard ceiling.
    #[error(
        "namespace quota exceeded for `{resource}`: projected {projected} > hard ceiling {ceiling}"
    )]
    QuotaExceeded {
        /// Resource dimension that breached the hard ceiling.
        resource: &'static str,
        /// Projected usage after admitting the workload.
        projected: u64,
        /// Configured hard ceiling.
        ceiling: u64,
    },
}

/// Computes exact integer permille (`projected * 1000 / ceiling`).
fn compute_permille(projected: u64, ceiling: u64) -> Result<u64, QuotaError> {
    if ceiling == 0 {
        return Err(QuotaError::ZeroQuotaCeiling {
            resource: "ceiling",
        });
    }
    let scaled = u128::from(projected)
        .checked_mul(1000)
        .ok_or(QuotaError::ArithmeticOverflow {
            resource: "permille",
        })?;
    let ratio = scaled / u128::from(ceiling);
    u64::try_from(ratio).map_err(|_| QuotaError::ArithmeticOverflow {
        resource: "permille",
    })
}

/// Evaluates whether a workload with `replicas`, per-replica `cpu_limit` and `memory_limit`,
/// and `isolation_profile` fits within `quota` given `usage` (`SPEC-0003`).
///
/// When `isolation_profile == IsolationProfile::KataMicroVm`, adds
/// [`DEFAULT_KATA_MEMORY_OVERHEAD_BYTES`] per replica to account for Kata VMM memory.
///
/// # Errors
///
/// Returns [`QuotaError`] if any ceiling is zero, quantities are invalid, or projected
/// usage exceeds the hard ceiling.
pub fn evaluate_quota_admission(
    quota: &NamespaceQuotaSpec,
    usage: &QuotaUsageSnapshot,
    replicas: u32,
    cpu_limit: &str,
    memory_limit: &str,
    isolation_profile: IsolationProfile,
) -> Result<QuotaHeadroomReport, QuotaError> {
    if quota.max_cpu_millis == 0 {
        return Err(QuotaError::ZeroQuotaCeiling { resource: "cpu" });
    }
    if quota.max_memory_bytes == 0 {
        return Err(QuotaError::ZeroQuotaCeiling { resource: "memory" });
    }
    if quota.max_pods == 0 {
        return Err(QuotaError::ZeroQuotaCeiling { resource: "pods" });
    }
    if replicas == 0 {
        return Err(QuotaError::ZeroQuotaCeiling {
            resource: "replicas",
        });
    }

    let per_pod_cpu = cpu_limit.parse::<CpuQuantity>()?.millicores();
    let per_pod_mem = memory_limit.parse::<MemoryQuantity>()?.bytes();
    let replicas_u64 = u64::from(replicas);

    let per_pod_kata_overhead = match isolation_profile {
        IsolationProfile::StandardRestricted => 0,
        IsolationProfile::KataMicroVm => DEFAULT_KATA_MEMORY_OVERHEAD_BYTES,
    };

    let kata_overhead_bytes =
        replicas_u64
            .checked_mul(per_pod_kata_overhead)
            .ok_or(QuotaError::ArithmeticOverflow {
                resource: "kata_overhead",
            })?;

    let workload_cpu = replicas_u64
        .checked_mul(per_pod_cpu)
        .ok_or(QuotaError::ArithmeticOverflow { resource: "cpu" })?;
    let workload_container_mem = replicas_u64
        .checked_mul(per_pod_mem)
        .ok_or(QuotaError::ArithmeticOverflow { resource: "memory" })?;
    let workload_total_mem = workload_container_mem
        .checked_add(kata_overhead_bytes)
        .ok_or(QuotaError::ArithmeticOverflow { resource: "memory" })?;

    let projected_cpu_millis = usage
        .used_cpu_millis
        .checked_add(workload_cpu)
        .ok_or(QuotaError::ArithmeticOverflow { resource: "cpu" })?;
    let projected_memory_bytes = usage
        .used_memory_bytes
        .checked_add(workload_total_mem)
        .ok_or(QuotaError::ArithmeticOverflow { resource: "memory" })?;
    let projected_pods = usage
        .used_pods
        .checked_add(replicas)
        .ok_or(QuotaError::ArithmeticOverflow { resource: "pods" })?;

    if projected_cpu_millis > quota.max_cpu_millis {
        return Err(QuotaError::QuotaExceeded {
            resource: "cpu",
            projected: projected_cpu_millis,
            ceiling: quota.max_cpu_millis,
        });
    }
    if projected_memory_bytes > quota.max_memory_bytes {
        return Err(QuotaError::QuotaExceeded {
            resource: "memory",
            projected: projected_memory_bytes,
            ceiling: quota.max_memory_bytes,
        });
    }
    if projected_pods > quota.max_pods {
        return Err(QuotaError::QuotaExceeded {
            resource: "pods",
            projected: u64::from(projected_pods),
            ceiling: u64::from(quota.max_pods),
        });
    }

    let cpu_utilization_permille = compute_permille(projected_cpu_millis, quota.max_cpu_millis)?;
    let memory_utilization_permille =
        compute_permille(projected_memory_bytes, quota.max_memory_bytes)?;
    let pods_utilization_permille =
        compute_permille(u64::from(projected_pods), u64::from(quota.max_pods))?;

    let warn_threshold = u64::from(quota.warn_threshold_permille);
    let mut warnings = Vec::new();
    if cpu_utilization_permille >= warn_threshold {
        warnings.push(format!(
            "cpu utilization {cpu_utilization_permille} permille >= warning threshold {warn_threshold} permille"
        ));
    }
    if memory_utilization_permille >= warn_threshold {
        warnings.push(format!(
            "memory utilization {memory_utilization_permille} permille >= warning threshold {warn_threshold} permille"
        ));
    }
    if pods_utilization_permille >= warn_threshold {
        warnings.push(format!(
            "pods utilization {pods_utilization_permille} permille >= warning threshold {warn_threshold} permille"
        ));
    }

    Ok(QuotaHeadroomReport {
        projected_cpu_millis,
        projected_memory_bytes,
        projected_pods,
        kata_overhead_bytes,
        cpu_utilization_permille,
        memory_utilization_permille,
        pods_utilization_permille,
        warnings,
    })
}

/// Synthesizes a canonical Kubernetes `core/v1::ResourceQuota` object for a namespace.
///
/// # Errors
///
/// Returns [`QuotaError`] if `name` or `namespace` is not a valid DNS label or any
/// ceiling in `spec` is zero.
pub fn build_namespace_resource_quota(
    name: &str,
    namespace: &str,
    labels: BTreeMap<String, String>,
    spec: &NamespaceQuotaSpec,
) -> Result<ResourceQuota, QuotaError> {
    validate_dns1123_label(name)?;
    validate_dns1123_label(namespace)?;
    if spec.max_cpu_millis == 0 {
        return Err(QuotaError::ZeroQuotaCeiling { resource: "cpu" });
    }
    if spec.max_memory_bytes == 0 {
        return Err(QuotaError::ZeroQuotaCeiling { resource: "memory" });
    }
    if spec.max_pods == 0 {
        return Err(QuotaError::ZeroQuotaCeiling { resource: "pods" });
    }

    let cpu_qty = CpuQuantity::from_millicores(spec.max_cpu_millis).to_k8s_quantity();
    let mem_qty = MemoryQuantity::from_bytes(spec.max_memory_bytes).to_k8s_quantity();

    let mut hard = BTreeMap::new();
    hard.insert("requests.cpu".to_owned(), cpu_qty.clone());
    hard.insert("limits.cpu".to_owned(), cpu_qty);
    hard.insert("requests.memory".to_owned(), mem_qty.clone());
    hard.insert("limits.memory".to_owned(), mem_qty);
    hard.insert("pods".to_owned(), Quantity(spec.max_pods.to_string()));

    Ok(ResourceQuota {
        metadata: ObjectMeta {
            name: Some(name.to_owned()),
            namespace: Some(namespace.to_owned()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: Some(ResourceQuotaSpec {
            hard: Some(hard),
            ..Default::default()
        }),
        ..Default::default()
    })
}

/// Synthesizes a Kubernetes `core/v1::LimitRange` enforcing default and maximum
/// per-container CPU and memory bounds in a namespace.
///
/// # Errors
///
/// Returns [`QuotaError`] if `name`/`namespace` are invalid DNS labels or the default/max
/// quantities fail validation.
pub fn build_namespace_limit_range(
    name: &str,
    namespace: &str,
    labels: BTreeMap<String, String>,
    default_cpu: &str,
    default_memory: &str,
    max_cpu: &str,
    max_memory: &str,
) -> Result<LimitRange, QuotaError> {
    validate_dns1123_label(name)?;
    validate_dns1123_label(namespace)?;

    let def_cpu = default_cpu.parse::<CpuQuantity>()?;
    let def_mem = default_memory.parse::<MemoryQuantity>()?;
    let max_cpu_qty = max_cpu.parse::<CpuQuantity>()?;
    let max_mem_qty = max_memory.parse::<MemoryQuantity>()?;

    if def_cpu.millicores() > max_cpu_qty.millicores() {
        return Err(QuotaError::QuotaExceeded {
            resource: "limit_range.cpu",
            projected: def_cpu.millicores(),
            ceiling: max_cpu_qty.millicores(),
        });
    }
    if def_mem.bytes() > max_mem_qty.bytes() {
        return Err(QuotaError::QuotaExceeded {
            resource: "limit_range.memory",
            projected: def_mem.bytes(),
            ceiling: max_mem_qty.bytes(),
        });
    }

    let mut default_map = BTreeMap::new();
    default_map.insert("cpu".to_owned(), def_cpu.to_k8s_quantity());
    default_map.insert("memory".to_owned(), def_mem.to_k8s_quantity());

    let mut max_map = BTreeMap::new();
    max_map.insert("cpu".to_owned(), max_cpu_qty.to_k8s_quantity());
    max_map.insert("memory".to_owned(), max_mem_qty.to_k8s_quantity());

    Ok(LimitRange {
        metadata: ObjectMeta {
            name: Some(name.to_owned()),
            namespace: Some(namespace.to_owned()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: Some(LimitRangeSpec {
            limits: vec![LimitRangeItem {
                type_: "Container".to_owned(),
                default: Some(default_map.clone()),
                default_request: Some(default_map),
                max: Some(max_map),
                ..Default::default()
            }],
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kata_microvm_overhead_is_accounted_in_quota_admission() {
        let quota = NamespaceQuotaSpec {
            max_cpu_millis: 4000,
            max_memory_bytes: 2 * 1024 * 1024 * 1024,
            max_pods: 10,
            warn_threshold_permille: 800,
        };
        let usage = QuotaUsageSnapshot {
            used_cpu_millis: 1000,
            used_memory_bytes: 1024 * 1024 * 1024,
            used_pods: 2,
        };

        let standard = evaluate_quota_admission(
            &quota,
            &usage,
            1,
            "1",
            "896Mi",
            IsolationProfile::StandardRestricted,
        );
        assert!(standard.is_ok());
        let Ok(standard_report) = standard else {
            return;
        };
        assert_eq!(standard_report.kata_overhead_bytes, 0);
        assert_eq!(standard_report.memory_utilization_permille, 937);
        assert_eq!(standard_report.warnings.len(), 1);

        let kata = evaluate_quota_admission(
            &quota,
            &usage,
            1,
            "1",
            "896Mi",
            IsolationProfile::KataMicroVm,
        );
        assert_eq!(
            kata,
            Err(QuotaError::QuotaExceeded {
                resource: "memory",
                projected: 2176 * 1024 * 1024,
                ceiling: 2048 * 1024 * 1024,
            })
        );
    }

    #[test]
    fn builds_resource_quota_and_limit_range_manifests() {
        let spec = NamespaceQuotaSpec::default();
        let rq = build_namespace_resource_quota("agent-quota", "default", BTreeMap::new(), &spec);
        assert!(rq.is_ok());

        let lr = build_namespace_limit_range(
            "agent-limits",
            "default",
            BTreeMap::new(),
            "500m",
            "512Mi",
            "4",
            "8Gi",
        );
        assert!(lr.is_ok());
    }
}
