// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded ephemeral scratch volumes (`emptyDir`), mount-path traversal prevention,
//! and static `PodSpec` volume security auditing (`SPEC-0003`).
//!
//! Because `k8-api::security` mandates `readOnlyRootFilesystem: true`, sandboxed
//! agent containers require bounded writable scratch directories (e.g. `/tmp` or
//! `/workspace`). This module synthesizes size-limited `emptyDir` volumes and
//! audits `PodSpec` volumes to forbid `hostPath`, unbounded `emptyDir`, path
//! traversal (`..`), and sensitive system mount targets.

use k8s_openapi::api::core::v1::{EmptyDirVolumeSource, PodSpec, Volume, VolumeMount};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::quantity::{MemoryQuantity, QuantityError};
use crate::selector::{validate_dns1123_label, LabelError};

/// Default scratch volume name for `/tmp`.
pub const DEFAULT_SCRATCH_VOLUME_NAME: &str = "scratch-tmp";

/// Default scratch mount path (`"/tmp"`).
pub const DEFAULT_SCRATCH_MOUNT_PATH: &str = "/tmp";

/// Default scratch volume size limit (`"64Mi"`).
pub const DEFAULT_SCRATCH_SIZE_LIMIT: &str = "64Mi";

/// Sensitive kernel, runtime, and credential mount prefixes that workloads must never shadow.
pub const FORBIDDEN_MOUNT_PREFIXES: &[&str] = &[
    "/proc",
    "/sys",
    "/dev",
    "/var/run",
    "/run",
    "/etc/kubernetes",
    "/etc/passwd",
    "/etc/shadow",
    "/boot",
];

/// Backing storage medium for a bounded `emptyDir` scratch volume.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ScratchMedium {
    /// Node ephemeral filesystem (`emptyDir.medium: ""`) bounded by `sizeLimit`.
    Disk,
    /// RAM-backed `tmpfs` (`emptyDir.medium: "Memory"`) bounded by `sizeLimit` and container memory limit.
    #[default]
    Memory,
}

impl ScratchMedium {
    /// Returns the Kubernetes `emptyDir.medium` string representation.
    #[must_use]
    pub const fn as_k8s_medium(self) -> Option<&'static str> {
        match self {
            Self::Disk => None,
            Self::Memory => Some("Memory"),
        }
    }
}

/// Declarative specification for a bounded ephemeral scratch volume (`SPEC-0003`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ScratchVolumeSpec {
    /// DNS-1123 volume name (e.g. `"scratch-tmp"`).
    pub name: String,
    /// Validated absolute container mount path (e.g. `"/tmp"` or `"/workspace"`).
    pub mount_path: String,
    /// Mandatory positive storage ceiling (e.g. `"64Mi"`, `"1Gi"`).
    pub size_limit: String,
    /// Backing storage medium (`Disk` or `Memory`).
    #[serde(default)]
    pub medium: ScratchMedium,
}

impl Default for ScratchVolumeSpec {
    fn default() -> Self {
        Self {
            name: DEFAULT_SCRATCH_VOLUME_NAME.to_owned(),
            mount_path: DEFAULT_SCRATCH_MOUNT_PATH.to_owned(),
            size_limit: DEFAULT_SCRATCH_SIZE_LIMIT.to_owned(),
            medium: ScratchMedium::Memory,
        }
    }
}

/// Errors returned during scratch volume synthesis or `PodSpec` volume auditing (`SPEC-0003`).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// Invalid volume name DNS label.
    #[error("invalid volume name: {0}")]
    InvalidVolumeName(#[from] LabelError),
    /// Invalid `sizeLimit` quantity.
    #[error("invalid volume sizeLimit quantity: {0}")]
    InvalidSizeLimit(#[from] QuantityError),
    /// `hostPath` volume detected in a workload `PodSpec`.
    #[error("volume `{volume_name}` uses forbidden hostPath mount")]
    HostPathForbidden {
        /// Name of the violating volume.
        volume_name: String,
    },
    /// `emptyDir` volume is missing a positive `sizeLimit`.
    #[error("volume `{volume_name}` uses unbounded emptyDir without a positive sizeLimit")]
    UnboundedEmptyDir {
        /// Name of the violating volume.
        volume_name: String,
    },
    /// Container mount path is not a clean, non-root absolute path.
    #[error("invalid container mountPath `{mount_path}`: {reason}")]
    InvalidMountPath {
        /// Violating mount path.
        mount_path: String,
        /// Explanation of why the mount path was rejected.
        reason: &'static str,
    },
    /// Container mount path targets a forbidden kernel/runtime prefix.
    #[error("container mountPath `{mount_path}` targets forbidden system prefix `{prefix}`")]
    ForbiddenMountTarget {
        /// Violating mount path.
        mount_path: String,
        /// Matched forbidden prefix.
        prefix: &'static str,
    },
    /// `VolumeMount.subPath` or `subPathExpr` contains path traversal or absolute segments.
    #[error("container volumeMount `{volume_name}` has unsafe subPath `{sub_path}`")]
    SubPathTraversal {
        /// Name of the volume mount.
        volume_name: String,
        /// Violating `subPath` or `subPathExpr`.
        sub_path: String,
    },
}

/// Validates that `mount_path` is a clean, non-root absolute POSIX path that
/// does not contain `.` or `..` segments and does not target [`FORBIDDEN_MOUNT_PREFIXES`].
///
/// # Errors
///
/// Returns [`StorageError::InvalidMountPath`] or [`StorageError::ForbiddenMountTarget`]
/// if validation fails.
pub fn validate_mount_path(mount_path: &str) -> Result<(), StorageError> {
    if !mount_path.starts_with('/') {
        return Err(StorageError::InvalidMountPath {
            mount_path: mount_path.to_owned(),
            reason: "mountPath must be an absolute path starting with `/`",
        });
    }
    if mount_path == "/" {
        return Err(StorageError::InvalidMountPath {
            mount_path: mount_path.to_owned(),
            reason: "mountPath must not be root `/`",
        });
    }
    if mount_path.ends_with('/') {
        return Err(StorageError::InvalidMountPath {
            mount_path: mount_path.to_owned(),
            reason: "mountPath must not have a trailing `/`",
        });
    }
    if mount_path.contains("//") {
        return Err(StorageError::InvalidMountPath {
            mount_path: mount_path.to_owned(),
            reason: "mountPath must not contain empty `//` segments",
        });
    }

    for segment in mount_path.split('/').skip(1) {
        if segment == "." || segment == ".." {
            return Err(StorageError::InvalidMountPath {
                mount_path: mount_path.to_owned(),
                reason: "mountPath must not contain `.` or `..` traversal segments",
            });
        }
    }

    for &prefix in FORBIDDEN_MOUNT_PREFIXES {
        if mount_path == prefix
            || mount_path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
        {
            return Err(StorageError::ForbiddenMountTarget {
                mount_path: mount_path.to_owned(),
                prefix,
            });
        }
    }

    Ok(())
}

/// Synthesizes a bounded Kubernetes `Volume` (`emptyDir` with explicit `sizeLimit`)
/// and matching `VolumeMount` from a [`ScratchVolumeSpec`].
///
/// # Errors
///
/// Returns [`StorageError`] if the volume name, mount path, or `size_limit` is invalid.
pub fn build_scratch_volume_and_mount(
    spec: &ScratchVolumeSpec,
) -> Result<(Volume, VolumeMount), StorageError> {
    validate_dns1123_label(&spec.name)?;
    validate_mount_path(&spec.mount_path)?;
    let size_qty = spec.size_limit.parse::<MemoryQuantity>()?;

    let volume = Volume {
        name: spec.name.clone(),
        empty_dir: Some(EmptyDirVolumeSource {
            medium: spec.medium.as_k8s_medium().map(str::to_owned),
            size_limit: Some(size_qty.to_k8s_quantity()),
        }),
        ..Default::default()
    };

    let mount = VolumeMount {
        name: spec.name.clone(),
        mount_path: spec.mount_path.clone(),
        read_only: Some(false),
        ..Default::default()
    };

    Ok((volume, mount))
}

/// Audits all volumes and container `volumeMounts` in a Kubernetes `PodSpec`
/// (`SPEC-0003`).
///
/// Rejects:
/// - Any `hostPath` volume
/// - Any `emptyDir` volume without a valid positive `sizeLimit`
/// - Any container or init-container `VolumeMount` with an invalid or forbidden `mountPath`
/// - Any `subPath` or `subPathExpr` containing `..` or starting with `/`
///
/// # Errors
///
/// Returns the first [`StorageError`] encountered.
pub fn audit_pod_volumes(pod_spec: &PodSpec) -> Result<(), StorageError> {
    if let Some(volumes) = &pod_spec.volumes {
        for volume in volumes {
            if volume.host_path.is_some() {
                return Err(StorageError::HostPathForbidden {
                    volume_name: volume.name.clone(),
                });
            }
            if let Some(empty_dir) = &volume.empty_dir {
                let Some(size_limit) = &empty_dir.size_limit else {
                    return Err(StorageError::UnboundedEmptyDir {
                        volume_name: volume.name.clone(),
                    });
                };
                if size_limit.0.parse::<MemoryQuantity>().is_err() {
                    return Err(StorageError::UnboundedEmptyDir {
                        volume_name: volume.name.clone(),
                    });
                }
            }
        }
    }

    let all_containers = pod_spec
        .containers
        .iter()
        .chain(pod_spec.init_containers.as_deref().unwrap_or(&[]));

    for container in all_containers {
        if let Some(mounts) = &container.volume_mounts {
            for mount in mounts {
                validate_mount_path(&mount.mount_path)?;
                if let Some(sub_path) = &mount.sub_path {
                    validate_sub_path(&mount.name, sub_path)?;
                }
                if let Some(sub_path_expr) = &mount.sub_path_expr {
                    validate_sub_path(&mount.name, sub_path_expr)?;
                }
            }
        }
    }

    Ok(())
}

fn validate_sub_path(volume_name: &str, sub_path: &str) -> Result<(), StorageError> {
    if sub_path.starts_with('/')
        || sub_path
            .split('/')
            .any(|seg| seg == ".." || seg == "." || seg.is_empty())
    {
        return Err(StorageError::SubPathTraversal {
            volume_name: volume_name.to_owned(),
            sub_path: sub_path.to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use k8s_openapi::api::core::v1::{Container, HostPathVolumeSource};

    use super::*;

    #[test]
    fn default_scratch_volume_is_bounded_and_passes_audit() {
        let spec = ScratchVolumeSpec::default();
        let res = build_scratch_volume_and_mount(&spec);
        assert!(res.is_ok());
        let Ok((vol, mount)) = res else { return };

        let pod_spec = PodSpec {
            volumes: Some(vec![vol]),
            containers: vec![Container {
                name: "agent".to_owned(),
                volume_mounts: Some(vec![mount]),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(audit_pod_volumes(&pod_spec).is_ok());
    }

    #[test]
    fn rejects_host_path_unbounded_empty_dir_and_forbidden_mounts() {
        let host_path_pod = PodSpec {
            volumes: Some(vec![Volume {
                name: "docker-sock".to_owned(),
                host_path: Some(HostPathVolumeSource {
                    path: "/var/run/docker.sock".to_owned(),
                    type_: None,
                }),
                ..Default::default()
            }]),
            containers: vec![],
            ..Default::default()
        };
        assert_eq!(
            audit_pod_volumes(&host_path_pod),
            Err(StorageError::HostPathForbidden {
                volume_name: "docker-sock".to_owned(),
            })
        );

        let unbounded_empty_dir_pod = PodSpec {
            volumes: Some(vec![Volume {
                name: "cache".to_owned(),
                empty_dir: Some(EmptyDirVolumeSource::default()),
                ..Default::default()
            }]),
            containers: vec![],
            ..Default::default()
        };
        assert_eq!(
            audit_pod_volumes(&unbounded_empty_dir_pod),
            Err(StorageError::UnboundedEmptyDir {
                volume_name: "cache".to_owned(),
            })
        );

        assert_eq!(
            validate_mount_path("/var/run/secrets"),
            Err(StorageError::ForbiddenMountTarget {
                mount_path: "/var/run/secrets".to_owned(),
                prefix: "/var/run",
            })
        );
        assert_eq!(
            validate_mount_path("/workspace/../etc"),
            Err(StorageError::InvalidMountPath {
                mount_path: "/workspace/../etc".to_owned(),
                reason: "mountPath must not contain `.` or `..` traversal segments",
            })
        );
    }
}
