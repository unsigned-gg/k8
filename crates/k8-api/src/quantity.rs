// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Kubernetes resource quantity parsing, canonical formatting, and quota admission arithmetic.

use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Errors returned during Kubernetes quantity parsing or quota admission.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum QuantityError {
    /// Quantity string was empty.
    #[error("resource quantity cannot be empty")]
    Empty,

    /// Quantity string had an invalid numeric value or negative sign.
    #[error("invalid resource quantity number in '{0}'")]
    InvalidNumber(String),

    /// Quantity string had an unrecognized unit suffix.
    #[error("unsupported resource quantity suffix in '{0}'")]
    InvalidSuffix(String),

    /// Quantity value was zero where a positive allocation is required.
    #[error("resource quantity must be greater than zero")]
    ZeroQuantity,

    /// Arithmetic overflow when computing resource quantities.
    #[error("arithmetic overflow in resource quantity calculation")]
    Overflow,

    /// Arithmetic underflow when releasing resource quantities.
    #[error("arithmetic underflow when releasing resource quantity")]
    Underflow,

    /// Requested resources exceed the configured namespace quota.
    #[error("quota exceeded for {resource}: requested {requested}, available {available}")]
    QuotaExceeded {
        /// Resource dimension name (`cpu`, `memory`, `gpu`, `pods`).
        resource: &'static str,
        /// Requested amount in canonical units.
        requested: u64,
        /// Remaining available capacity in canonical units.
        available: u64,
    },
}

/// CPU quantity normalized to millicores (`1000m == 1 vCPU`).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Serialize,
    Deserialize,
    JsonSchema,
)]
pub struct CpuQuantity(u64);

impl CpuQuantity {
    /// Construct a `CpuQuantity` directly from millicores.
    #[must_use]
    pub const fn from_millicores(millicores: u64) -> Self {
        Self(millicores)
    }

    /// Construct a `CpuQuantity` from whole cores.
    pub const fn from_cores(cores: u64) -> Result<Self, QuantityError> {
        match cores.checked_mul(1_000) {
            Some(m) => Ok(Self(m)),
            None => Err(QuantityError::Overflow),
        }
    }

    /// Return the value in millicores.
    #[must_use]
    pub const fn millicores(self) -> u64 {
        self.0
    }

    /// Checked addition of two CPU quantities.
    pub const fn checked_add(self, rhs: Self) -> Result<Self, QuantityError> {
        match self.0.checked_add(rhs.0) {
            Some(v) => Ok(Self(v)),
            None => Err(QuantityError::Overflow),
        }
    }

    /// Checked subtraction of two CPU quantities.
    pub const fn checked_sub(self, rhs: Self) -> Result<Self, QuantityError> {
        match self.0.checked_sub(rhs.0) {
            Some(v) => Ok(Self(v)),
            None => Err(QuantityError::Underflow),
        }
    }

    /// Convert to a `k8s_openapi` [`Quantity`].
    #[must_use]
    pub fn to_k8s_quantity(self) -> Quantity {
        Quantity(self.to_string())
    }
}

impl fmt::Display for CpuQuantity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 > 0 && self.0.is_multiple_of(1_000) {
            write!(f, "{}", self.0 / 1_000)
        } else {
            write!(f, "{}m", self.0)
        }
    }
}

impl FromStr for CpuQuantity {
    type Err = QuantityError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let s = raw.trim();
        if s.is_empty() {
            return Err(QuantityError::Empty);
        }
        if s.starts_with('-') {
            return Err(QuantityError::InvalidNumber(raw.to_string()));
        }

        if let Some(milli_str) = s.strip_suffix('m') {
            if milli_str.is_empty() {
                return Err(QuantityError::InvalidNumber(raw.to_string()));
            }
            let millis = milli_str
                .parse::<u64>()
                .map_err(|_| QuantityError::InvalidNumber(raw.to_string()))?;
            if millis == 0 {
                return Err(QuantityError::ZeroQuantity);
            }
            return Ok(Self(millis));
        }

        if let Some((whole_str, frac_str)) = s.split_once('.') {
            if whole_str.is_empty() || frac_str.is_empty() || frac_str.len() > 3 {
                return Err(QuantityError::InvalidNumber(raw.to_string()));
            }
            if !frac_str.chars().all(|c| c.is_ascii_digit()) {
                return Err(QuantityError::InvalidSuffix(raw.to_string()));
            }
            let whole = whole_str
                .parse::<u64>()
                .map_err(|_| QuantityError::InvalidNumber(raw.to_string()))?;
            let frac = frac_str
                .parse::<u64>()
                .map_err(|_| QuantityError::InvalidNumber(raw.to_string()))?;
            let scale = match frac_str.len() {
                1 => 100,
                2 => 10,
                3 => 1,
                _ => return Err(QuantityError::InvalidNumber(raw.to_string())),
            };
            let total = whole
                .checked_mul(1_000)
                .and_then(|w| frac.checked_mul(scale).and_then(|f| w.checked_add(f)))
                .ok_or(QuantityError::Overflow)?;
            if total == 0 {
                return Err(QuantityError::ZeroQuantity);
            }
            return Ok(Self(total));
        }

        if s.chars().any(|c| !c.is_ascii_digit()) {
            return Err(QuantityError::InvalidSuffix(raw.to_string()));
        }
        let cores = s
            .parse::<u64>()
            .map_err(|_| QuantityError::InvalidNumber(raw.to_string()))?;
        if cores == 0 {
            return Err(QuantityError::ZeroQuantity);
        }
        Self::from_cores(cores)
    }
}

/// Memory quantity normalized to exact bytes.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Serialize,
    Deserialize,
    JsonSchema,
)]
pub struct MemoryQuantity(u64);

impl MemoryQuantity {
    /// Construct a `MemoryQuantity` directly from bytes.
    #[must_use]
    pub const fn from_bytes(bytes: u64) -> Self {
        Self(bytes)
    }

    /// Return the value in bytes.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.0
    }

    /// Checked addition of two memory quantities.
    pub const fn checked_add(self, rhs: Self) -> Result<Self, QuantityError> {
        match self.0.checked_add(rhs.0) {
            Some(v) => Ok(Self(v)),
            None => Err(QuantityError::Overflow),
        }
    }

    /// Checked subtraction of two memory quantities.
    pub const fn checked_sub(self, rhs: Self) -> Result<Self, QuantityError> {
        match self.0.checked_sub(rhs.0) {
            Some(v) => Ok(Self(v)),
            None => Err(QuantityError::Underflow),
        }
    }

    /// Convert to a `k8s_openapi` [`Quantity`].
    #[must_use]
    pub fn to_k8s_quantity(self) -> Quantity {
        Quantity(self.to_string())
    }
}

impl fmt::Display for MemoryQuantity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const GI: u64 = 1024 * 1024 * 1024;
        const MI: u64 = 1024 * 1024;
        const KI: u64 = 1024;

        if self.0 > 0 && self.0.is_multiple_of(GI) {
            write!(f, "{}Gi", self.0 / GI)
        } else if self.0 > 0 && self.0.is_multiple_of(MI) {
            write!(f, "{}Mi", self.0 / MI)
        } else if self.0 > 0 && self.0.is_multiple_of(KI) {
            write!(f, "{}Ki", self.0 / KI)
        } else {
            write!(f, "{}", self.0)
        }
    }
}

impl FromStr for MemoryQuantity {
    type Err = QuantityError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let s = raw.trim();
        if s.is_empty() {
            return Err(QuantityError::Empty);
        }
        if s.starts_with('-') {
            return Err(QuantityError::InvalidNumber(raw.to_string()));
        }

        let (num_str, multiplier): (&str, u64) = if let Some(n) = s.strip_suffix("Ei") {
            (n, 1_u64 << 60)
        } else if let Some(n) = s.strip_suffix("Pi") {
            (n, 1_u64 << 50)
        } else if let Some(n) = s.strip_suffix("Ti") {
            (n, 1_u64 << 40)
        } else if let Some(n) = s.strip_suffix("Gi") {
            (n, 1_u64 << 30)
        } else if let Some(n) = s.strip_suffix("Mi") {
            (n, 1_u64 << 20)
        } else if let Some(n) = s.strip_suffix("Ki") {
            (n, 1_u64 << 10)
        } else if let Some(n) = s.strip_suffix('E') {
            (n, 1_000_000_000_000_000_000)
        } else if let Some(n) = s.strip_suffix('P') {
            (n, 1_000_000_000_000_000)
        } else if let Some(n) = s.strip_suffix('T') {
            (n, 1_000_000_000_000)
        } else if let Some(n) = s.strip_suffix('G') {
            (n, 1_000_000_000)
        } else if let Some(n) = s.strip_suffix('M') {
            (n, 1_000_000)
        } else if let Some(n) = s.strip_suffix('k').or_else(|| s.strip_suffix('K')) {
            (n, 1_000)
        } else {
            if s.chars().any(|c| !c.is_ascii_digit()) {
                return Err(QuantityError::InvalidSuffix(raw.to_string()));
            }
            (s, 1)
        };

        if num_str.is_empty() || num_str.chars().any(|c| !c.is_ascii_digit()) {
            return Err(QuantityError::InvalidNumber(raw.to_string()));
        }

        let base = num_str
            .parse::<u64>()
            .map_err(|_| QuantityError::InvalidNumber(raw.to_string()))?;
        if base == 0 {
            return Err(QuantityError::ZeroQuantity);
        }
        let bytes = base
            .checked_mul(multiplier)
            .ok_or(QuantityError::Overflow)?;
        Ok(Self(bytes))
    }
}

/// Validated resource request for a single workload pod.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct ResourceRequest {
    /// Requested CPU in millicores.
    pub cpu: CpuQuantity,
    /// Requested memory in bytes.
    pub memory: MemoryQuantity,
    /// Requested GPU count.
    pub gpu: u32,
}

/// Current cumulative resource usage across a namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct ResourceUsage {
    /// Allocated CPU in millicores.
    pub cpu: CpuQuantity,
    /// Allocated memory in bytes.
    pub memory: MemoryQuantity,
    /// Allocated GPU count.
    pub gpu: u32,
    /// Active pod count.
    pub pods: u32,
}

/// Deterministic namespace resource quota specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResourceQuotaSpec {
    /// Maximum cumulative CPU across all active pods.
    pub max_cpu: CpuQuantity,
    /// Maximum cumulative memory across all active pods.
    pub max_memory: MemoryQuantity,
    /// Maximum cumulative GPUs across all active pods.
    pub max_gpu: u32,
    /// Maximum active pods.
    pub max_pods: u32,
}

impl ResourceQuotaSpec {
    /// Admit a workload [`ResourceRequest`] against `current` usage, returning updated usage.
    pub fn admit(
        &self,
        current: &ResourceUsage,
        request: &ResourceRequest,
    ) -> Result<ResourceUsage, QuantityError> {
        let next_pods = current.pods.checked_add(1).ok_or(QuantityError::Overflow)?;
        if next_pods > self.max_pods {
            return Err(QuantityError::QuotaExceeded {
                resource: "pods",
                requested: 1,
                available: u64::from(self.max_pods.saturating_sub(current.pods)),
            });
        }

        let next_cpu = current.cpu.checked_add(request.cpu)?;
        if next_cpu > self.max_cpu {
            return Err(QuantityError::QuotaExceeded {
                resource: "cpu",
                requested: request.cpu.millicores(),
                available: self
                    .max_cpu
                    .millicores()
                    .saturating_sub(current.cpu.millicores()),
            });
        }

        let next_memory = current.memory.checked_add(request.memory)?;
        if next_memory > self.max_memory {
            return Err(QuantityError::QuotaExceeded {
                resource: "memory",
                requested: request.memory.bytes(),
                available: self
                    .max_memory
                    .bytes()
                    .saturating_sub(current.memory.bytes()),
            });
        }

        let next_gpu = current
            .gpu
            .checked_add(request.gpu)
            .ok_or(QuantityError::Overflow)?;
        if next_gpu > self.max_gpu {
            return Err(QuantityError::QuotaExceeded {
                resource: "gpu",
                requested: u64::from(request.gpu),
                available: u64::from(self.max_gpu.saturating_sub(current.gpu)),
            });
        }

        Ok(ResourceUsage {
            cpu: next_cpu,
            memory: next_memory,
            gpu: next_gpu,
            pods: next_pods,
        })
    }

    /// Release a previously admitted [`ResourceRequest`] from `current` usage.
    pub fn release(
        &self,
        current: &ResourceUsage,
        request: &ResourceRequest,
    ) -> Result<ResourceUsage, QuantityError> {
        let next_pods = current
            .pods
            .checked_sub(1)
            .ok_or(QuantityError::Underflow)?;
        let next_cpu = current.cpu.checked_sub(request.cpu)?;
        let next_memory = current.memory.checked_sub(request.memory)?;
        let next_gpu = current
            .gpu
            .checked_sub(request.gpu)
            .ok_or(QuantityError::Underflow)?;

        Ok(ResourceUsage {
            cpu: next_cpu,
            memory: next_memory,
            gpu: next_gpu,
            pods: next_pods,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_quantity_parsing_and_display() {
        let q1: CpuQuantity = "500m".parse().expect("500m");
        assert_eq!(q1.millicores(), 500);
        assert_eq!(q1.to_string(), "500m");

        let q2: CpuQuantity = "2".parse().expect("2 cores");
        assert_eq!(q2.millicores(), 2_000);
        assert_eq!(q2.to_string(), "2");

        let q3: CpuQuantity = "1.5".parse().expect("1.5 cores");
        assert_eq!(q3.millicores(), 1_500);
        assert_eq!(q3.to_string(), "1500m");

        assert!("0m".parse::<CpuQuantity>().is_err());
        assert!("-100m".parse::<CpuQuantity>().is_err());
        assert!("200x".parse::<CpuQuantity>().is_err());
    }

    #[test]
    fn test_memory_quantity_parsing_and_display() {
        let m1: MemoryQuantity = "4Gi".parse().expect("4Gi");
        assert_eq!(m1.bytes(), 4 * 1024 * 1024 * 1024);
        assert_eq!(m1.to_string(), "4Gi");

        let m2: MemoryQuantity = "512Mi".parse().expect("512Mi");
        assert_eq!(m2.bytes(), 512 * 1024 * 1024);
        assert_eq!(m2.to_string(), "512Mi");

        let m3: MemoryQuantity = "1000M".parse().expect("1000M");
        assert_eq!(m3.bytes(), 1_000_000_000);

        assert!("0Gi".parse::<MemoryQuantity>().is_err());
        assert!("16Zi".parse::<MemoryQuantity>().is_err());
    }

    #[test]
    fn test_quota_admission_and_release() {
        let quota = ResourceQuotaSpec {
            max_cpu: CpuQuantity::from_millicores(4_000),
            max_memory: MemoryQuantity::from_bytes(8 * 1024 * 1024 * 1024),
            max_gpu: 2,
            max_pods: 4,
        };
        let req = ResourceRequest {
            cpu: CpuQuantity::from_millicores(2_000),
            memory: MemoryQuantity::from_bytes(4 * 1024 * 1024 * 1024),
            gpu: 1,
        };
        let usage0 = ResourceUsage::default();
        let usage1 = quota.admit(&usage0, &req).expect("first admit");
        let usage2 = quota.admit(&usage1, &req).expect("second admit");
        assert_eq!(usage2.pods, 2);
        assert_eq!(usage2.gpu, 2);

        // Third admit exceeds CPU, memory, and GPU quota
        assert!(quota.admit(&usage2, &req).is_err());

        let released = quota.release(&usage2, &req).expect("release");
        assert_eq!(released, usage1);
    }
}
