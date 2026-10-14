// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `k8` CLI entrypoint.

use clap::{Parser, Subcommand};
use k8_api::{
    audit_job_immutable_drift, audit_network_policy_zero_trust,
    audit_pod_priority_and_grace_period, audit_pod_probes, audit_pod_secret_and_token_hygiene,
    audit_pod_spec_restricted, audit_pod_volumes, audit_pvc_mutation, audit_role_least_privilege,
    audit_service_account_zero_trust, audit_statefulset_immutable_drift, build_controller_lease,
    build_immutable_config_map, evaluate_cluster_invariants, evaluate_lease_transition,
    evaluate_node_drain, evaluate_rollout_quorum, evaluate_workload_admission,
    from_multi_yaml_manifests, from_yaml_manifest, to_yaml_manifest, AdmissionContext,
    AgentWorkload, AgentWorkloadSpec, ClusterInvariantReport, ClusterInventorySnapshot,
    CpuQuantity, DrainClusterContext, DrainPlanReport, DriftRemediationStrategy, EgressRuleSpec,
    ImmutableDriftReport, IsolationProfile, MemoryQuantity, NamespaceQuotaSpec, QuotaUsageSnapshot,
    RolloutQuorumReport, RolloutQuorumSpec, ScratchMedium, ScratchVolumeSpec, WorkloadPriorityTier,
    DEFAULT_LEASE_DURATION_SECONDS, MAX_TERMINATION_GRACE_SECONDS,
};
use k8_core::{K8Client, K8Error, Result};
use k8_orchestrator::Orchestrator;
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Pod, ServiceAccount};
use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::api::rbac::v1::Role;
use kube::api::{Api, ListParams};
use std::collections::BTreeMap;
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(name = "k8")]
#[command(author = "unsigned.gg <engineering@unsigned.gg>")]
#[command(version = "0.1.0")]
#[command(
    about = "Kubernetes agent orchestrator and native CLI tooling for autonomous agent fleets",
    long_about = None
)]
struct Cli {
    /// Kubernetes namespace override
    #[arg(short, long, env = "K8S_NAMESPACE")]
    namespace: Option<String>,

    /// Disable ANSI colors in log and table output
    #[arg(long, global = true)]
    plain: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Inspect cluster health, connected namespace, and agent node status
    Status,

    /// Render the AgentWorkload CustomResourceDefinition (CRD) YAML 1.2 manifest
    Crd,

    /// Audit a single or multi-document YAML 1.2 manifest against PodSecurity `restricted`, RBAC, volume, priority, secret, probe, and network invariants
    Audit {
        /// Path to the YAML 1.2 manifest file
        #[arg(short, long)]
        file: PathBuf,
    },

    /// Evaluate the pure multi-gate ValidatingAdmissionPolicy engine against an AgentWorkload manifest
    Admit {
        /// Path to the AgentWorkload YAML 1.2 manifest file
        #[arg(short, long)]
        file: PathBuf,

        /// Namespace CPU quota ceiling (e.g. 16000m or 16)
        #[arg(long, default_value = "16000m")]
        max_cpu: String,

        /// Namespace memory quota ceiling (e.g. 32Gi)
        #[arg(long, default_value = "32Gi")]
        max_memory: String,

        /// Namespace active pod ceiling
        #[arg(long, default_value_t = 16)]
        max_pods: u32,
    },

    /// Audit a ClusterInventorySnapshot YAML 1.2 file against node identity, Kata overhead, and Service endpoint invariants
    Invariants {
        /// Path to the ClusterInventorySnapshot YAML 1.2 file
        #[arg(short, long)]
        file: PathBuf,
    },

    /// Evaluate a deterministic node cordon & drain plan (`SPEC-0005`) against PDB budgets and destination Kata capacity
    DrainPlan {
        /// Path to the DrainClusterContext YAML 1.2 file
        #[arg(short, long)]
        file: PathBuf,
    },

    /// Detect immutable Kubernetes field drift (`StatefulSet`, `Job`, `PersistentVolumeClaim`) and classify remediation (`SPEC-0005`)
    Drift {
        /// Path to the live cluster resource YAML 1.2 file
        #[arg(long)]
        live: PathBuf,

        /// Path to the desired GitOps resource YAML 1.2 file
        #[arg(long)]
        desired: PathBuf,
    },

    /// Render a content-addressed immutable v1/ConfigMap YAML 1.2 manifest (`SPEC-0006`)
    ConfigMap {
        /// Base name prefix (DNS-1123 label, suffixed with -<hash8>)
        #[arg(long)]
        name: String,

        /// Key-value entries in KEY=VALUE format (repeatable)
        #[arg(long = "from-literal", num_args = 1..)]
        literals: Vec<String>,
    },

    /// Verify Deployment RollingUpdate surge/unavailable bounds against PDB minAvailable quorum (`SPEC-0006`)
    RolloutCheck {
        /// Path to the RolloutQuorumSpec YAML 1.2 file
        #[arg(short, long)]
        file: PathBuf,
    },

    /// Render a coordination.k8s.io/v1 leader-election Lease YAML 1.2 manifest
    Lease {
        /// Lease metadata.name (DNS-1123 label)
        #[arg(long, default_value = "k8-orchestrator-leader")]
        name: String,

        /// Candidate leader holder identity (DNS-1123 label)
        #[arg(long, default_value = "k8-orchestrator-0")]
        holder: String,

        /// Lease duration in seconds (1..=3600)
        #[arg(long, default_value_t = DEFAULT_LEASE_DURATION_SECONDS)]
        duration_secs: u32,
    },

    /// Dispatch a one-shot autonomous agent container Job
    Run {
        /// Container image to launch
        image: String,

        /// Command override
        #[arg(short, long, num_args = 1..)]
        command: Vec<String>,

        /// Arguments passed to the command
        #[arg(short, long, num_args = 1..)]
        args: Vec<String>,

        /// GPU count requested
        #[arg(short, long)]
        gpu: Option<u32>,

        /// CPU request/limit (e.g. 2000m or 2)
        #[arg(long)]
        cpu: Option<String>,

        /// Memory request/limit (e.g. 4Gi)
        #[arg(short, long)]
        memory: Option<String>,

        /// Job deadline in seconds
        #[arg(short, long)]
        timeout: Option<u64>,

        /// Agent persona or role label
        #[arg(short, long)]
        role: Option<String>,

        /// Schedule inside a Kata Containers hardware-virtualized microVM (`runtimeClassName: kata`)
        #[arg(long)]
        kata: bool,

        /// Allowed outbound CIDR block for zero-trust egress (repeatable, non-wildcard)
        #[arg(long = "allow-cidr")]
        allow_cidrs: Vec<String>,

        /// Allowed outbound TCP port for zero-trust egress (repeatable)
        #[arg(long = "allow-port")]
        allow_ports: Vec<u16>,

        /// Attach a bounded tmpfs `/tmp` scratch volume with the specified size limit (e.g. 64Mi)
        #[arg(long = "scratch-tmp")]
        scratch_tmp: Option<String>,

        /// Render the full YAML 1.2 bundle (ServiceAccount + NetworkPolicy + PodDisruptionBudget + Job) in dry-run mode
        #[arg(long)]
        bundle: bool,

        /// Render the validated Kubernetes YAML manifest without contacting the cluster
        #[arg(long)]
        dry_run: bool,
    },

    /// List active agent workloads and Jobs
    List,

    /// Terminate and cleanup an agent Job
    Stop {
        /// Job run ID to terminate
        run_id: String,
    },

    /// Start the autonomous background orchestrator daemon loop
    Daemon,
}

fn should_disable_ansi(plain_flag: bool) -> bool {
    plain_flag
        || std::env::var_os("NO_COLOR").is_some()
        || std::env::var("TERM").is_ok_and(|t| t == "dumb")
}

fn audit_yaml_stream(raw_yaml: &str) -> Result<usize> {
    let docs: Vec<serde_json::Value> = from_multi_yaml_manifests(raw_yaml)?;
    for doc in &docs {
        let kind = doc
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("Unknown");
        match kind {
            "AgentWorkload" => {
                let wl: AgentWorkload = serde_json::from_value(doc.clone())
                    .map_err(|e| K8Error::Config(format!("invalid AgentWorkload document: {e}")))?;
                wl.spec.validate()?;
            }
            "Job" => {
                let job: Job = serde_json::from_value(doc.clone())
                    .map_err(|e| K8Error::Config(format!("invalid Job document: {e}")))?;
                let pod_spec = job
                    .spec
                    .as_ref()
                    .and_then(|s| s.template.spec.as_ref())
                    .ok_or_else(|| K8Error::Config("Job missing spec.template.spec".into()))?;
                audit_pod_spec_restricted(pod_spec).map_err(K8Error::SecurityAudit)?;
                audit_pod_volumes(pod_spec).map_err(|e| {
                    K8Error::Config(format!("Job volume security audit failed: {e}"))
                })?;
                audit_pod_priority_and_grace_period(pod_spec, MAX_TERMINATION_GRACE_SECONDS)
                    .map_err(|e| {
                        K8Error::Config(format!(
                            "Job priority/grace-period security audit failed: {e}"
                        ))
                    })?;
                audit_pod_secret_and_token_hygiene(pod_spec).map_err(|e| {
                    K8Error::Config(format!("Job secret/token hygiene audit failed: {e}"))
                })?;
                audit_pod_probes(pod_spec)
                    .map_err(|e| K8Error::Config(format!("Job probe timing audit failed: {e}")))?;
            }
            "Pod" => {
                let pod: Pod = serde_json::from_value(doc.clone())
                    .map_err(|e| K8Error::Config(format!("invalid Pod document: {e}")))?;
                let pod_spec = pod
                    .spec
                    .as_ref()
                    .ok_or_else(|| K8Error::Config("Pod missing spec".into()))?;
                audit_pod_spec_restricted(pod_spec).map_err(K8Error::SecurityAudit)?;
                audit_pod_volumes(pod_spec).map_err(|e| {
                    K8Error::Config(format!("Pod volume security audit failed: {e}"))
                })?;
                audit_pod_priority_and_grace_period(pod_spec, MAX_TERMINATION_GRACE_SECONDS)
                    .map_err(|e| {
                        K8Error::Config(format!(
                            "Pod priority/grace-period security audit failed: {e}"
                        ))
                    })?;
                audit_pod_secret_and_token_hygiene(pod_spec).map_err(|e| {
                    K8Error::Config(format!("Pod secret/token hygiene audit failed: {e}"))
                })?;
                audit_pod_probes(pod_spec)
                    .map_err(|e| K8Error::Config(format!("Pod probe timing audit failed: {e}")))?;
            }
            "ServiceAccount" => {
                let sa: ServiceAccount = serde_json::from_value(doc.clone()).map_err(|e| {
                    K8Error::Config(format!("invalid ServiceAccount document: {e}"))
                })?;
                audit_service_account_zero_trust(&sa).map_err(|e| {
                    K8Error::Config(format!("ServiceAccount zero-trust audit failed: {e}"))
                })?;
            }
            "Role" => {
                let role: Role = serde_json::from_value(doc.clone())
                    .map_err(|e| K8Error::Config(format!("invalid Role document: {e}")))?;
                audit_role_least_privilege(&role).map_err(|e| {
                    K8Error::Config(format!("Role least-privilege audit failed: {e}"))
                })?;
            }
            "NetworkPolicy" => {
                let np: NetworkPolicy = serde_json::from_value(doc.clone())
                    .map_err(|e| K8Error::Config(format!("invalid NetworkPolicy document: {e}")))?;
                if let Err(violations) = audit_network_policy_zero_trust(&np) {
                    return Err(K8Error::Config(format!(
                        "NetworkPolicy zero-trust audit failed: {}",
                        violations.join("; ")
                    )));
                }
            }
            _ => {}
        }
    }
    Ok(docs.len())
}

fn admit_yaml_stream(
    raw_yaml: &str,
    namespace: &str,
    max_cpu: &str,
    max_memory: &str,
    max_pods: u32,
) -> Result<Vec<String>> {
    let cpu_qty = max_cpu
        .parse::<CpuQuantity>()
        .map_err(k8_api::SpecValidationError::from)?;
    let mem_qty = max_memory
        .parse::<MemoryQuantity>()
        .map_err(k8_api::SpecValidationError::from)?;
    let ctx = AdmissionContext {
        quota: Some((
            NamespaceQuotaSpec {
                max_cpu_millis: cpu_qty.millicores(),
                max_memory_bytes: mem_qty.bytes(),
                max_pods,
                warn_threshold_permille: k8_api::DEFAULT_QUOTA_WARN_PERMILLE,
            },
            QuotaUsageSnapshot::default(),
        )),
        required_receipt: None,
    };

    let workloads: Vec<AgentWorkload> = from_multi_yaml_manifests(raw_yaml)?;
    let mut digests = Vec::with_capacity(workloads.len());
    for wl in &workloads {
        let mut evaluated = wl.clone();
        if evaluated.metadata.namespace.is_none() {
            evaluated.metadata.namespace = Some(namespace.to_string());
        }
        let outcome = evaluate_workload_admission(&evaluated, &ctx);
        if !outcome.allowed {
            let formatted = outcome
                .violations
                .iter()
                .map(|v| format!("[{:?}:{}] {}", v.gate, v.code, v.message))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(K8Error::Config(format!(
                "Admission denied for {} (digest={}): {formatted}",
                outcome.workload_name, outcome.decision_digest
            )));
        }
        digests.push(outcome.decision_digest);
    }
    Ok(digests)
}

fn audit_cluster_invariants_yaml(raw_yaml: &str) -> Result<ClusterInvariantReport> {
    let snapshot: ClusterInventorySnapshot = from_yaml_manifest(raw_yaml)?;
    let report = evaluate_cluster_invariants(&snapshot);
    if !report.healthy {
        let errors = report
            .findings
            .iter()
            .map(|f| {
                format!(
                    "[{:?}:{:?}] {}: {}",
                    f.severity, f.category, f.resource, f.message
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(K8Error::Config(format!(
            "Cluster invariant audit failed (digest={}, errors={}, warnings={}): {errors}",
            report.report_digest, report.error_count, report.warning_count
        )));
    }
    Ok(report)
}

fn evaluate_drain_plan_yaml(raw_yaml: &str) -> Result<DrainPlanReport> {
    let ctx: DrainClusterContext = from_yaml_manifest(raw_yaml)?;
    let report = evaluate_node_drain(&ctx);
    if !report.safe_to_drain {
        let blockers = report
            .pod_decisions
            .iter()
            .filter_map(|d| {
                if let k8_api::PodEvictionAction::Blocked { reason } = &d.action {
                    Some(format!("{}/{}: {:?}", d.namespace, d.pod_name, reason))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(K8Error::Config(format!(
            "Node drain blocked for `{}` (digest={}, blocked={}): {blockers}",
            report.target_node, report.plan_digest, report.blocked_count
        )));
    }
    Ok(report)
}

fn evaluate_drift_yaml(live_yaml: &str, desired_yaml: &str) -> Result<ImmutableDriftReport> {
    let live_doc: serde_json::Value = from_yaml_manifest(live_yaml)?;
    let desired_doc: serde_json::Value = from_yaml_manifest(desired_yaml)?;
    let live_kind = live_doc
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("Unknown");
    let desired_kind = desired_doc
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("Unknown");
    if live_kind != desired_kind {
        return Err(K8Error::Config(format!(
            "resource kind mismatch between live (`{live_kind}`) and desired (`{desired_kind}`)"
        )));
    }

    let report = match live_kind {
        "StatefulSet" => {
            let live_sts: StatefulSet = serde_json::from_value(live_doc)
                .map_err(|e| K8Error::Config(format!("invalid live StatefulSet: {e}")))?;
            let desired_sts: StatefulSet = serde_json::from_value(desired_doc)
                .map_err(|e| K8Error::Config(format!("invalid desired StatefulSet: {e}")))?;
            audit_statefulset_immutable_drift(&live_sts, &desired_sts)
        }
        "Job" => {
            let live_job: Job = serde_json::from_value(live_doc)
                .map_err(|e| K8Error::Config(format!("invalid live Job: {e}")))?;
            let desired_job: Job = serde_json::from_value(desired_doc)
                .map_err(|e| K8Error::Config(format!("invalid desired Job: {e}")))?;
            audit_job_immutable_drift(&live_job, &desired_job)
        }
        "PersistentVolumeClaim" => {
            let live_pvc: PersistentVolumeClaim = serde_json::from_value(live_doc)
                .map_err(|e| K8Error::Config(format!("invalid live PVC: {e}")))?;
            let desired_pvc: PersistentVolumeClaim = serde_json::from_value(desired_doc)
                .map_err(|e| K8Error::Config(format!("invalid desired PVC: {e}")))?;
            audit_pvc_mutation(&live_pvc, &desired_pvc)
        }
        other => {
            return Err(K8Error::Config(format!(
                "unsupported resource kind `{other}` for immutable drift audit (expected StatefulSet, Job, or PersistentVolumeClaim)"
            )));
        }
    };

    if report.strategy == DriftRemediationStrategy::RejectedForbiddenMutation {
        let reasons = report
            .findings
            .iter()
            .map(|f| format!("{f:?}"))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(K8Error::Config(format!(
            "Forbidden immutable field mutation on `{}` (digest={}): {reasons}",
            report.resource_id, report.report_digest
        )));
    }

    Ok(report)
}

fn render_immutable_configmap_yaml(
    base_name: &str,
    namespace: &str,
    literals: &[String],
) -> Result<String> {
    let mut data = BTreeMap::new();
    for entry in literals {
        let Some((k, v)) = entry.split_once('=') else {
            return Err(K8Error::Config(format!(
                "invalid --from-literal `{entry}` (expected KEY=VALUE)"
            )));
        };
        data.insert(k.to_string(), v.to_string());
    }
    let cm = build_immutable_config_map(base_name, namespace, &data)
        .map_err(|e| K8Error::Config(format!("failed to build immutable ConfigMap: {e}")))?;
    Ok(to_yaml_manifest(&cm)?)
}

fn evaluate_rollout_check_yaml(raw_yaml: &str) -> Result<RolloutQuorumReport> {
    let spec: RolloutQuorumSpec = from_yaml_manifest(raw_yaml)?;
    evaluate_rollout_quorum(&spec)
        .map_err(|e| K8Error::Config(format!("rollout quorum audit failed: {e}")))
}

fn render_lease_yaml(
    name: &str,
    namespace: &str,
    holder: &str,
    duration_secs: u32,
) -> Result<String> {
    let outcome = evaluate_lease_transition(name, namespace, None, holder, 0, duration_secs)
        .map_err(|e| K8Error::Config(format!("invalid Lease specification: {e}")))?;
    let lease = build_controller_lease(&outcome.next_state)
        .map_err(|e| K8Error::Config(format!("failed to synthesize Lease manifest: {e}")))?;
    let yaml = to_yaml_manifest(&lease)?;
    Ok(yaml)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let disable_ansi = should_disable_ansi(cli.plain);

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "k8=info".into()),
        )
        .with(tracing_subscriber::fmt::layer().with_ansi(!disable_ansi))
        .init();

    match cli.command {
        Commands::Crd => {
            let yaml = AgentWorkload::crd_yaml()?;
            print!("{yaml}");
            return Ok(());
        }

        Commands::Audit { file } => {
            let raw = std::fs::read_to_string(&file).map_err(|e| {
                K8Error::Config(format!("failed to read manifest {}: {e}", file.display()))
            })?;
            let count = audit_yaml_stream(&raw)?;
            println!(
                "Verified {count} YAML 1.2 document(s) in {} against PodSecurity restricted, RBAC, volume, priority, secret, probe, and zero-trust invariants",
                file.display()
            );
            return Ok(());
        }

        Commands::Admit {
            file,
            max_cpu,
            max_memory,
            max_pods,
        } => {
            let raw = std::fs::read_to_string(&file).map_err(|e| {
                K8Error::Config(format!("failed to read manifest {}: {e}", file.display()))
            })?;
            let ns = cli.namespace.as_deref().unwrap_or("default");
            let digests = admit_yaml_stream(&raw, ns, &max_cpu, &max_memory, max_pods)?;
            println!(
                "Admitted {} AgentWorkload(s) in {} [digests: {}]",
                digests.len(),
                file.display(),
                digests.join(", ")
            );
            return Ok(());
        }

        Commands::Invariants { file } => {
            let raw = std::fs::read_to_string(&file).map_err(|e| {
                K8Error::Config(format!(
                    "failed to read cluster snapshot {}: {e}",
                    file.display()
                ))
            })?;
            let report = audit_cluster_invariants_yaml(&raw)?;
            println!(
                "Cluster invariants healthy in {} [nodes={}, warnings={}, digest={}]",
                file.display(),
                report.node_summaries.len(),
                report.warning_count,
                report.report_digest
            );
            return Ok(());
        }

        Commands::DrainPlan { file } => {
            let raw = std::fs::read_to_string(&file).map_err(|e| {
                K8Error::Config(format!(
                    "failed to read drain context {}: {e}",
                    file.display()
                ))
            })?;
            let report = evaluate_drain_plan_yaml(&raw)?;
            println!(
                "Node drain plan safe for `{}` [evicted={}, skipped={}, digest={}]",
                report.target_node, report.evicted_count, report.skipped_count, report.plan_digest
            );
            return Ok(());
        }

        Commands::Drift { live, desired } => {
            let live_raw = std::fs::read_to_string(&live).map_err(|e| {
                K8Error::Config(format!(
                    "failed to read live manifest {}: {e}",
                    live.display()
                ))
            })?;
            let desired_raw = std::fs::read_to_string(&desired).map_err(|e| {
                K8Error::Config(format!(
                    "failed to read desired manifest {}: {e}",
                    desired.display()
                ))
            })?;
            let report = evaluate_drift_yaml(&live_raw, &desired_raw)?;
            println!(
                "Immutable drift check for `{}`: strategy={:?}, findings={}, digest={}",
                report.resource_id,
                report.strategy,
                report.findings.len(),
                report.report_digest
            );
            return Ok(());
        }

        Commands::ConfigMap { name, literals } => {
            let ns = cli.namespace.as_deref().unwrap_or("default");
            let yaml = render_immutable_configmap_yaml(&name, ns, &literals)?;
            print!("{yaml}");
            return Ok(());
        }

        Commands::RolloutCheck { file } => {
            let raw = std::fs::read_to_string(&file).map_err(|e| {
                K8Error::Config(format!(
                    "failed to read rollout quorum spec {}: {e}",
                    file.display()
                ))
            })?;
            let report = evaluate_rollout_check_yaml(&raw)?;
            println!(
                "Rollout quorum safe in {} [min_ready={}, peak={}, pdb_min={}]",
                file.display(),
                report.min_ready_during_rollout,
                report.max_total_pods_during_rollout,
                report.pdb_min_available
            );
            return Ok(());
        }

        Commands::Lease {
            name,
            holder,
            duration_secs,
        } => {
            let ns = cli.namespace.as_deref().unwrap_or("default");
            let yaml = render_lease_yaml(&name, ns, &holder, duration_secs)?;
            print!("{yaml}");
            return Ok(());
        }

        Commands::Run {
            image,
            command,
            args,
            gpu,
            cpu,
            memory,
            timeout,
            role,
            kata,
            allow_cidrs,
            allow_ports,
            scratch_tmp,
            bundle,
            dry_run,
        } => {
            let egress = if allow_cidrs.is_empty() && allow_ports.is_empty() {
                None
            } else {
                Some(EgressRuleSpec {
                    allow_dns: true,
                    allowed_cidrs: allow_cidrs,
                    allowed_tcp_ports: allow_ports,
                })
            };

            let scratch_volumes = match scratch_tmp {
                Some(limit) => vec![ScratchVolumeSpec {
                    name: "scratch-tmp".to_string(),
                    mount_path: "/tmp".to_string(),
                    size_limit: limit,
                    medium: ScratchMedium::Memory,
                }],
                None => Vec::new(),
            };

            let spec = AgentWorkloadSpec {
                image,
                command,
                args,
                env: BTreeMap::new(),
                cpu,
                memory,
                gpu,
                timeout_seconds: timeout,
                agent_role: role,
                isolation_profile: if kata {
                    IsolationProfile::KataMicroVm
                } else {
                    IsolationProfile::StandardRestricted
                },
                priority_tier: WorkloadPriorityTier::InteractiveAgent,
                termination_grace_period_seconds: None,
                egress,
                scratch_volumes,
                rbac_rules: Vec::new(),
            };

            if dry_run {
                let ns = cli.namespace.as_deref().unwrap_or("default");
                let yaml = if bundle {
                    Orchestrator::render_workload_bundle_yaml("agent-dryrun", ns, &spec)?
                } else {
                    Orchestrator::render_job_yaml("agent-dryrun", ns, &spec)?
                };
                print!("{yaml}");
                return Ok(());
            }

            let mut client = K8Client::default_client().await?;
            if let Some(ns) = cli.namespace {
                client = client.with_namespace(ns);
            }
            let orch = Orchestrator::new(client);
            let run_id = orch.dispatch(spec).await?;
            println!("Dispatched agent Job: {run_id}");
            return Ok(());
        }

        other => {
            let mut client = K8Client::default_client().await?;
            if let Some(ns) = cli.namespace {
                client = client.with_namespace(ns);
            }

            match other {
                Commands::Status => {
                    println!("k8 Kubernetes Orchestrator v0.1.0");
                    println!("Connected namespace: {}", client.namespace());
                    let pods: Api<Pod> =
                        Api::namespaced(client.inner().clone(), client.namespace());
                    let lp = ListParams::default().labels("app.kubernetes.io/managed-by=k8");
                    let pod_list = pods.list(&lp).await?;
                    println!("Active agent pods: {}", pod_list.items.len());
                }

                Commands::List => {
                    let jobs: Api<Job> =
                        Api::namespaced(client.inner().clone(), client.namespace());
                    let lp = ListParams::default().labels("app.kubernetes.io/managed-by=k8");
                    let job_list = jobs.list(&lp).await?;
                    println!("{:<24} {:<15} {:<10}", "RUN ID", "STATUS", "COMPLETIONS");
                    println!("{:-<52}", "");
                    for job in job_list.items {
                        let phase = Orchestrator::evaluate_job_phase(&job);
                        let name = job.metadata.name.unwrap_or_default();
                        println!("{name:<24} {phase:?}");
                    }
                }

                Commands::Stop { run_id } => {
                    let orch = Orchestrator::new(client);
                    orch.terminate(&run_id).await?;
                    println!("Terminated agent Job: {run_id}");
                }

                Commands::Daemon => {
                    println!(
                        "Starting k8 agent orchestrator daemon in namespace: {}",
                        client.namespace()
                    );
                    println!("Listening for autonomous agent workload CRDs and job signals...");
                    tokio::signal::ctrl_c().await.map_err(|e| {
                        K8Error::Config(format!("failed to listen for shutdown signal: {e}"))
                    })?;
                    println!("Received shutdown signal. Exiting k8 daemon.");
                }

                Commands::Crd
                | Commands::Audit { .. }
                | Commands::Admit { .. }
                | Commands::Invariants { .. }
                | Commands::DrainPlan { .. }
                | Commands::Drift { .. }
                | Commands::ConfigMap { .. }
                | Commands::RolloutCheck { .. }
                | Commands::Lease { .. }
                | Commands::Run { .. } => {}
            }
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use k8_api::{
        DrainCandidatePod, K8sNodeSnapshot, PdbBudgetSnapshot, ProviderNodeRecord,
        ScheduledPodFootprint, ScopedRuleSpec, ServiceEndpointSnapshot,
    };
    use k8s_openapi::api::apps::v1::StatefulSetSpec;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    #[test]
    fn test_audit_yaml_stream_accepts_hardened_bundle_with_rbac_and_scratch() {
        let spec = AgentWorkloadSpec {
            image: "ghcr.io/unsigned-gg/agent:latest".to_string(),
            isolation_profile: IsolationProfile::KataMicroVm,
            egress: Some(EgressRuleSpec {
                allow_dns: true,
                allowed_cidrs: vec!["10.42.0.0/16".to_string()],
                allowed_tcp_ports: vec![443],
            }),
            scratch_volumes: vec![ScratchVolumeSpec::default()],
            rbac_rules: vec![ScopedRuleSpec {
                api_group: String::new(),
                resource: "configmaps".to_string(),
                resource_names: vec!["agent-cfg".to_string()],
                verbs: vec!["get".to_string()],
            }],
            ..Default::default()
        };
        let bundle = Orchestrator::render_workload_bundle_yaml("agent-bundle1", "default", &spec)
            .expect("render bundle");
        let count = audit_yaml_stream(&bundle).expect("audit bundle");
        assert_eq!(count, 6);
    }

    #[test]
    fn test_admit_yaml_stream_evaluates_multi_gate_engine() {
        let wl = AgentWorkload {
            metadata: ObjectMeta {
                name: Some("agent-admit1".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: AgentWorkloadSpec {
                image: "ghcr.io/unsigned-gg/agent:latest".to_string(),
                cpu: Some("1000m".to_string()),
                memory: Some("1Gi".to_string()),
                isolation_profile: IsolationProfile::KataMicroVm,
                scratch_volumes: vec![ScratchVolumeSpec::default()],
                ..Default::default()
            },
            status: None,
        };
        let raw = to_yaml_manifest(&wl).expect("serialize workload");
        let digests =
            admit_yaml_stream(&raw, "default", "8000m", "8Gi", 8).expect("admit valid workload");
        assert_eq!(digests.len(), 1);
        assert_eq!(digests[0].len(), 16);

        // Exceeding memory quota (1Gi + 256Mi Kata overhead > 1Gi ceiling) must fail admission
        assert!(admit_yaml_stream(&raw, "default", "8000m", "1Gi", 8).is_err());
    }

    #[test]
    fn test_invariants_and_lease_cli_helpers() {
        let snapshot = ClusterInventorySnapshot {
            provider_nodes: vec![ProviderNodeRecord {
                provider_id: "hetzner://1001".to_string(),
                expected_name: "cygnus-worker-01".to_string(),
                require_kata_runtime: true,
            }],
            k8s_nodes: vec![K8sNodeSnapshot {
                name: "cygnus-worker-01".to_string(),
                provider_id: Some("hetzner://1001".to_string()),
                ready: true,
                unschedulable: false,
                allocatable_cpu_millis: 8_000,
                allocatable_memory_bytes: 16 * 1024 * 1024 * 1024,
                kata_runtime_capable: true,
            }],
            scheduled_pods: vec![ScheduledPodFootprint {
                name: "agent-01".to_string(),
                namespace: "agent-ns".to_string(),
                node_name: "cygnus-worker-01".to_string(),
                cpu_millis: 2_000,
                memory_bytes: 2 * 1024 * 1024 * 1024,
                isolation_profile: IsolationProfile::KataMicroVm,
            }],
            services: vec![ServiceEndpointSnapshot {
                name: "reverie".to_string(),
                namespace: "agent-ns".to_string(),
                service_type: "LoadBalancer".to_string(),
                ready_endpoints: 2,
            }],
            kata_memory_overhead_bytes: None,
            memory_warn_permille: None,
        };
        let raw = to_yaml_manifest(&snapshot).expect("serialize snapshot");
        let report = audit_cluster_invariants_yaml(&raw).expect("healthy cluster snapshot");
        assert!(report.healthy);
        assert_eq!(report.error_count, 0);

        let lease_yaml = render_lease_yaml(
            "k8-orchestrator-leader",
            "agent-ns",
            "k8-orchestrator-0",
            15,
        )
        .expect("render lease");
        assert!(lease_yaml.contains("k8-orchestrator-leader"));
        assert!(lease_yaml.contains("k8-orchestrator-0"));
    }

    #[test]
    fn test_drain_plan_and_drift_cli_helpers() {
        let drain_ctx = DrainClusterContext {
            target_node: "cygnus-worker-01".to_string(),
            nodes: vec![
                K8sNodeSnapshot {
                    name: "cygnus-worker-01".to_string(),
                    provider_id: Some("hetzner://1001".to_string()),
                    ready: true,
                    unschedulable: false,
                    allocatable_cpu_millis: 8_000,
                    allocatable_memory_bytes: 16 * 1024 * 1024 * 1024,
                    kata_runtime_capable: true,
                },
                K8sNodeSnapshot {
                    name: "cygnus-worker-02".to_string(),
                    provider_id: Some("hetzner://1002".to_string()),
                    ready: true,
                    unschedulable: false,
                    allocatable_cpu_millis: 8_000,
                    allocatable_memory_bytes: 16 * 1024 * 1024 * 1024,
                    kata_runtime_capable: true,
                },
            ],
            existing_pods_on_other_nodes: vec![],
            drain_candidates: vec![DrainCandidatePod {
                name: "agent-01".to_string(),
                namespace: "agent-ns".to_string(),
                priority_tier: WorkloadPriorityTier::InteractiveAgent,
                isolation_profile: IsolationProfile::KataMicroVm,
                cpu_millis: 2_000,
                memory_bytes: 2 * 1024 * 1024 * 1024,
                is_daemonset: false,
                is_mirror_pod: false,
                has_unmanaged_local_storage: false,
                pdb_name: Some("agent-pdb".to_string()),
            }],
            pdbs: vec![PdbBudgetSnapshot {
                name: "agent-pdb".to_string(),
                namespace: "agent-ns".to_string(),
                disruptions_allowed: 1,
            }],
            allow_local_storage_erasure: false,
            kata_memory_overhead_bytes: None,
        };
        let drain_yaml = to_yaml_manifest(&drain_ctx).expect("serialize drain context");
        let drain_report = evaluate_drain_plan_yaml(&drain_yaml).expect("safe drain plan");
        assert!(drain_report.safe_to_drain);
        assert_eq!(drain_report.evicted_count, 1);

        let live_sts = StatefulSet {
            metadata: ObjectMeta {
                name: Some("reverie-db".to_string()),
                ..Default::default()
            },
            spec: Some(StatefulSetSpec {
                service_name: Some("reverie-headless".to_string()),
                replicas: Some(1),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut desired_sts = live_sts.clone();
        desired_sts.spec.as_mut().unwrap().replicas = Some(3);
        let live_yaml = to_yaml_manifest(&live_sts).expect("serialize live sts");
        let desired_yaml = to_yaml_manifest(&desired_sts).expect("serialize desired sts");
        let drift_report =
            evaluate_drift_yaml(&live_yaml, &desired_yaml).expect("in-place sts scale");
        assert_eq!(
            drift_report.strategy,
            DriftRemediationStrategy::InPlaceApply
        );
    }

    #[test]
    fn test_configmap_and_rollout_check_cli_helpers() {
        let cm_yaml = render_immutable_configmap_yaml(
            "agent-cfg",
            "agent-ns",
            &["LOG_LEVEL=info".to_string(), "PORT=8080".to_string()],
        )
        .expect("render immutable ConfigMap");
        assert!(cm_yaml.contains("immutable: true"));
        assert!(cm_yaml.contains("agent-cfg-"));

        let rollout_spec = RolloutQuorumSpec {
            workload_id: "agent-ns/reverie".to_string(),
            replicas: 4,
            max_unavailable: 1,
            max_surge: 1,
            pdb_min_available: 3,
        };
        let rollout_yaml = to_yaml_manifest(&rollout_spec).expect("serialize rollout spec");
        let report = evaluate_rollout_check_yaml(&rollout_yaml).expect("valid rollout quorum");
        assert_eq!(report.min_ready_during_rollout, 3);
        assert_eq!(report.max_total_pods_during_rollout, 5);
    }
}
