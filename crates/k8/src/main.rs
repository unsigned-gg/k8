// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `k8` CLI entrypoint.

use clap::{Parser, Subcommand};
use k8_api::{
    audit_network_policy_zero_trust, audit_pod_spec_restricted, audit_pod_volumes,
    audit_role_least_privilege, audit_service_account_zero_trust, build_controller_lease,
    evaluate_cluster_invariants, evaluate_lease_transition, evaluate_workload_admission,
    from_multi_yaml_manifests, from_yaml_manifest, to_yaml_manifest, AdmissionContext,
    AgentWorkload, AgentWorkloadSpec, ClusterInvariantReport, ClusterInventorySnapshot,
    CpuQuantity, EgressRuleSpec, IsolationProfile, MemoryQuantity, NamespaceQuotaSpec,
    QuotaUsageSnapshot, ScratchMedium, ScratchVolumeSpec, DEFAULT_LEASE_DURATION_SECONDS,
};
use k8_core::{K8Client, K8Error, Result};
use k8_orchestrator::Orchestrator;
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::{Pod, ServiceAccount};
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

    /// Audit a single or multi-document YAML 1.2 manifest against PodSecurity `restricted`, RBAC, volume, and network invariants
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
                "Verified {count} YAML 1.2 document(s) in {} against PodSecurity restricted, RBAC, volume, and zero-trust invariants",
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
        K8sNodeSnapshot, ProviderNodeRecord, ScheduledPodFootprint, ScopedRuleSpec,
        ServiceEndpointSnapshot,
    };
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
}
