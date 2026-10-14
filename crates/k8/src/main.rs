// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `k8` CLI entrypoint.

use clap::{Parser, Subcommand};
use k8_api::{
    audit_network_policy_zero_trust, audit_pod_spec_restricted, from_multi_yaml_manifests,
    AgentWorkload, AgentWorkloadSpec, EgressRuleSpec, IsolationProfile,
};
use k8_core::{K8Client, K8Error, Result};
use k8_orchestrator::Orchestrator;
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::api::networking::v1::NetworkPolicy;
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

    /// Audit a single or multi-document YAML 1.2 manifest against PodSecurity `restricted` and zero-trust invariants
    Audit {
        /// Path to the YAML 1.2 manifest file
        #[arg(short, long)]
        file: PathBuf,
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

        /// Render the full YAML 1.2 bundle (NetworkPolicy + PodDisruptionBudget + Job) in dry-run mode
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
            }
            "Pod" => {
                let pod: Pod = serde_json::from_value(doc.clone())
                    .map_err(|e| K8Error::Config(format!("invalid Pod document: {e}")))?;
                let pod_spec = pod
                    .spec
                    .as_ref()
                    .ok_or_else(|| K8Error::Config("Pod missing spec".into()))?;
                audit_pod_spec_restricted(pod_spec).map_err(K8Error::SecurityAudit)?;
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
                "Verified {count} YAML 1.2 document(s) in {} against PodSecurity restricted and zero-trust invariants",
                file.display()
            );
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

                Commands::Crd | Commands::Audit { .. } | Commands::Run { .. } => {}
            }
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_yaml_stream_accepts_hardened_bundle() {
        let spec = AgentWorkloadSpec {
            image: "ghcr.io/unsigned-gg/agent:latest".to_string(),
            isolation_profile: IsolationProfile::KataMicroVm,
            egress: Some(EgressRuleSpec {
                allow_dns: true,
                allowed_cidrs: vec!["10.42.0.0/16".to_string()],
                allowed_tcp_ports: vec![443],
            }),
            ..Default::default()
        };
        let bundle = Orchestrator::render_workload_bundle_yaml("agent-bundle1", "default", &spec)
            .expect("render bundle");
        let count = audit_yaml_stream(&bundle).expect("audit bundle");
        assert_eq!(count, 3);
    }
}
