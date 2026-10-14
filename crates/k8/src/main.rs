// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `k8` CLI entrypoint.

use clap::{Parser, Subcommand};
use k8_api::{AgentWorkload, AgentWorkloadSpec};
use k8_core::{K8Client, K8Error, Result};
use k8_orchestrator::Orchestrator;
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, ListParams};
use std::collections::BTreeMap;
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

        /// Render the validated Kubernetes Job YAML manifest without contacting the cluster
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

        Commands::Run {
            image,
            command,
            args,
            gpu,
            cpu,
            memory,
            timeout,
            role,
            dry_run,
        } => {
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
            };

            if dry_run {
                let ns = cli.namespace.as_deref().unwrap_or("default");
                let yaml = Orchestrator::render_job_yaml("agent-dryrun", ns, &spec)?;
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

                Commands::Crd | Commands::Run { .. } => {}
            }
        }
    }

    Ok(())
}
