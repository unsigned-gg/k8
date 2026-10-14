# k8 — Estate Standard Justfile
# Host throttling: -j 2 is mandatory on host ceres.

set shell := ["bash", "-euo", "pipefail", "-c"]

jobs := env_var_or_default("CARGO_BUILD_JOBS", "2")

# Default recipe: list available recipes
default:
    @just --list

# Run all formatting, lint, test, doc-test, advisory, and xtask gates
check: fmt-check clippy test doc-test deny graph-audit spec-check

# Format all workspace Rust code
fmt:
    cargo fmt --all

# Check formatting without modifying files
fmt-check:
    cargo fmt --all -- --check

# Run clippy lints across all workspace targets
clippy:
    cargo clippy --workspace --all-targets -j {{jobs}} -- -D warnings

# Run unit and integration tests
test:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v cargo-nextest >/dev/null 2>&1; then
        cargo nextest run --workspace -j {{jobs}}
    else
        cargo test --workspace -j {{jobs}}
    fi

# Run documentation tests
doc-test:
    cargo test --workspace --doc -j {{jobs}}

# Run cargo-deny advisory, license, ban, and source checks
deny:
    cargo deny check

# Build all workspace crates in debug mode
build:
    cargo build --workspace -j {{jobs}}

# Build all workspace crates in release mode
release:
    cargo build --workspace --release -j {{jobs}}

# Run the checkpointed xtask verification DAG
xtask-check:
    cargo xtask check

# Verify Wave-0 zero-I/O leaf crate and acyclic workspace DAG
graph-audit:
    cargo xtask graph-audit

# Validate architecture specs in specs/
spec-check:
    cargo xtask spec-check

# Verify active rustc matches rust-toolchain.toml
toolchain-check:
    cargo xtask toolchain-check

# Audit local git branches against origin/main
branch-hygiene:
    cargo xtask branch-hygiene

# Clean build artifacts
clean:
    cargo clean
