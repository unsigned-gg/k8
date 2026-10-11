# Justfile for unsigned-gg/k8
# The modern command runner for Rust projects.

set shell := ["bash", "-euo", "pipefail", "-c"]

jobs := "2"

# Default recipe: list available commands
default:
    @just --list

# Check code compiles across all crates
check:
    cargo check --workspace -j {{jobs}}

# Run all tests with standard runner
test:
    cargo test --workspace -j {{jobs}}

# Format all code
fmt:
    cargo fmt --all

# Check code formatting without modifying
fmt-check:
    cargo fmt --all -- --check

# Run clippy linter
clippy:
    cargo clippy --workspace --all-targets -j {{jobs}}

# Build release binaries
build-release:
    cargo build --release --workspace -j {{jobs}}

# Run the k8 CLI locally
run *args:
    cargo run -p k8 -j {{jobs}} -- {{args}}
