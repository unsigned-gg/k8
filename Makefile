# Makefile for unsigned-gg/k8
# POSIX make wrapper that bridges directly to cargo or just.

JOBS ?= 2

.PHONY: all default check test fmt fmt-check clippy build-release run help

default: check

check:
	cargo check --workspace -j $(JOBS)

test:
	cargo test --workspace -j $(JOBS)

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets -j $(JOBS)

build-release:
	cargo build --release --workspace -j $(JOBS)

help:
	@echo "Available targets:"
	@echo "  make check         - Check compilation across all crates"
	@echo "  make test          - Run test suites"
	@echo "  make fmt           - Autoformat code"
	@echo "  make fmt-check     - Verify code format"
	@echo "  make clippy        - Run clippy linting"
	@echo "  make build-release - Build optimized release binaries"
