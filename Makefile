# k8 — Estate Standard Rust Makefile
# Host throttling: -j 2 is mandatory on host ceres.

CARGO ?= cargo
JOBS ?= 2
CARGO_FLAGS ?= --workspace -j $(JOBS)

.DEFAULT_GOAL := help

.PHONY: help check fmt fmt-check clippy test doc-test deny build release clean \
        xtask-check graph-audit spec-check toolchain-check branch-hygiene

##@ General

help: ## Display this help screen
	@awk 'BEGIN { \
		use_color = (ENVIRON["NO_COLOR"] == "" && ENVIRON["TERM"] != "dumb"); \
		c_bold = use_color ? "\033[1m" : ""; \
		c_cyan = use_color ? "\033[36m" : ""; \
		c_reset = use_color ? "\033[0m" : ""; \
		FS = ":.*##"; \
		printf "\nUsage:\n  make %s<target>%s\n", c_cyan, c_reset \
	} \
	/^[a-zA-Z_0-9-]+:.*?##/ { \
		printf "  %s%-20s%s %s\n", c_cyan, $$1, c_reset, $$2 \
	} \
	/^##@/ { \
		printf "\n%s%s%s\n", c_bold, substr($$0, 5), c_reset \
	}' $(MAKEFILE_LIST)

##@ Check & Lint

check: fmt-check clippy test doc-test deny graph-audit spec-check ## Run all formatting, lint, test, advisory, and xtask gates

fmt: ## Format all workspace Rust sources
	$(CARGO) fmt --all

fmt-check: ## Verify formatting without modifying files
	$(CARGO) fmt --all -- --check

clippy: ## Run Clippy across all workspace targets with warnings denied
	$(CARGO) clippy $(CARGO_FLAGS) --all-targets -- -D warnings

deny: ## Audit licenses, bans, sources, and security advisories via cargo-deny
	@if command -v cargo-deny >/dev/null 2>&1; then \
		$(CARGO) deny check; \
	else \
		echo "cargo-deny not installed; skipping"; \
	fi

##@ Build & Test

build: ## Build all workspace targets in debug mode
	$(CARGO) build $(CARGO_FLAGS)

release: ## Build all workspace targets in release mode
	$(CARGO) build $(CARGO_FLAGS) --release

test: ## Run unit and integration tests (prefers cargo-nextest when available)
	@if command -v cargo-nextest >/dev/null 2>&1; then \
		$(CARGO) nextest run $(CARGO_FLAGS); \
	else \
		$(CARGO) test $(CARGO_FLAGS); \
	fi

doc-test: ## Run documentation tests across the workspace
	$(CARGO) test $(CARGO_FLAGS) --doc

clean: ## Remove build artifacts
	$(CARGO) clean

##@ Tooling & Maintenance

xtask-check: ## Run the checkpointed xtask verification DAG
	$(CARGO) xtask check

graph-audit: ## Verify Wave-0 zero-I/O leaf crate and acyclic workspace DAG
	$(CARGO) xtask graph-audit

spec-check: ## Validate architecture specifications in specs/
	$(CARGO) xtask spec-check

toolchain-check: ## Verify active rustc matches rust-toolchain.toml and MSRV floor
	$(CARGO) xtask toolchain-check

branch-hygiene: ## Audit local git branches landed on origin/main
	$(CARGO) xtask branch-hygiene
