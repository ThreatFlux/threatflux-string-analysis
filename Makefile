.DEFAULT_GOAL := help

MSRV := 1.95.0
STABLE := 1.97.1
MARKDOWN_TARGET_DIR := target/markdown-doctests

.PHONY: help fmt fmt-check check lint test test-doc markdown msrv-check docs examples
.PHONY: coverage audit deny semver package publish-dry-run ci clean

help: ## Show available commands
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make <target>\n\n"} /^[a-zA-Z_-]+:.*##/ {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

fmt: ## Format Rust sources
	cargo fmt --all

fmt-check: ## Check Rust formatting
	cargo fmt --all -- --check

check: ## Check all targets and features
	cargo check --all-targets --all-features --locked

lint: ## Run strict Clippy checks
	cargo clippy --all-targets --all-features --locked -- -D warnings

test: ## Run the test suite
	cargo test --all-targets --all-features --locked

test-doc: ## Run crate documentation tests
	cargo test --doc --all-features --locked

markdown: ## Compile Rust blocks in README and guides
	CARGO_TARGET_DIR=$(MARKDOWN_TARGET_DIR) cargo +$(STABLE) build --all-features --locked
	@set -eu; \
	rlib=$$(ls -t $(MARKDOWN_TARGET_DIR)/debug/deps/libthreatflux_string_analysis-*.rlib | head -n 1); \
	for document in README.md docs/*.md; do \
		rustup run $(STABLE) rustdoc --test "$$document" --edition 2024 \
			--extern threatflux_string_analysis="$$rlib" \
			-L dependency=$(MARKDOWN_TARGET_DIR)/debug/deps; \
	done

msrv-check: ## Check and test with the minimum Rust version
	cargo +$(MSRV) check --all-targets --all-features --locked
	cargo +$(MSRV) test --all-targets --all-features --locked

docs: ## Build documentation with warnings denied
	RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps --locked

examples: ## Build all examples
	cargo build --examples --all-features --locked

coverage: ## Generate an LCOV coverage report with cargo-llvm-cov
	cargo llvm-cov --all-features --workspace --locked --lcov --output-path lcov.info

audit: ## Check RustSec advisories
	cargo audit --deny warnings

deny: ## Check dependency and license policy
	cargo deny check

semver: ## Compare the public API with the latest release
	cargo semver-checks check-release --all-features

package: ## Build and verify the crates.io package
	cargo package --allow-dirty --locked

publish-dry-run: ## Validate crates.io publication without uploading
	cargo publish --dry-run --allow-dirty --locked

ci: fmt-check check lint test test-doc markdown msrv-check docs examples audit deny package ## Run the complete local CI matrix

clean: ## Remove Cargo build output
	cargo clean
