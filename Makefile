.PHONY: help init build release clean test test-unit test-integration test-comprehensive lint fmt fmt-check check deps deps-tree security-audit deny-check outdated-check machete-check quality-check dev dev-full ci ci-full prepare-release coverage coverage-html setup-optimization docs version

# Default target
help:
	@echo "String Analysis - Makefile Commands"
	@echo "================================"
	@echo "BUILD COMMANDS:"
	@echo "  init          - Initialize project dependencies"
	@echo "  build         - Build the crate in debug mode"
	@echo "  release       - Build the crate in release mode"
	@echo "  clean         - Clean build artifacts"
	@echo ""
	@echo "TEST COMMANDS:"
	@echo "  test          - Run all tests"
	@echo "  test-unit     - Run unit tests"
	@echo "  test-integration - Run integration tests"
	@echo "  test-comprehensive - Run comprehensive tests"
	@echo ""
	@echo "QUALITY COMMANDS:"
	@echo "  lint          - Run clippy linter"
	@echo "  fmt           - Format code with rustfmt"
	@echo "  fmt-check     - Check code formatting"
	@echo "  check         - Run cargo check"
	@echo "  security-audit - Run security audit"
	@echo ""
	@echo "MISC COMMANDS:"
	@echo "  deps          - Update dependencies"
	@echo "  deps-tree     - Show dependency tree"
	@echo "  coverage      - Generate code coverage"
	@echo "  coverage-html - Generate HTML coverage report"
	@echo "  docs          - Build documentation"
	@echo "  version       - Show crate version"
	@echo ""
	@echo "WORKFLOWS:"
	@echo "  dev           - Format, lint and test"
	@echo "  dev-full      - Format, lint and comprehensive tests"
	@echo "  ci            - Formatting check, lint and tests"
	@echo "  ci-full       - Formatting check, lint, comprehensive tests and audit"
	@echo "  prepare-release - Clean, release build, comprehensive tests and audit"

# Initialize project
init:
	@echo "Initializing project..."
	rustup update stable
	rustup component add clippy rustfmt
	cargo fetch
	@echo "Project initialized successfully!"

# Build debug version
build:
	@echo "Building debug version..."
	@if command -v sccache >/dev/null 2>&1; then \
	export RUSTC_WRAPPER=sccache; \
fi; \
	cargo build

# Build release version
release:
	@echo "Building release version..."
	@if command -v sccache >/dev/null 2>&1; then \
	export RUSTC_WRAPPER=sccache; \
fi; \
	cargo build --release

# Run tests
test:
	@echo "Running all tests..."
	cargo test

# Run unit tests only
test-unit:
	@echo "Running unit tests..."
	cargo test --test unit_test

# Run integration tests
test-integration:
	@echo "Running integration tests..."
	cargo test --test integration_test

# Run comprehensive tests
test-comprehensive:
	@echo "Running comprehensive tests..."
	cargo test --test comprehensive_test

# Setup optimization tools
setup-optimization:
	@echo "Setting up optimization tools..."
	@command -v cargo-llvm-cov >/dev/null 2>&1 || cargo install cargo-llvm-cov --locked
	@command -v sccache >/dev/null 2>&1 || cargo install sccache --locked
	@echo "Optimization tools installed!"

# Generate code coverage
coverage:
	@echo "Generating code coverage..."
	cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info
	@echo "Coverage report: lcov.info"

# Generate HTML coverage report
coverage-html:
	@echo "Generating HTML coverage report..."
	cargo llvm-cov --all-features --workspace --html
	@echo "Coverage report: open target/llvm-cov/html/index.html"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf target/

# Code quality
lint:
	@echo "Running clippy..."
	cargo clippy -- -D warnings

fmt:
	@echo "Formatting code..."
	cargo fmt

fmt-check:
	@echo "Checking code formatting..."
	cargo fmt -- --check

check:
	@echo "Running cargo check..."
	cargo check --all-features

# Dependency management
deps:
	@echo "Updating dependencies..."
	cargo update

deps-tree:
	@echo "Showing dependency tree..."
	cargo tree

# Security audit
security-audit:
	@echo "Running security audit..."
	cargo audit

# Dependency analysis with cargo-deny
deny-check:
	@echo "Running cargo-deny checks..."
	cargo deny check

# Check for outdated dependencies
outdated-check:
	@echo "Checking for outdated dependencies..."
	cargo outdated

# Remove unused dependencies
machete-check:
	@echo "Checking for unused dependencies..."
	cargo machete

# Full quality check
quality-check: fmt-check lint security-audit deny-check
	@echo "✅ All quality checks passed!"

# Development workflow (fast)
dev: fmt lint test
	@echo "Development checks passed!"

# Development workflow (comprehensive)
dev-full: fmt lint test-comprehensive
	@echo "Comprehensive development checks passed!"

# CI/CD preparation (fast for quick checks)
ci: fmt-check lint test
	@echo "CI checks passed!"

# CI/CD preparation (comprehensive for full validation)
ci-full: fmt-check lint test-comprehensive security-audit
	@echo "Comprehensive CI checks passed!"

# Release workflow
prepare-release: clean release test-comprehensive security-audit
	@echo "Release preparation complete!"
	@echo "Library location: ./target/release/libthreatflux_string_analysis.rlib"

# Documentation
docs:
	@echo "Building documentation..."
	cargo doc --no-deps --open

# Version info
version:
	@echo "threatflux-string-analysis version:"
	@cargo pkgid | cut -d# -f2

