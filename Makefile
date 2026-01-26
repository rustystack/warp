# WARP Project Makefile
# Convenience commands for development and CI

.PHONY: all build test check fmt clippy deny audit doc clean

# Default target
all: check test

# Build all crates
build:
	cargo build --workspace

# Build with all features
build-full:
	cargo build --workspace --all-features

# Run all tests
test:
	cargo test --workspace

# Run tests with all features
test-full:
	cargo test --workspace --all-features

# Run concurrency tests (loom/shuttle)
test-concurrency:
	cargo test -p warp-store --test healer_loom -- --test-threads=1
	cargo test -p warp-store --test scrub_shuttle -- --test-threads=1
	cargo test -p warp-store --test arbiter_shuttle -- --test-threads=1

# Run all checks (format, clippy, deny)
check: fmt-check clippy deny

# Check formatting
fmt-check:
	cargo fmt --all -- --check

# Format code
fmt:
	cargo fmt --all

# Run clippy lints
clippy:
	cargo clippy --workspace --all-targets -- -D warnings

# Run clippy with all features
clippy-full:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

# Security audit
audit:
	cargo audit

# Dependency policy checks
deny:
	cargo deny check

deny-advisories:
	cargo deny check advisories

deny-licenses:
	cargo deny check licenses

deny-bans:
	cargo deny check bans

# Check for unused dependencies (requires nightly)
udeps:
	cargo +nightly udeps --workspace

# Generate documentation
doc:
	cargo doc --workspace --no-deps

# Generate documentation with private items
doc-private:
	cargo doc --workspace --no-deps --document-private-items

# Open documentation in browser
doc-open:
	cargo doc --workspace --no-deps --open

# Check for missing documentation
doc-check:
	@echo "Checking for missing documentation..."
	@cargo doc --workspace --no-deps 2>&1 | grep -i "missing" || echo "No missing documentation warnings"

# Clean build artifacts
clean:
	cargo clean

# Run benchmarks
bench:
	cargo bench --workspace

# Install development tools
tools:
	cargo install cargo-audit cargo-deny cargo-udeps

# Protocol handlers tests
test-protocols:
	cargo test -p warp-smb -- --nocapture
	cargo test -p warp-nfs -- --nocapture
	cargo test -p warp-block --features nvmeof -- nvmeof --nocapture

# Dashboard tests
test-dashboard:
	cargo test -p warp-dashboard -- --nocapture

# HPC tests
test-hpc:
	cargo test -p warp-sched -- --nocapture
	cargo test -p warp-store --features hpc-channels -- --nocapture

# Help
help:
	@echo "WARP Project Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all             - Run checks and tests (default)"
	@echo "  build           - Build all crates"
	@echo "  build-full      - Build with all features"
	@echo "  test            - Run all tests"
	@echo "  test-full       - Run tests with all features"
	@echo "  test-concurrency - Run loom/shuttle concurrency tests"
	@echo "  check           - Run format check, clippy, and deny"
	@echo "  fmt             - Format code"
	@echo "  fmt-check       - Check formatting"
	@echo "  clippy          - Run clippy lints"
	@echo "  clippy-full     - Run clippy with all features"
	@echo "  audit           - Security audit with cargo-audit"
	@echo "  deny            - Dependency policy check with cargo-deny"
	@echo "  udeps           - Check for unused dependencies (nightly)"
	@echo "  doc             - Generate documentation"
	@echo "  doc-open        - Generate and open documentation"
	@echo "  doc-check       - Check for missing documentation"
	@echo "  clean           - Clean build artifacts"
	@echo "  bench           - Run benchmarks"
	@echo "  tools           - Install development tools"
	@echo "  test-protocols  - Test protocol handlers (SMB, NFS, NVMe-oF)"
	@echo "  test-dashboard  - Test dashboard"
	@echo "  test-hpc        - Test HPC features"
	@echo "  help            - Show this help"
