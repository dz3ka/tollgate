# Tollgate developer Makefile. Targets assume the pinned Rust toolchain (see rust-toolchain.toml).

.PHONY: build test fmt fmt-check lint ci

## build: compile the whole workspace against the committed lockfile
build:
	cargo build --workspace --locked

## test: run the full workspace test suite
test:
	cargo test --workspace --locked

## fmt: format all crates in place
fmt:
	cargo fmt --all

## fmt-check: verify formatting without modifying files
fmt-check:
	cargo fmt --all --check

## lint: run clippy across all targets, treating warnings as errors
lint:
	cargo clippy --workspace --all-targets --locked -- -D warnings

## ci: single entrypoint CI runs — format check, build, lint, test
ci: fmt-check build lint test
