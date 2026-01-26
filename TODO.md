# TODO - Post Code Review Items

This file documents optional improvements identified during the 8-pass code review.

## Completed (2024-01-04)

All 8 passes of the fullcleanreview completed successfully:

1. **Pass 1: Foundation** - Architecture sound, ownership boundaries clear
2. **Pass 2: Error Flow** - Error handling with thiserror/anyhow, proper propagation
3. **Pass 3: Correctness** - Tests exist, debug_assert! added, proptest coverage
4. **Pass 4: Safety** - All unsafe blocks documented with SAFETY comments
5. **Pass 5: Concurrency** - Atomic ordering correct, cancel-safety reviewed
6. **Pass 6: Performance** - Cache alignment, inlining, release profile optimized
7. **Pass 7: Domain-Specific** - Networking/memory/GPU patterns validated
8. **Pass 8: Polish** - Formatting applied, stub modules created

## Optional Improvements

### Documentation

- [x] Add doc comments to reduce `missing_docs` warnings (DONE)
  - Fixed 61 missing doc warnings across warp-iam, warp-cli, warp-gpu, warp-stream

### Build Optimization

- [ ] Consider `lto = true` instead of `lto = "thin"` for maximum release optimization
  - Trade-off: slower compile, smaller/faster binary
  - Current setting is a reasonable balance

- [x] Set up `cargo-deny` for supply chain security (DONE)
  ```bash
  cargo deny check  # advisories ok, bans ok, licenses ok, sources ok
  ```

- [ ] Run `cargo +nightly udeps` periodically to check for unused dependencies
  ```bash
  cargo install cargo-udeps
  cargo +nightly udeps
  ```

### Dependency Management

- [ ] Resolve duplicate transitive dependencies (low priority, not actionable)
  - `axum-core` v0.4.5 and v0.5.5 (askama_axum vs axum)
  - `core-foundation` v0.9.4 and v0.10.1 (different rustls paths)
  - These are transitive and will resolve when upstream updates

### Testing

- [x] Add loom/shuttle tests for concurrent code paths (DONE)
  - Healer daemon: `crates/warp-store/tests/healer_loom.rs`
  - Scrub daemon: `crates/warp-store/tests/scrub_shuttle.rs`
  - NetworkManager: `crates/portal-net/tests/manager_loom.rs`, `manager_shuttle.rs`

### Feature Implementations

- [x] LDAP provider implemented (DONE)
  - Full `IdentityProvider` trait implementation with ldap3 v0.12
  - Supports OpenLDAP and Active Directory configurations
  - STARTTLS and TLS verification options
  - User/group search and authentication
  - Enable with: `cargo build -p warp-iam --features ldap`

- [x] AWS KMS provider implemented (DONE)
  - Full `KmsProvider` trait implementation with aws-sdk-kms v1.97
  - Create/list/rotate/delete keys
  - Envelope encryption with data key generation
  - Re-encryption, tagging, and key management
  - LocalStack support via custom endpoint
  - Enable with: `cargo build -p warp-kms --features aws`

### Feature Stubs

The following feature modules have placeholder implementations:
- `warp-dpu/src/backends/bluefield.rs` - BlueField DPU (requires DOCA SDK)

## Review Plan Reference

The full review plan is preserved at:
`.claude/plans/splendid-mapping-parnas.md`
