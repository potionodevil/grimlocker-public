# Grimlocker Architecture — Public Edition

## Overview

Grimlocker is a zero-trust vault daemon. The public repository exposes the
**cryptographic engine** — the part that must be verifiable by independent
security researchers. The full appliance (storage format, network layer,
UI integration) remains proprietary.

## Layer Diagram

```
                        ┌─────────────────────────┐
                        │    Security Audit Log    │
                        │  (tamper-evident ring)   │
                        └──────────┬──────────────┘
                                   │
┌──────────┐    ┌──────────┐    ┌──┴────────┐    ┌──────────┐
│  Client  │───▶│  GQL     │───▶│  Kernel   │───▶│  Crypto  │
│ (SDK/UI) │    │ Protocol │    │ Event Bus │    │ Provider │
└──────────┘    └──────────┘    └─────┬─────┘    └──────────┘
                                      │
                               ┌──────┴──────┐
                               │   Security   │
                               │   State      │
                               │   Machine    │
                               └─────────────┘
```

## Package Responsibilities

### `engine/crypto/` — Cryptographic Provider

The root cryptographic interface. All implementations must be stateless and
perform no file I/O.

| File | Responsibility |
|------|----------------|
| `interface.go` | `Provider` interface: Encrypt, Decrypt, DeriveArgon2id, HKDF, Coordinate, SecureZero |
| `chacha.go` | ChaCha20-Poly1305 AEAD encrypt/decrypt (via `golang.org/x/crypto`) |
| `argon.go` | Argon2id key derivation — 128MB memory, 4 iterations (OWASP 2023+) |
| `hkdf.go` | HKDF-SHA256 key expansion |
| `coordinate.go` | Entropy file offset derivation → XOR → MVK |
| `entropy.go` | Entropy file generation (secure random) |
| `shredder.go` | 7-pass secure file overwrite |
| `provider.go` | Provider implementation (delegates to RustBridge for enclave ops) |
| `pqc_ready.go` | Post-quantum crypto stubs (ML-KEM, ML-DSA — roadmap) |

### `engine/security/` — Security State Machine

| File | Responsibility |
|------|----------------|
| `session.go` | `SessionContext` — vault unlock/lock state, activity timer |
| `lockdown.go` | `LockdownManager` — auth failure escalation (soft → hard) |
| `audit.go` | `AuditLog` — append-only ring buffer, SHA-256 chained |
| `mvk_store.go` | `MVKStore` — handle-based key storage in locked memory |
| `memguard.go` | `MemoryGuard` interface — OS memory locking abstraction |
| `constant_time.go` | Constant-time comparison utilities |
| `secret_guard.go` | `SecretGuard` — heap-allocated secret with zeroization |
| `intrusion_detector.go` | `IntrusionDetector` — anomaly-based threat detection |
| `rate_limiter.go` | `RateLimiter` — exponential backoff for auth failures |
| `zkp.go` | Zero-Knowledge Proof challenge/response (commitment scheme) |

### `engine/gql/` — Binary Protocol (GrimQueryLanguage)

The **injection-immune** binary query protocol. No text parsing occurs at
any point — every field is length-prefixed binary, every operation is
schema-validated, and every mutation requires ACL clearance.

| File | Responsibility |
|------|----------------|
| `frame.go` | Frame encode/decode (8-byte header + binary payload) |
| `opcodes.go` | Operation constants + read/write classification |
| `types.go` | `GQLQuery`, `GQLEntry`, `GQLResult` types + binary serialization |
| `validator.go` | Two-stage validator: syntactic (schema) → semantic (ACL) |
| `errors.go` | Error code mapping |

**Security property:** The binary-only format with length-prefixed fields
makes it impossible to inject SQL, JSON, command-line escapes, or control
characters. All identifiers are restricted to `[a-zA-Z0-9_.-]`.

### `engine/kernel/` — Event Bus

The backbone of the internal architecture. All components communicate through
typed events on a channel-gated bus.

| File | Responsibility |
|------|----------------|
| `dispatcher.go` | `Dispatcher` interface — Dispatch, Request, Subscribe, Register |
| `event.go` | `Event` struct — ID, Type, Payload, ReplyTo |
| `bus.go` | `Bus` implementation — gated channels, timeout-safe Request |
| `registry.go` | Module lifecycle management |
| `handler.go` | Handler decorators — panic recovery, structured logging |
| `uuid.go` | Cryptographically random event IDs |
| `module_factory.go` | `ModuleFactory` and `BaseModule` templates |

### `engine/errors/` — Error System

| File | Responsibility |
|------|----------------|
| `types.go` | `GrimlockError` — typed codes, safe JSON serialization |
| `logging.go` | `StructuredLogger` interface + `StdLogger` implementation |
| `stacktrace.go` | Stack frame capture and formatting |

### `engine/storage/` — Block Store Interface (Minimal)

Only the public interfaces — no implementation, no vault format.

| File | Responsibility |
|------|----------------|
| `interface.go` | `BlockStore` interface: WriteBlock, ReadBlock, DeleteBlock, ListBlocks |
| `block.go` | `Block` and `BlockMeta` data types |
| `blockstore_v2.go` | `BlockStoreV2`, `WriteTransaction`, `ReadTransaction` interfaces + `InMemoryWriteTransaction` |
| `entry.go` | `Category` type + constants |

### `engine/bridge/` — RustBridge Interface

Abstracts the Rust secure enclave. The engine never depends on the Rust
binary directly — only on the `RustBridge` interface. When the enclave
is unavailable, the `DefaultBridge` provides pure Go fallbacks.

### `engine/provider/` — Hexagonal Port Interfaces

| File | Responsibility |
|------|----------------|
| `interfaces.go` | `VaultProvider`, `AuthProvider`, `StorageProvider` — the hexagonal architecture ports |

## Design Principles

1. **Engine never sees passwords.** Only pre-hashed `[]byte`.
2. **Engine never opens files.** Only abstract `FileSystem` handles.
3. **Engine never uses HTTP.** Network is the appliance's responsibility.
4. **All crypto is stateless.** No key material held in the crypto provider.
5. **Error types carry codes, not secrets.** Stack traces excluded from client responses.
6. **Interfaces over concrete types.** Every cross-boundary dependency is an interface.
