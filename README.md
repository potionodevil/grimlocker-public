# Grimlocker — Security Audit Edition

> **Transparent cryptographic implementation for community code review and independent security analysis.**

---

## Purpose

This is the **public audit edition** of Grimlocker — a zero-trust, enterprise-grade password manager. It exposes every line of the cryptographic and security-critical code for public scrutiny while keeping proprietary infrastructure, storage logic, and UI components in the private repository.

**What this enables:**
- Independent verification of cryptographic correctness
- Community-driven vulnerability discovery
- Trust-through-transparency for a security product
- Educational reference for production-grade crypto engineering

**What is NOT included:**
- Storage / database implementation (block store, VFS, compression, ingest)
- API / WebSocket / IPC infrastructure
- UI layer (Tauri + React)
- Deployment configuration beyond crypto
- Credentials, test data, or operational configs

---

## Repository Contents

```
grimlocker-public/
├── core-rust/                          # Rust crypto enclave (cdylib)
│   ├── Cargo.toml
│   ├── Cargo.lock
│   └── src/
│       ├── crypto.rs                   # ChaCha20-Poly1305, BLAKE3, mlock, zeroize, guard pages
│       ├── enclave.rs                  # Secure memory enclave with mlock/VirtualLock
│       ├── lib.rs                      # C-ABI entry points (FFI exports for Go/CGO)
│       ├── main.rs                     # CLI state machine, IPC client, coordinate parser
│       ├── time_guard.rs              # Dual-clock integrity verification (monotonic + wallclock)
│       └── wipe.rs                    # 7-pass anti-forensic shredder with fsync verification
│
└── grimdb/                             # Go security & crypto packages
    ├── go.mod                          # Module: github.com/grimlocker/grimdb-public
    ├── go.sum
    │
    ├── cgo/
    │   └── rustbridge.go              # Go-Rust FFI bridge (CGO bindings to core-rust cdylib)
    │
    ├── crypto/                         # Go Crypto Engine
    │   ├── argon.go                    # Argon2id password hashing with calibrated parameters
    │   ├── chacha.go                   # ChaCha20-Poly1305 AEAD encryption/decryption
    │   ├── coordinate.go              # Key derivation from coordinate strings (BLAKE3 + HKDF)
    │   ├── engine.go                   # Central crypto engine coordinating all primitives
    │   ├── entropy.go                  # Secure random number generation (crypto/rand)
    │   ├── hkdf.go                     # HKDF-SHA256 key derivation
    │   ├── interface.go               # Provider interfaces for swappable crypto backends
    │   ├── module.go                   # Kernel module registration and lifecycle
    │   ├── provider.go                # Default provider implementation
    │   └── shredder.go                # Secure memory/disk deletion with verification
    │
    ├── kernel/                         # Minimal kernel stubs (for compilation)
    │   └── kernel.go                  # Event type constants, interfaces (Dispatcher, Module)
    │
    └── security/                       # Security Module
        ├── audit.go                    # Cryptographic audit log with SHA-256 chaining
        ├── constant_time.go           # Constant-time comparison primitives
        ├── integrity.go               # Binary integrity verification (hash-checking)
        ├── lockdown.go                # Hard/soft lockdown state machine (200-min window)
        ├── memlock.go                  # Cross-platform memory locking interface
        ├── memlock_unix.go            # Unix memory lock (mlock syscall)
        ├── memlock_windows.go         # Windows memory lock (VirtualLock API)
        ├── module.go                   # Security module registration and event handlers
        └── session.go                 # Session management and key lifecycle
```

---

## Cryptographic Architecture

### Key Hierarchy

```
User Password (human-memorable)
        │
        ▼
   Argon2id (32 MiB memory, 3 iterations, 4 parallelism)
        │
        ▼
   Master Key (32 bytes)
        │
        ├──► BLAKE3(Master Key) → HKDF-SHA256 → Workspace Keys (32 bytes)
        │
        └──► Entropy File (200-char) → Coordinate Extraction
                │
                ▼
           BLAKE3 + HKDF-SHA256 → Decryption Key (32 bytes)
```

### Cryptographic Primitives

| Primitive | Implementation | Purpose |
|---|---|---|
| **Argon2id** | `crypto/argon.go` + `golang.org/x/crypto/argon2` | Password hashing with memory-hardness |
| **ChaCha20-Poly1305** | `crypto/chacha.go` + `core-rust/crypto.rs` | AEAD encryption of all vault data |
| **BLAKE3** | `core-rust/crypto.rs` + `crypto/coordinate.go` | Fast key derivation from entropy |
| **HKDF-SHA256** | `crypto/hkdf.go` + `core-rust/crypto.rs` | Key expansion with info/context binding |
| **CSPRNG** | `crypto/entropy.go` → `crypto/rand` | Entropy file generation, nonces, salts |
| **SHA-256** | `security/audit.go` | Cryptographic audit log chaining |

### Design Principles

1. **Plaintext keys never touch Go's garbage collector.** All sensitive key material is generated, used, and zeroized exclusively in Rust's memory space via CGO FFI.
2. **Memory-locked allocations.** `mlock` (Unix) / `VirtualLock` (Windows) prevent sensitive data from being paged to swap.
3. **Zeroize-on-drop.** Rust's `zeroize` crate ensures key material is overwritten the moment it goes out of scope.
4. **Guard pages.** Rust allocates protected pages before and after sensitive buffers to catch buffer overflows as segfaults.
5. **Dual-clock integrity.** Monotonic + wall-clock cross-check prevents system clock manipulation attacks.

---

## Rust Enclave Details

### `crypto.rs` — Core Cryptographic Operations
- ChaCha20-Poly1305 encryption/decryption via the `chacha20poly1305` crate
- BLAKE3 hashing via the `blake3` crate
- Memory locking with mlock/VirtualLock
- Zeroize integration with the `zeroize` crate
- Guard page allocation surrounding all sensitive buffers

### `enclave.rs` — Secure Memory Enclave
- Manages the lifecycle of encrypted memory regions
- Provides `alloc()` / `dealloc()` with automatic zeroization
- Platform-specific memory protection (pages marked as non-readable after use)

### `lib.rs` — C-ABI Entry Points
Public FFI functions exported as `extern "C"`:
- `generate_entropy_file(path, length)` — Creates the 200-character entropy source
- `extract_key_from_coordinates(coords, entropy)` — Derives key from coordinate positions
- `generate_random_coordinates()` — Produces random coordinate sets
- `secure_zero(buf, len)` — Zeroizes a buffer with compiler barrier
- `encrypt_chacha(key, nonce, plaintext)` — AEAD encryption
- `decrypt_chacha(key, nonce, ciphertext)` — AEAD decryption

### `main.rs` — CLI State Machine
- Implements the Rust-side IPC client for direct vault operations
- Coordinate parser that extracts bytes from entropy at specified positions
- Entropy file reading, validation, and coordinate-based key reconstruction

### `time_guard.rs` — Dual-Clock Integrity
- Monotonic clock (`std::time::Instant`) that cannot be manipulated by OS time changes
- Wall-clock cross-check: if `current_wallclock < last_seen_wallclock`, time was turned backward
- Anomaly detection: wall-clock jumps > 1 year or monotonic regression trigger wipe
- Ticks-to-walloffset mapping stored in the `.gdb` header

### `wipe.rs` — Anti-Forensic Shredder
- 7-pass overwrite with cryptographic random data (matching exact file size)
- `fsync` after each pass to flush OS buffers
- File truncation to 0 bytes
- Final `fsync` + `unlink` (file deletion)
- Designed as best-effort on SSDs (FTL remapping caveat documented)

---

## Go Crypto Engine Details

### `argon.go` — Password Hashing
- Argon2id with calibrated parameters: 32 MiB memory, 3 iterations, 4 degrees of parallelism
- Produces a 32-byte hash suitable for master key derivation
- Salt is randomly generated per vault with `crypto/rand`

### `chacha.go` — AEAD Encryption
- ChaCha20-Poly1305 via the `golang.org/x/crypto/chacha20poly1305` library
- Nonce management with CSPRNG generation
- Additional data (AD) binding for context-aware encryption

### `coordinate.go` — Key Derivation from Coordinates
- Parses coordinate sets from the entropy file
- Combines extracted bytes via BLAKE3 hashing
- Expands via HKDF-SHA256 to produce a 32-byte decryption key
- Panic-key detection (`0,0,0` triggers disguised wipe)

### `engine.go` — Central Crypto Coordinator
- Orchestrates all cryptographic operations
- Manages key material lifecycle (generation, usage, zeroization)
- Provides a unified interface consumed by the storage and security modules

### `entropy.go` — Secure Random Generation
- Wraps Go's `crypto/rand` for all random bytes
- Generates entropy files used as the basis for coordinate-based key derivation
- Validates entropy file integrity (size, entropy density)

### `hkdf.go` — Key Derivation Function
- HKDF-SHA256 as specified in RFC 5869
- Extract phase with salt, expand phase with info parameter
- Used for deriving child keys from the master key

### `interface.go` — Provider Interfaces
- Defines swappable interfaces (`Engine`, `PasswordHasher`, `Encryptor`, `KeyDeriver`)
- Enables testing with mock implementations
- Follows Go interface segregation principles

### `module.go` — Kernel Integration
- Registers the crypto engine as a GrimDB kernel module
- Handles lifecycle events: init, start, stop, shutdown
- Subscribes to relevant event bus events (`AUTH.UNLOCK`, `VAULT.CREATE`, etc.)

### `provider.go` — Default Provider
- Provides the default implementation of all crypto interfaces
- Wires Go primitives with Rust FFI calls for performance-critical paths

### `shredder.go` — Secure Deletion
- Memory zeroization with compiler optimization barriers (`runtime.KeepAlive`)
- Disk wipe support via direct file overwrite patterns
- Verification step to confirm all bytes were zeroized

---

## Go Security Layer Details

### `audit.go` — Cryptographic Audit Log
- Immutable, append-only log with SHA-256 hash chaining
- Each entry: `SHA-256(prevHash || timestamp || level || module || message || subjectID)`
- Tampering detectable: any modification breaks the hash chain
- Logged events: login attempts, lockdown triggers, key operations, policy violations

### `constant_time.go` — Timing-Attack Protection
- Constant-time byte and string comparisons
- Prevents timing side-channel leakage during password/coordinate verification
- All comparison paths execute the same number of CPU instructions

### `integrity.go` — Binary Integrity Verification
- Hashes the executing binary at startup and periodically (30-second heartbeat)
- Compares against a known-good hash stored in the vault header
- Watchdog triggers kernel restart if hash mismatch is detected

### `lockdown.go` — Security Lockdown State Machine
- 3 failed attempts → 200-minute lockdown window
- During lockdown, only coordinate-based override is allowed (4 attempts max)
- 4 failed overrides or timeout → hard wipe (self-destruct)
- State persisted in `.gdb` header across reboots

### `memlock.go` — Memory Locking Interface
- Cross-platform abstraction over mlock/VirtualLock
- Fallback strategies for platforms without direct support
- Configuration for lock limits (RLIMIT_MEMLOCK on Unix)

### `memlock_unix.go` — Unix Implementation
- `mlock()` syscall via `golang.org/x/sys/unix`
- Locks all pages containing a buffer into physical RAM
- Prevents sensitive data from being written to swap

### `memlock_windows.go` — Windows Implementation
- `VirtualLock()` via `golang.org/x/sys/windows`
- Equivalent semantics to Unix mlock
- Requires `SeLockMemoryPrivilege` for large allocations

### `module.go` — Security Module Registration
- Registers the security module with the GrimDB kernel
- Handles event subscriptions: `AUTH.ATTEMPT`, `AUTH.LOCKDOWN`, `SECURITY.AUDIT`, `SECURITY.WIPE`
- Coordinates between audit, lockdown, integrity, and session subsystems

### `session.go` — Session & Key Lifecycle
- Manages ephemeral session keys derived from the master key
- Automatic expiry and re-derivation on timeout
- Zeroization of session keys on logout, timeout, or lockdown
- Tracks active sessions for the watchdog

---

## CGO Bridge

### `rustbridge.go` — Go-Rust FFI
- CGO bindings that load `libgrimlocker_core` (compiled Rust cdylib)
- Type-safe Go wrappers around all `extern "C"` functions
- Memory management: Go allocates buffers, Rust fills/encrypts/zeroizes them
- Error translation from Rust error codes to Go errors
- Build linkage: `// #cgo LDFLAGS: -L${SRCDIR}/../../core-rust/target/release -lgrimlocker_core`

---

## Code Review Guide

Security auditors should focus on these areas:

### 1. Constant-Time Operations
- [ ] `grimdb/security/constant_time.go`: Verify all comparison paths execute identically
- [ ] `core-rust/src/lib.rs`: Confirm `subtle::ConstantTimeEq` usage
- [ ] Check that password verification never short-circuits on mismatch

### 2. Memory Safety (Rust)
- [ ] `core-rust/src/crypto.rs`: Verify `unsafe` blocks are sound and minimal
- [ ] `core-rust/src/enclave.rs`: Check guard page allocation/deallocation
- [ ] `core-rust/src/wipe.rs`: Confirm `zeroize` crate usage after each `unsafe` block

### 3. Key Material Lifecycle
- [ ] `grimdb/security/session.go`: Verify keys are zeroized on all exit paths
- [ ] `grimdb/crypto/engine.go`: Check key derivation does not leave intermediate material
- [ ] `core-rust/src/lib.rs`: Confirm all FFI functions zeroize before returning

### 4. Cryptographic Correctness
- [ ] `grimdb/crypto/argon.go`: Verify Argon2id parameters (32 MiB, 3 iterations, 4 lanes)
- [ ] `grimdb/crypto/chacha.go`: Check nonce generation and reuse prevention
- [ ] `grimdb/crypto/hkdf.go`: Verify RFC 5869 compliance
- [ ] `core-rust/src/crypto.rs`: Confirm AEAD tag verification before decryption

### 5. Lockdown Logic
- [ ] `grimdb/security/lockdown.go`: Verify failed attempt counter overflow
- [ ] `grimdb/security/lockdown.go`: Confirm 200-minute window enforcement
- [ ] `core-rust/src/time_guard.rs`: Check dual-clock integrity edge cases

### 6. Error Handling
- [ ] No plaintext keys in error messages, logs, or stack traces
- [ ] No timing differences in error vs. success paths
- [ ] Proper lockdown escalation on cryptographic errors

---

## Build & Test

### Prerequisites

| Component | Version |
|---|---|
| Rust | 1.75+ |
| Go | 1.21+ |

### Build

```bash
# Build Rust crypto core
cd core-rust
cargo build --release
# Output: target/release/libgrimlocker_core.so (Linux) / .dylib (macOS) / .dll (Windows)

# Verify Go packages compile
cd ../grimdb
go build ./crypto/...
go build ./security/...
go build ./cgo
go build ./kernel
```

### Test

```bash
# Rust unit tests
cd core-rust
cargo test --release

# Go unit tests
cd ../grimdb
go test ./crypto/...
go test ./security/...

# Rust linting (memory safety)
cd ../core-rust
cargo clippy --release -- -D warnings

# Go linting
cd ../grimdb
golangci-lint run ./...
```

### Verifying Reproducibility

To confirm the public edition matches the private edition's crypto/security code:

```bash
# Compare Rust core (exclude coordinates.rs which is private-only)
diff -r grimlocker-private/core-rust/src/ grimlocker-public/core-rust/src/ \
  --exclude=coordinates.rs

# Compare Go crypto package
diff -r grimlocker-private/grimdb/crypto/ grimlocker-public/grimdb/crypto/

# Compare Go security package
diff -r grimlocker-private/grimdb/security/ grimlocker-public/grimdb/security/

# Compare CGO bridge
diff grimlocker-private/grimdb/cgo/rustbridge.go grimlocker-public/grimdb/cgo/rustbridge.go
```

All four diffs should produce **no output** (identical files).

---

## Complete System

The full Grimlocker system — including storage, API, UI, deployment configs, and enterprise tiering — is available in the private edition:

- **grimlocker-private**: Contains `core-rust`, full `grimdb` with all modules (storage, API, SDK, config, tools, deploy), and the `ui-layer` Tauri + React frontend.

---

## License

Grimlocker Core (crypto + security packages) is available under the license specified in the repository.

---

## Reporting Security Issues

If you discover a security vulnerability, please create a detailed issue in this repository. Include:

- Affected file(s) and line numbers
- Description of the vulnerability
- Potential impact
- Suggested fix (if known)

**Responsible disclosure is appreciated.** Critical vulnerabilities will be acknowledged within 48 hours.
