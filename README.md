# Grimlocker Core Engine — Security Audit Edition

[![Go 1.25+](https://img.shields.io/badge/Go-1.25+-00ADD8)](https://go.dev)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

> **Transparent Core, Trusted Appliance.**  
> This repository contains the publicly auditable cryptographic engine of Grimlocker — a zero-trust vault daemon.  
> The full appliance (storage format, network layer, OS integration) remains proprietary.

---

## Philosophy

Grimlocker follows a **"Transparent Core, Trusted Appliance"** security model:

| Layer | Status | Purpose |
|-------|--------|---------|
| **Core Engine** (`engine/`) | ✅ **Public** | ChaCha20-Poly1305 encryption, Argon2id KDF, GQL binary protocol, security state machine, kernel event bus. **Audit this.** |
| **Rust Enclave** (`core-rust/`) | ✅ **Public** | Hardware-backed secure zeroization, BLAKE3→HKDF coordinate derivation. |
| **Storage Layer** (`engine/storage/`) | ❌ **Private** | Vault on-disk format — kept proprietary to prevent format-specific attacks. |
| **Appliance** (`daemon/`) | ❌ **Private** | HTTP/WebSocket servers, OS hooks, sync, config — proprietary integration logic. |

**Why not fully open source?** The vault's on-disk format and the daemon's operational orchestration are kept proprietary. This prevents mass-exploitation of the specific storage format and protects the intellectual property of the appliance's operational logic — while the cryptographic core remains fully transparent for third-party audit.

---

## What's in This Repo

### `engine/` — Go Core Engine

| Package | Description | Tests | Dependencies |
|---------|-------------|-------|-------------|
| `engine/crypto/` | ChaCha20-Poly1305 AEAD, Argon2id KDF, HKDF, entropy coordinate derivation, secure shredder, PQC stubs | — | `golang.org/x/crypto` |
| `engine/security/` | Session lifecycle, lockdown manager, audit log (tamper-evident), MVK store, ZKP challenges, rate limiter, intrusion detection | — | `golang.org/x/crypto` |
| `engine/gql/` | GrimQueryLanguage — binary frame protocol, two-stage validator (syntactic + ACL), **total injection immunity** | ✅ Fuzz-tested | stdlib only |
| `engine/kernel/` | Event bus, dispatcher, module registry, handler builder with panic recovery + logging | ✅ Tested | stdlib only |
| `engine/errors/` | Typed error system (GrimlockError), structured logging, stack traces, HTTP status mapping | ✅ Tested | stdlib only |
| `engine/tools/` | Ed25519 SSH key generation (OpenSSH format, passphrase encryption) | ✅ Tested | `golang.org/x/crypto` |
| `engine/bridge/` | RustBridge interface — abstraction over the Rust secure enclave (pure Go fallback) | — | stdlib only |
| `engine/provider/` | Hexagonal port interfaces — `VaultProvider`, `AuthProvider`, `StorageProvider` | — | stdlib only |
| `engine/storage/` | BlockStore interface, transactional extensions, block types (minimal — no implementation) | — | stdlib only |

### `core-rust/` — Rust Secure Enclave

The Rust crate `grimlocker-core` provides:
- **Secure memory zeroization** (7-pass, compiler-resistant)
- **BLAKE3→HKDF coordinate derivation**
- **ChaCha20-Poly1305 session key encryption**

Built as a cdylib for runtime loading (Windows: `LoadLibrary`, Unix: `dlopen`).

---

## Build & Test

### Prerequisites

- Go 1.25+
- Rust toolchain (optional — only for the enclave crate)

### Build

```bash
go build ./engine/...
```

All 9 engine packages compile. No external dependencies beyond `golang.org/x/crypto`.

### Test

```bash
go test ./engine/...
```

```
ok  engine/errors   0.761s
ok  engine/gql      0.602s   (includes 10,000-iteration fuzz test)
ok  engine/kernel   0.604s
ok  engine/tools    0.937s
```

### Rust Enclave (optional)

```bash
cd core-rust
cargo build --release
```

---

## Security Properties (Auditable in this Repo)

| Property | Where to Verify |
|----------|-----------------|
| **AEAD encryption** | `engine/crypto/chacha.go` — ChaCha20-Poly1305 via `x/crypto` |
| **Key derivation** | `engine/crypto/argon.go` — Argon2id (128MB, 4 iterations, OWASP 2023+) |
| **Entropy coordinate system** | `engine/crypto/coordinate.go` — HKDF-based offset derivation |
| **Secure memory zeroization** | `engine/crypto/provider.go` + `core-rust/src/wipe.rs` |
| **Session state machine** | `engine/security/session.go` — unlock/lock lifecycle |
| **Brute-force protection** | `engine/security/lockdown.go` — exponential backoff → hard lockdown |
| **Tamper-evident audit log** | `engine/security/audit.go` — SHA-256 chained hashes |
| **Injection immunity** | `engine/gql/validator.go` — two-stage binary validation |
| **Binary protocol** | `engine/gql/frame.go` — length-prefixed, no text parsing |
| **Event bus** | `engine/kernel/bus.go` — gated channels, timeout-safe dispatch |
| **Error safety** | `engine/errors/types.go` — typed codes, stack traces, no info leakage |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Public (this repo)                │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────┐  ┌─────────┐  │
│  │  Crypto   │  │ Security │  │ GQL  │  │  Kernel  │  │
│  │  ChaCha20 │  │ Session  │  │Frame │  │ Event Bus│  │
│  │  Argon2id │  │ Lockdown │  │Valid.│  │ Registry │  │
│  │  HKDF     │  │ Audit    │  │Fuzzer│  │ Handlers │  │
│  └────┬─────┘  └────┬─────┘  └──┬───┘  └────┬─────┘  │
│       │              │           │            │         │
│       └──────────────┴───────────┴────────────┘         │
│                          │                              │
├──────────────────────────┴──────────────────────────────┤
│                    Private                               │
│                                                          │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ Storage  │  │  Appliance   │  │  UI (Tauri)       │  │
│  │ Vault    │  │  HTTP/WS     │  │  React Dashboard  │  │
│  │ On-Disk  │  │  OS Hooks    │  │  IPC Bridge       │  │
│  │ Format   │  │  Config      │  │                   │  │
│  └──────────┘  └──────────────┘  └───────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

The **public engine** defines interfaces that the **private appliance** implements. The appliance never sees passwords — only pre-hashed `[]byte`. The engine never opens files — only abstract handles. The boundary is enforced by Go's `internal/` package rule.

---

## Verification

You can verify this public repository matches the private audited codebase:

```bash
# Clone both repos
git clone https://github.com/potionodevil/grimlocker-public.git
git clone https://github.com/potionodevil/grimlocker-private.git

# Diff the public engine against the private engine (excluding storage/)
diff -r grimlocker-public/engine grimlocker-private/grimdb/engine \
  --exclude=storage
```

The only diff should be the module path (`grimdb` → `grimdb-public`) and the excluded `storage/` package.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for security vulnerability disclosure.

This is an **audit-focused** repository. We welcome:
- Cryptographic review
- Fuzzing of the GQL protocol
- Analysis of the security state machine
- Side-channel evaluations

We do **not** accept pull requests for new features or the storage/daemon layers — those remain proprietary.

---

## License

MIT — see [LICENSE](LICENSE).
