# Grimlocker - Security Audit Edition

**Transparente Crypto & Security Implementation für Code Review und Sicherheits-Analyse.**

## 🔍 Zweck

Dies ist die **public Version** von Grimlocker, die die kritischen Komponenten transparent macht:

- ✅ **Vollständige Crypto-Implementation** (Rust + Go)
- ✅ **Security-Layer Code** (Lockdown, Audit, Memory-Protection)
- ✅ **Rust Enclave** mit sicherer Key-Verwaltung
- ❌ Keine Storage/Database-Implementierung
- ❌ Keine UI/API-Implementierung
- ❌ Keine Credentials/Test-Daten

**Ziel**: Community-Auditierung zeigen, dass die Verschlüsselung und Sicherheit wirklich robust ist.

## 📦 Inhalt

```
grimlocker-public/
├── core-rust/              # Sichere Rust-Enclave
│   ├── src/
│   │   ├── crypto.rs       # ChaCha20-Poly1305, BLAKE3, HKDF
│   │   ├── enclave.rs      # Sichere Enclaves
│   │   ├── time_guard.rs   # Timing-Angriff-Schutz
│   │   ├── wipe.rs         # Sichere Memory-Verwischung
│   │   └── lib.rs          # FFI-Bindings
│   └── Cargo.toml          # Rust Dependencies
│
└── grimdb/
    ├── crypto/             # Go Crypto Engine
    │   ├── argon.go        # Password-Hashing (Argon2id)
    │   ├── chacha.go       # ChaCha20-Poly1305
    │   ├── coordinate.go   # Key Derivation (Coordinates)
    │   ├── entropy.go      # Sichere Zufallszahlenerzeugung
    │   ├── engine.go       # Crypto-Core
    │   ├── hkdf.go         # HKDF-SHA256
    │   └── shredder.go     # Sichere Speicher-Löschung
    │
    ├── security/           # Security Module
    │   ├── audit.go        # Sicherheits-Auditing
    │   ├── constant_time.go # Timing-Angriff-Schutz
    │   ├── integrity.go    # Binary-Integrität
    │   ├── lockdown.go     # Hard/Soft Lockdown
    │   ├── memlock*.go     # Memory-Locking (OS-spezifisch)
    │   └── session.go      # Session-Verwaltung
    │
    ├── cgo/
    │   └── rustbridge.go   # Go-Rust FFI-Bindings
    │
    ├── kernel/
    │   └── kernel.go       # Event-Bus Interfaces (minimal)
    │
    └── go.mod             # Go Dependencies
```

## 🔐 Sicherheits-Merkmale

### Kryptographie
- **Master Key Derivation**: Argon2id(password, salt) → 32 bytes
- **Workspace Keys**: BLAKE3(master) → HKDF-SHA256 → 32 bytes
- **Session Keys**: ChaCha20-Poly1305 aus Rust Enclave
- **Key Material Storage**: Nur locked memory oder Rust-Enclave

### Timing-Angriff-Schutz
- Constant-time Vergleiche in Go (constant_time.go)
- Rust Enclave: `subtle::ConstantTimeComparison`
- Password-Verifikation: Always takes same time

### Memory-Protection
- **mlock (Unix)**: Verhindert Paging sensible Daten
- **VirtualLock (Windows)**: Equivalent für Windows
- **Wipe on Logout**: Sichere Zeroize mit DoD-Pattern (core-rust/wipe.rs)
- **7-Pass Overwrite**: core-rust/wipe.rs

### Sicherheits-Lockdown
- **Hard Lockdown**: Alle Key Materials zeroized → Prozess exited
- **Soft Lockdown**: Temporäre Blockade, Recovery möglich
- **Audit-Log**: Alle Security-Events geloggt
- **Panic-Handler**: Automatischer Hard Lockdown bei kritischen Fehlern

## 🚀 Build & Test

### Rust-Core

```bash
cd core-rust
cargo build --release
cargo test --release

# Check für Memory Unsafety
cargo clippy --release
```

### Go-Crypto & Security

```bash
cd grimdb
go build ./crypto
go build ./security
go test ./crypto/...
go test ./security/...

# Security linting
golangci-lint run
```

## 📊 Code Review Schwerpunkte

### Was Sie überprüfen sollten:

1. **Constant-Time Operationen**
   - `grimdb/security/constant_time.go`: Timing-Angriff-Schutz
   - `core-rust/src/lib.rs`: Rust constant-time functions

2. **Memory-Sicherheit**
   - `core-rust/src/wipe.rs`: Sichere Speicher-Löschung
   - `grimdb/security/memlock*.go`: Memory-Locking
   - `grimdb/security/session.go`: Key Lifecycle

3. **Kryptographische Primitives**
   - `core-rust/src/crypto.rs`: ChaCha20-Poly1305, BLAKE3
   - `grimdb/crypto/argon.go`: Argon2id Parameter
   - `grimdb/crypto/hkdf.go`: HKDF-SHA256 Implementation

4. **Error Handling**
   - Keine Plaintext-Keys in Logs/Errors
   - Keine Timing-Leaks in Error-Paths
   - Proper Lockdown bei Fehlern

## 🔗 Vollständiges System

Das komplette Grimlocker-System (mit Storage, API, UI) ist in der **private Edition** verfügbar:
- GitHub: [grimlocker/grimlocker-private](https://github.com/grimlocker/grimlocker-private) (privat)

## 📝 Lizenz

Grimlocker Core (crypto + security) ist unter **[LICENSE]** verfügbar.

---

**Feedback & Security Issues**: Bitte erstellen Sie einen Issue in diesem Repository mit Details zu gefundenen Sicherheitsproblemen.
