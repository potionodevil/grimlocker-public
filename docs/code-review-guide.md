# Code Review Guide — Grimlocker Security Audit Edition

This guide walks security researchers and auditors through a structured review of the Grimlocker cryptographic and security codebase. Each section identifies what to look for, where to find it, and what constitutes a correct implementation.

---

## Table of Contents

1. [Review Methodology](#review-methodology)
2. [Rust Crypto Enclave](#rust-crypto-enclave)
3. [Go Crypto Engine](#go-crypto-engine)
4. [Go Security Layer](#go-security-layer)
5. [CGO FFI Bridge](#cgo-ffi-bridge)
6. [Integration Points](#integration-points)
7. [Common Vulnerability Patterns](#common-vulnerability-patterns)
8. [Verification Checklist](#verification-checklist)

---

## Review Methodology

### Recommended Approach

1. **Start with the key hierarchy.** Understand how the master key is derived, stored, and used. This is the root of all trust.
2. **Trace a complete encrypt-decrypt cycle.** Follow data from plaintext through encryption to ciphertext and back.
3. **Review constant-time code paths.** All comparisons involving secrets must be constant-time.
4. **Trace key material lifecycle.** Every key byte must be zeroized before being freed or returned.
5. **Review the lockdown state machine.** Verify the state transitions and counter updates are correct.
6. **Check FFI boundaries.** Memory passed between Go and Rust must be correctly managed.

### Repository Map for Auditors

```
grimlocker-public/
├── core-rust/src/
│   ├── crypto.rs        ← Core crypto: ChaCha, BLAKE3, mlock, zeroize
│   ├── enclave.rs       ← Memory enclave: allocation lifecycle
│   ├── lib.rs           ← C-ABI exports: all FFI entry points
│   ├── main.rs          ← CLI: not security-critical (reference only)
│   ├── time_guard.rs    ← Dual-clock integrity
│   └── wipe.rs          ← 7-pass anti-forensic shredder
│
└── grimdb/
    ├── crypto/
    │   ├── argon.go     ← Argon2id password hashing
    │   ├── chacha.go    ← ChaCha20-Poly1305 AEAD
    │   ├── engine.go    ← Central crypto coordinator
    │   └── hkdf.go      ← HKDF-SHA256 key derivation
    │
    ├── security/
    │   ├── lockdown.go  ← Lockdown state machine
    │   ├── audit.go     ← Audit log with hash chaining
    │   ├── constant_time.go ← Constant-time primitives
    │   └── session.go   ← Key lifecycle management
    │
    └── cgo/
        └── rustbridge.go ← Go-Rust FFI bridge
```

---

## Rust Crypto Enclave

### `crypto.rs` — Cryptographic Operations

**What to verify:**

1. **ChaCha20-Poly1305 usage**
   - [ ] The `chacha20poly1305` crate is used correctly
   - [ ] Nonce is generated via CSPRNG (not counter, not hardcoded)
   - [ ] Nonce is 12 bytes (96 bits) as specified in RFC 8439
   - [ ] Authentication tag is verified before returning plaintext from decryption
   - [ ] No plaintext is returned if tag verification fails

2. **BLAKE3 usage**
   - [ ] Used only for key derivation, not password hashing
   - [ ] Input is always a strong key (32 bytes), not a low-entropy value

3. **Memory locking (mlock/VirtualLock)**
   - [ ] All buffers containing key material are locked
   - [ ] Lock is applied before writing key material
   - [ ] Unlock happens after zeroization (order: zeroize → unlock → free)

4. **Zeroization**
   - [ ] `zeroize` crate is used, not manual zeroing (compiler optimization may remove manual zeroing)
   - [ ] Zeroization occurs on every exit path, including error paths
   - [ ] `Drop` trait implements zeroization for heap-allocated key material

5. **Guard pages**
   - [ ] `mmap(PROT_NONE)` pages exist before and after sensitive allocations
   - [ ] Pages are unmapped (not just unprotected) on deallocation

**Common issues to look for:**
- Missing zeroization in error paths
- Nonce reuse due to counter or predictable generation
- Forgetting to verify the Poly1305 tag before decryption
- Using `memset` to zero (can be optimized away by compiler)

---

### `lib.rs` — C-ABI FFI Exports

**What to verify:**

1. **Pointer validation**
   - [ ] Every `*const T` and `*mut T` parameter is null-checked before use
   - [ ] Length parameters are validated against actual buffer sizes
   - [ ] `is_null()` check is the first operation in each FFI function

2. **Return value conventions**
   - [ ] `i32` return codes are documented: 0 = success, negative = error
   - [ ] Error codes are consistent across all functions
   - [ ] Partial outputs never returned on error (zeroize first)

3. **Thread safety**
   - [ ] No global mutable state (or properly synchronized)
   - [ ] FFI functions are reentrant
   - [ ] No `unsafe` blocks accessing global state without synchronization

4. **`unsafe` usage**
   - [ ] Every `unsafe` block has a `// SAFETY:` comment
   - [ ] `unsafe` blocks are minimal (few lines, not entire functions)
   - [ ] `std::slice::from_raw_parts` is used with correct length derivation
   - [ ] No data races possible in `unsafe` blocks

**Common issues to look for:**
- Missing null pointer checks
- Buffer overreads from incorrect length parameters
- Use-after-free if caller frees buffer while Rust still holds a reference
- Returning pointers to stack-allocated data

---

### `wipe.rs` — Anti-Forensic Shredder

**What to verify:**

1. **Overwrite sequence**
   - [ ] Exactly 7 passes as documented
   - [ ] Each pass uses fresh CSPRNG data (from `/dev/urandom` or `OsRng`)
   - [ ] Each pass writes exactly `file_size` bytes
   - [ ] `fsync` or `FlushFileBuffers` called after each pass

2. **File operations**
   - [ ] File is opened with write access (not append)
   - [ ] Seek position reset to 0 before each pass
   - [ ] File truncated to 0 before final unlink
   - [ ] Unlink happens after all overwrites complete

3. **Error handling**
   - [ ] Partial writes are detected and retried
   - [ ] Wipe continues even if individual pass fails (best-effort)
   - [ ] No crash if file is already deleted

**Common issues to look for:**
- Using the same random data for all passes (pattern detectable by forensic tools)
- Skipping `fsync` (data may remain in OS buffer)
- Not handling filesystem errors gracefully

---

### `time_guard.rs` — Dual-Clock Integrity

**What to verify:**

1. **Monotonic clock**
   - [ ] Uses `std::time::Instant` (not `SystemTime`) for the lockdown timer
   - [ ] `Instant::elapsed()` used correctly
   - [ ] Subtraction never panics on underflow

2. **Wall-clock cross-check**
   - [ ] `wallclock_last_seen` is updated atomically
   - [ ] `current_wallclock < last_seen_wallclock` triggers wipe (rollback detected)
   - [ ] Wall-clock jump > 1 year triggers wipe (anomalous)

3. **Tick-to-wall mapping**
   - [ ] On first call, maps current monotonic ticks to current wallclock
   - [ ] Uses this mapping to derive elapsed time in real seconds
   - [ ] Handles overflow of 64-bit monotonic counter correctly

**Common issues to look for:**
- Using `SystemTime` where `Instant` should be used
- Integer overflow in tick arithmetic
- Race conditions between clock reads

---

## Go Crypto Engine

### `argon.go` — Password Hashing

**What to verify:**

1. **Algorithm selection**
   - [ ] Uses `argon2.IDKey` (Argon2id, not Argon2i or Argon2d)
   - [ ] Parameters match documentation: 32 MiB, 3 iterations, 4 parallelism
   - [ ] Salt is randomly generated per vault (via `crypto/rand`)

2. **Parameter validation**
   - [ ] Memory parameter is exactly 32 * 1024 KiB
   - [ ] Iteration count is at least 3
   - [ ] Parallelism is at least 4

3. **Output handling**
   - [ ] Returns exactly 32 bytes
   - [ ] Output is zeroized after use if stored in Go memory
   - [ ] Salt is stored (needed for re-derivation), but not logged

**Common issues to look for:**
- Using Argon2i (weaker against GPU attacks) when Argon2id is available
- Hardcoded salt
- Insufficient memory parameter (less than 32 MiB)
- Logging the derived key or intermediate values

---

### `chacha.go` — AEAD Encryption

**What to verify:**

1. **API usage**
   - [ ] Uses `chacha20poly1305.New(key)` correctly
   - [ ] `aead.Seal` / `aead.Open` with proper nonce extraction
   - [ ] Nonce is prepended to ciphertext: `[12-byte nonce][ciphertext + 16-byte tag]`

2. **Nonce management**
   - [ ] Generated via `crypto/rand.Read(nonce)`
   - [ ] Nonce size matches `aead.NonceSize()` (12 bytes)
   - [ ] No nonce reuse — each encryption creates a new nonce

3. **Decryption**
   - [ ] `aead.Open` errors are handled (tag verification failure)
   - [ ] Plaintext is never returned if `Open` returns an error
   - [ ] Decrypted data is zeroized after use

**Common issues to look for:**
- Reusing the same nonce for multiple encryptions (catastrophic failure)
- Not verifying the authentication tag before using decrypted data
- Using additional data (AD) parameter incorrectly

---

### `hkdf.go` — Key Derivation

**What to verify:**

1. **API usage**
   - [ ] Uses `hkdf.New(sha256.New, ikm, salt, info)` (RFC 5869 compliant)
   - [ ] Reads exactly 32 bytes from the reader
   - [ ] `io.ReadFull` is used (not `io.Read`)

2. **Parameter binding**
   - [ ] Salt is context-specific (workspace UUID, session ID)
   - [ ] Info parameter binds the key to its purpose
   - [ ] No two derivations use the same (salt, info) pair

3. **IKM quality**
   - [ ] IKM is always a strong key (master key, extracted coordinates)
   - [ ] Never use low-entropy IKM (password goes through Argon2id first)

**Common issues to look for:**
- Using `io.Read` instead of `io.ReadFull` (may return fewer bytes)
- Reusing salt + info pairs for different key derivations
- Weak IKM (direct password without Argon2id)

---

## Go Security Layer

### `lockdown.go` — Lockdown State Machine

**What to verify:**

1. **State transitions**
   ```
   UNLOCKED → (fail) → failed_attempts++
   failed_attempts < 3 → (fail) → failed_attempts++ (retry allowed)
   failed_attempts >= 3 → LOCKDOWN (200-min window)
   LOCKDOWN → (correct coords) → UNLOCKED (counters reset)
   LOCKDOWN → (wrong coords × 4) → WIPE
   LOCKDOWN → (timeout 200min) → WIPE
   ```

2. **Counter integrity**
   - [ ] `failed_attempts` is atomic (no race conditions)
   - [ ] Counters are never negative
   - [ ] `override_attempts_left` decremented from 4, not reset mid-override

3. **Persistence**
   - [ ] Header is written atomically to `.gdb` after every state change
   - [ ] Previous header is not corrupted during write
   - [ ] Header reads are validated (checksum or sanity checks)

**Common issues to look for:**
- Race condition between counter read and write
- Overflow of the `failed_attempts` counter (uint8, max 255)
- Failing to persist state before zeroizing keys (keys gone before state saved)
- Integer overflow in timestamp math

---

### `constant_time.go` — Constant-Time Operations

**What to verify:**

1. **Implementation**
   - [ ] Uses `crypto/subtle.ConstantTimeCompare` (Go standard library)
   - [ ] Never uses `bytes.Equal` for security-sensitive comparisons
   - [ ] Never uses `==` for `[]byte` comparison

2. **Usage audit**
   - [ ] Password verification uses constant-time comparison
   - [ ] Coordinate verification uses constant-time comparison
   - [ ] Token/key comparison uses constant-time comparison
   - [ ] Any code path that could reveal "how many bytes matched"

3. **Error paths**
   - [ ] Error returns occur AFTER the comparison (not early-return on mismatch)
   - [ ] Error messages do not reveal byte position of mismatch

**Common issues to look for:**
- Early return on first byte mismatch
- Using `bytes.Equal` or `reflect.DeepEqual` for secrets
- Different code paths for success vs. failure (timing difference)

---

### `audit.go` — Audit Log

**What to verify:**

1. **Hash chaining**
   - [ ] Each entry includes `SHA-256(prevHash || timestamp || level || module || message || subjectID)`
   - [ ] First entry uses zero-hash as `prevHash`
   - [ ] Any modification to an entry breaks all subsequent hashes

2. **Completeness**
   - [ ] All security events are logged (no silent operations)
   - [ ] Failed operations are logged alongside successful ones
   - [ ] Audit log cannot be truncated without detection

3. **Access**
   - [ ] Audit log is append-only at runtime
   - [ ] Audit log cannot be accessed via WebSocket/API (defense against remote attackers)
   - [ ] Audit log is plain-text accessible for local review

**Common issues to look for:**
- Hash chaining that can be recomputed after tampering
- Missing events (operations without audit entries)
- Hash computation that omits critical fields (e.g., missing timestamp)

---

### `session.go` — Key Lifecycle

**What to verify:**

1. **Key derivation**
   - [ ] Session keys derived via BLAKE3(master) → HKDF(session_id)
   - [ ] Each session gets a unique key
   - [ ] Keys are never derived from predictable session IDs

2. **Key storage**
   - [ ] Session keys stored in Rust's locked memory (handle system)
   - [ ] Go holds only handles (not raw key bytes)
   - [ ] Keys never serialized or stored on disk

3. **Key destruction**
   - [ ] All exit paths zeroize session keys: logout, timeout, lockdown, crash
   - [ ] Panic recovery calls zeroization before re-panicking
   - [ ] Deferred cleanup ensures zeroization even on early return

**Common issues to look for:**
- Session keys stored in Go heap
- Forgetting zeroization in error/defer paths
- Session ID reuse leading to key reuse
- Panic not caught during key operations

---

## CGO FFI Bridge

### `rustbridge.go` — Go-Rust Bridge

**What to verify:**

1. **Memory management**
   - [ ] Go-allocated buffers via `C.malloc` are freed with `C.free`
   - [ ] Rust-allocated output buffers are freed by Go after use
   - [ ] No Go garbage collector manages memory that Rust holds references to
   - [ ] `runtime.KeepAlive()` used where Go GC might collect prematurely

2. **Data flow**
   - [ ] Plaintext data goes Go → CGO → Rust, never the reverse
   - [ ] Encrypted data goes Rust → CGO → Go
   - [ ] Keys never appear in Go memory as raw bytes

3. **Error translation**
   - [ ] Rust error codes are properly mapped to Go errors
   - [ ] No information leakage through error codes
   - [ ] Error returns trigger zeroization in Go

4. **Build configuration**
   - [ ] `// #cgo LDFLAGS:` correctly points to the Rust library
   - [ ] Cross-compilation paths are correct for all target platforms

**Common issues to look for:**
- Memory leak: `C.malloc` without corresponding `C.free`
- Use-after-free: Go holds pointer after `C.free`
- Double-free: both Go and Rust try to free the same buffer
- GC collecting buffer that CGO is still using

---

## Integration Points

### Key Derivation Chain (End-to-End)

Trace a complete key derivation and verify each step:

```
1. User enters password
   → Argon2id(password, salt) → Master Key (Go side, but immediate transfer to Rust)
   
2. Master Key used to derive Workspace Key
   → BLAKE3(MK) → HKDF-SHA256(..., workspaceUUID) → Workspace Key (Rust side)

3. Workspace Key used to encrypt an entry
   → ChaCha20-Poly1305(key, nonce, plaintext) → ciphertext (Rust → Go for storage)

4. Entry readback
   → Go reads ciphertext from disk → passes to Rust
   → ChaCha20-Poly1305(key, nonce, ciphertext) → plaintext (Rust side, never returned to Go)
```

Verify at each step:
- [ ] Keys are in the correct memory space (Rust for all key material)
- [ ] Zeroization happens after each use
- [ ] No intermediate key material is leaked in logs or errors
- [ ] Nonces are unique and random

### Lockdown + Wipe Integration

Trace a complete lockdown → wipe cycle:

```
1. 3 failed attempts → Lockdown
   - [ ] Header correctly updated with lockdown_timestamp
   - [ ] All session keys zeroized
   - [ ] VFS unmounted
   
2. 4 failed coordinate overrides → Wipe
   - [ ] Header shows override_attempts_left = 0
   - [ ] 7-pass shredder invoked
   - [ ] .gdb deleted
   - [ ] Daemon exits or returns to initial state
   
3. Panic-key (0,0,0) → Disguised Wipe
   - [ ] Fake success messages displayed
   - [ ] Background shredding occurs
   - [ ] Normal-looking UI state maintained
```

---

## Common Vulnerability Patterns

### Pattern 1: Non-Constant-Time Comparison

```go
// VULNERABLE
if bytes.Equal(submittedPassword, storedHash) {
    return nil // Quick return on match
}
return errors.New("incorrect password") // Slower return on mismatch
// Timing difference reveals password correctness
```

```go
// CORRECT
match := subtle.ConstantTimeCompare(submittedPassword, storedHash) == 1
// Always execute this code path
if !match {
    return errors.New("incorrect password")
}
return nil
```

### Pattern 2: Premature Zeroization or Missing Zeroization

```rust
// VULNERABLE: error path misses zeroization
let mut key = [0u8; 32];
generate_key(&mut key);
let result = encrypt(&key, plaintext);
if result.is_err() {
    return Err(result.unwrap_err()); // key not zeroized!
}
key.zeroize();
```

```rust
// CORRECT: zeroize in all paths
let mut key = [0u8; 32];
generate_key(&mut key);
let result = encrypt(&key, plaintext);
key.zeroize(); // Always zeroize, regardless of result
result
```

### Pattern 3: Nonce Reuse

```go
// VULNERABLE: counter-based nonce
var nonceCounter uint64
binary.BigEndian.PutUint64(nonce[4:], nonceCounter)
nonceCounter++ // If this overflows or resets, nonces repeat
```

```go
// CORRECT: random nonce
nonce := make([]byte, aead.NonceSize())
crypto.rand.Read(nonce) // CSPRNG ensures uniqueness
```

### Pattern 4: Key Material in Go Memory

```go
// VULNERABLE: raw key in Go heap
masterKey := argon2.IDKey(password, salt, 3, 32*1024, 4, 32)
// masterKey is in Go GC-managed memory — can be copied, paged, etc.

// CORRECT: key derived via CGO and held in Rust
handle := cgo.DeriveMasterKey(password, salt)
// handle is just an integer; actual key never in Go memory
```

---

## Verification Checklist

### Rust Core (`core-rust/`)

- [ ] All `unsafe` blocks have `// SAFETY:` comments
- [ ] All FFI functions validate null pointers
- [ ] `zeroize` used on every key-material path
- [ ] `mlock`/`VirtualLock` applied to all sensitive buffers
- [ ] Guard pages surrounding sensitive allocations
- [ ] Nonce generation via CSPRNG (not counter)
- [ ] Poly1305 tag verified before returning plaintext
- [ ] `Instant` used for lockdown timer (not `SystemTime`)
- [ ] Wall-clock regression triggers wipe
- [ ] 7 distinct pass of CSPRNG data in shredder
- [ ] `fsync` after each shredder pass
- [ ] `clippy` passes with `-D warnings`

### Go Crypto (`grimdb/crypto/`)

- [ ] Argon2id with 32 MiB, 3 iterations, 4 parallelism
- [ ] Salt generated per vault (not hardcoded)
- [ ] Nonce generated per encryption (not reused)
- [ ] `aead.Open` error handled (tag verification)
- [ ] HKDF uses `io.ReadFull` (not `io.Read`)
- [ ] Salt + info unique per derivation
- [ ] IKM always a strong key

### Go Security (`grimdb/security/`)

- [ ] `crypto/subtle.ConstantTimeCompare` for all secret comparisons
- [ ] No `bytes.Equal` on secret data
- [ ] Lockdown counter updates are atomic
- [ ] Header written atomically to `.gdb`
- [ ] Audit log uses SHA-256 chaining
- [ ] All security events are logged
- [ ] Session keys zeroized on all exit paths

### CGO Bridge (`grimdb/cgo/`)

- [ ] `C.malloc` paired with `C.free`
- [ ] No raw key bytes in Go heap
- [ ] `runtime.KeepAlive` used where needed
- [ ] Error codes properly mapped
- [ ] Build flags correct for all platforms

### General

- [ ] No plaintext keys in logs, errors, or comments
- [ ] No hardcoded secrets or keys
- [ ] No debug code exposing security-critical state
- [ ] All tests pass (`cargo test`, `go test`)
- [ ] No compiler/linter warnings
