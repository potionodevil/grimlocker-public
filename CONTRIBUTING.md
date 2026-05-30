# Contributing to Grimlocker (Public Audit Edition)

Thank you for contributing to the security of Grimlocker. This repository exists specifically for community review, vulnerability discovery, and cryptographic validation.

---

## Ways to Contribute

### Security Vulnerability Reports

If you find a security vulnerability in the cryptographic or security code:

1. **Do NOT disclose publicly until confirmed fixed.** Use a responsible disclosure process.
2. Open a detailed GitHub issue with:
   - Affected file(s) and specific line numbers
   - Type of vulnerability (e.g., timing side-channel, buffer overflow, cryptographic weakness)
   - Reproduction steps or proof of concept
   - Potential impact assessment
   - Suggested fix (if known)
3. Label the issue with the appropriate severity.

**Response time**: Critical vulnerabilities acknowledged within 48 hours. Confirmed fixes deployed to the private repository and synced here within 7 days.

### Code Quality Improvements

Non-security improvements are also welcome:

- **Documentation**: Fixing typos, improving clarity, adding missing context
- **Test coverage**: Adding unit tests for edge cases
- **Build improvements**: Cross-platform compatibility, CI/CD suggestions
- **Code clarity**: Refactoring for readability (without changing security properties)

### What NOT to Submit

- **Feature requests** for storage, UI, API, or deployment — these belong to the private edition
- **Pull requests** that add new cryptographic primitives without prior discussion
- **Dependency updates** without explicit vulnerability justification

---

## Code Review Focus Areas

When reviewing code, prioritize these areas:

1. **Constant-time correctness** — Any comparison involving secrets (passwords, coordinates, keys)
2. **Memory safety** — Buffer lifetimes, zeroization on all exit paths, mlock/guard page usage
3. **Cryptographic algorithm usage** — Correct API usage, parameter validation, nonce management
4. **Error handling** — No information leakage in error messages, constant-time error paths
5. **FFI boundary** — Safe pointer handling between Go and Rust via CGO

---

## Reporting Format

### Security Vulnerability Report Template

```
### Summary
[Brief description of the vulnerability]

### Affected Code
- File: [path]
- Lines: [start-end]
- Component: [crypto / security / cgo / rust-core]

### Vulnerability Details
[Detailed technical description]

### Reproduction
[Step-by-step reproduction or proof of concept code]

### Impact
[What an attacker could achieve by exploiting this]

### Suggested Fix
[If you have one]

### Environment
- OS: [Linux/macOS/Windows]
- Rust version: [e.g., 1.75]
- Go version: [e.g., 1.21]
```

---

## Development Setup

If you want to build and test the code locally:

```bash
# Prerequisites
# Rust 1.75+, Go 1.21+

# Build Rust core
cd core-rust
cargo build --release
cargo test --release
cargo clippy --release -- -D warnings

# Build Go packages
cd ../grimdb
go mod tidy
go build ./crypto/...
go build ./security/...
go build ./cgo
go test ./crypto/...
go test ./security/...
golangci-lint run ./...
```

---

## Communication

- **GitHub Issues**: For all bug reports, vulnerability disclosures, and discussions
- **Discussions**: For questions about cryptographic design decisions and architecture
- **No private channels**: All technical discussions should be visible to the community

---

## Recognition

Security researchers who report valid vulnerabilities will be:
- Acknowledged in the repository (with permission)
- Listed in the security hall of fame (if one is maintained)
- Eligible for inclusion in future bug bounty programs

---

## Code of Conduct

- Be respectful and constructive
- Focus on the code, not the author
- Provide evidence for claims (citations, references, proofs of concept)
- Assume good faith in design decisions
