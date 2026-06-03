// Package crypto (pqc_ready.go) provides the post-quantum cryptography (PQC)
// framework and migration infrastructure for Grimlocker Omega+.
//
// Current state: AES-256-GCM and ChaCha20-Poly1305 are both considered
// quantum-safe for symmetric encryption (Grover's algorithm reduces effective
// key strength from 256 to 128 bits, which remains secure).
//
// Future migration path:
//   - Key Encapsulation: CRYSTALS-Kyber (NIST PQC standard, ML-KEM)
//   - Signatures:        CRYSTALS-Dilithium (NIST PQC standard, ML-DSA)
//   - Hybrid mode:       Classic ECDH + Kyber KEM (belt-and-suspenders during
//     transition; protects against both classical and quantum attacks)
//
// This file defines the PQCProvider interface and a PQCStatus report so the
// system can be queried at runtime about its post-quantum readiness. When PQC
// libraries become available in Go's standard ecosystem, implement the interface
// and swap via PQCProvider injection — no other code changes required.
//
// References:
//   - NIST FIPS 203 (ML-KEM / CRYSTALS-Kyber)
//   - NIST FIPS 204 (ML-DSA / CRYSTALS-Dilithium)
//   - NIST SP 800-227 (recommendations for key establishment)
package crypto

import "fmt"

// PQCAlgorithm identifies a post-quantum cryptographic algorithm.
type PQCAlgorithm string

const (
	// AlgoMLKEM768 is CRYSTALS-Kyber at the 192-bit security level (NIST ML-KEM-768).
	AlgoMLKEM768 PQCAlgorithm = "ML-KEM-768"

	// AlgoMLDSA65 is CRYSTALS-Dilithium at the 192-bit security level (NIST ML-DSA-65).
	AlgoMLDSA65 PQCAlgorithm = "ML-DSA-65"

	// AlgoHybridX25519MLKEM is the hybrid X25519 + ML-KEM key agreement recommended
	// during the classical-to-post-quantum migration period.
	AlgoHybridX25519MLKEM PQCAlgorithm = "X25519+ML-KEM-768"

	// AlgoChaCha20Poly1305 is the current symmetric algorithm (quantum-safe at 256-bit).
	AlgoChaCha20Poly1305 PQCAlgorithm = "ChaCha20-Poly1305"
)

// PQCSafetyLevel describes how well an algorithm resists quantum attacks.
type PQCSafetyLevel int

const (
	// PQCSafetyClassical means the algorithm is safe against classical computers
	// but would be broken by a sufficiently large quantum computer.
	PQCSafetyClassical PQCSafetyLevel = iota

	// PQCSafetyQuantumReduced means the algorithm retains security against quantum
	// attacks but at a reduced bit-strength (e.g. AES-256 → 128-bit against Grover).
	PQCSafetyQuantumReduced

	// PQCSafetyQuantumFull means the algorithm is specifically designed to resist
	// quantum attacks at its full advertised security level.
	PQCSafetyQuantumFull
)

// PQCStatus describes the post-quantum readiness of the current configuration.
type PQCStatus struct {
	// SymmetricAlgo is the symmetric encryption algorithm in use.
	SymmetricAlgo PQCAlgorithm `json:"symmetric_algo"`

	// SymmetricSafety is the quantum safety level of the symmetric algorithm.
	SymmetricSafety PQCSafetyLevel `json:"symmetric_safety"`

	// KEMAvailable reports whether a post-quantum Key Encapsulation Mechanism
	// is available in the current build.
	KEMAvailable bool `json:"kem_available"`

	// SigAvailable reports whether a post-quantum signature scheme is available.
	SigAvailable bool `json:"sig_available"`

	// HybridMode reports whether hybrid (classical + PQC) key agreement is active.
	HybridMode bool `json:"hybrid_mode"`

	// Notes contains human-readable guidance about the current PQC posture.
	Notes []string `json:"notes"`
}

// CurrentPQCStatus returns the post-quantum readiness of the current build.
// This is version 1 — classical algorithms only with quantum-safe symmetric crypto.
func CurrentPQCStatus() PQCStatus {
	return PQCStatus{
		SymmetricAlgo:   AlgoChaCha20Poly1305,
		SymmetricSafety: PQCSafetyQuantumReduced,
		KEMAvailable:    false,
		SigAvailable:    false,
		HybridMode:      false,
		Notes: []string{
			"ChaCha20-Poly1305 with 256-bit keys is quantum-safe for symmetric operations " +
				"(Grover's algorithm reduces effective strength to 128 bits — still secure).",
			"Key encapsulation (ML-KEM / CRYSTALS-Kyber) is not yet integrated. " +
				"When available, enable HybridMode for X25519 + ML-KEM key agreement.",
			"Signature scheme (ML-DSA / CRYSTALS-Dilithium) is not yet integrated.",
			"Migration path: implement PQCProvider interface and inject via SetPQCProvider().",
		},
	}
}

// PQCProvider is the interface for post-quantum cryptographic operations.
// Implement this interface when ML-KEM / ML-DSA libraries become available
// in the Go ecosystem, then inject via a future SetPQCProvider() call.
type PQCProvider interface {
	// GenerateKEMKeyPair generates a KEM key pair (public + private).
	GenerateKEMKeyPair() (publicKey, privateKey []byte, err error)

	// Encapsulate generates a shared secret and its ciphertext using the
	// recipient's public key. The sender transmits ciphertext; the shared
	// secret is used to derive the symmetric encryption key.
	Encapsulate(publicKey []byte) (ciphertext, sharedSecret []byte, err error)

	// Decapsulate recovers the shared secret from a ciphertext using the
	// recipient's private key.
	Decapsulate(privateKey, ciphertext []byte) (sharedSecret []byte, err error)

	// Algorithm returns the algorithm identifier for this provider.
	Algorithm() PQCAlgorithm
}

// notImplementedPQCProvider is a placeholder that returns clear error messages.
// Replace with a real implementation when an ML-KEM library is available.
type notImplementedPQCProvider struct{}

func (n *notImplementedPQCProvider) GenerateKEMKeyPair() ([]byte, []byte, error) {
	return nil, nil, fmt.Errorf("PQC not yet implemented — see crypto/pqc_ready.go migration notes")
}

func (n *notImplementedPQCProvider) Encapsulate([]byte) ([]byte, []byte, error) {
	return nil, nil, fmt.Errorf("PQC not yet implemented — see crypto/pqc_ready.go migration notes")
}

func (n *notImplementedPQCProvider) Decapsulate([]byte, []byte) ([]byte, error) {
	return nil, fmt.Errorf("PQC not yet implemented — see crypto/pqc_ready.go migration notes")
}

func (n *notImplementedPQCProvider) Algorithm() PQCAlgorithm { return "" }

// DefaultPQCProvider returns the current (not-yet-implemented) PQC provider.
// Replace the return value with a real implementation when available.
func DefaultPQCProvider() PQCProvider {
	return &notImplementedPQCProvider{}
}
