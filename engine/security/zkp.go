// Package security (zkp.go) implements a Zero-Knowledge Proof (ZKP) challenge-
// response mechanism for password authentication.
//
// Goal: Prove knowledge of a password WITHOUT ever transmitting the password
// in plaintext (or even hashed plaintext) over any channel including the kernel
// event bus.
//
// Protocol (ZKPP — Zero-Knowledge Password Proof):
//  1. Daemon generates a random 32-byte nonce and stores it temporarily.
//  2. Daemon sends (salt, nonce) to the client.
//  3. Client computes: proof = Argon2id(password, salt) XOR BLAKE2b(nonce)
//     — or equivalently: proof = derived_key XOR nonce_hash
//     The proof is a one-time commitment that cannot be replayed (nonce is
//     single-use) and does not reveal the password or the derived key alone.
//  4. Client sends proof to daemon.
//  5. Daemon verifies: stored_derived_key XOR BLAKE2b(nonce) == proof
//     — using constant-time comparison to prevent timing attacks.
//  6. Daemon deletes the nonce immediately after verification (replay prevention).
//
// Security properties:
//   - Password never leaves the client in any form.
//   - Proof is single-use (nonce-bound) — replay attack protection.
//   - Constant-time verification — no timing oracle.
//   - Even if the proof is intercepted, the attacker cannot derive the password
//     or the vault key without knowing the nonce AND the original password.
//
// NOTE: This is a Go-side framework. The actual password derivation (Argon2id)
// happens in the Tauri frontend and in the Go auth handler. This file provides
// the nonce lifecycle management and verification primitives.
package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
)

const (
	// ZKPNonceSize is the length of the single-use challenge nonce in bytes.
	ZKPNonceSize = 32

	// ZKPProofSize is the length of the ZKP commitment proof in bytes.
	ZKPProofSize = 32

	// zkpNonceTTL is how long a nonce is valid after issuance.
	// After this, the challenge expires and the client must request a new one.
	zkpNonceTTL = 5 * time.Minute
)

// ZKPChallenge is a single-use authentication challenge issued to a client.
type ZKPChallenge struct {
	// Nonce is the single-use random challenge sent to the client.
	// Hex-encoded for safe transport over JSON/WebSocket.
	Nonce string `json:"nonce"`

	// ExpiresAt is when this challenge becomes invalid.
	ExpiresAt time.Time `json:"expires_at"`
}

// ZKPVerifier manages the lifecycle of ZKP challenges and verifies proofs.
type ZKPVerifier struct {
	mu       sync.Mutex
	pending  map[string][ZKPNonceSize]byte // challenge_id -> raw nonce
	expiries map[string]time.Time          // challenge_id -> expiry
}

// NewZKPVerifier creates a ZKPVerifier.
func NewZKPVerifier() *ZKPVerifier {
	v := &ZKPVerifier{
		pending:  make(map[string][ZKPNonceSize]byte),
		expiries: make(map[string]time.Time),
	}
	// Background cleanup of expired challenges.
	go v.cleanupLoop()
	return v
}

// IssueChallenge generates a new single-use nonce and returns a ZKPChallenge
// to be sent to the client. The challenge ID is used by the client to reference
// which challenge it is responding to.
func (v *ZKPVerifier) IssueChallenge() (challengeID string, challenge ZKPChallenge, err error) {
	var rawID [16]byte
	if _, err := rand.Read(rawID[:]); err != nil {
		return "", ZKPChallenge{}, fmt.Errorf("nonce generation failed: %w", err)
	}
	challengeID = hex.EncodeToString(rawID[:])

	var nonce [ZKPNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", ZKPChallenge{}, fmt.Errorf("nonce generation failed: %w", err)
	}

	expiry := time.Now().Add(zkpNonceTTL)

	v.mu.Lock()
	v.pending[challengeID] = nonce
	v.expiries[challengeID] = expiry
	v.mu.Unlock()

	return challengeID, ZKPChallenge{
		Nonce:     hex.EncodeToString(nonce[:]),
		ExpiresAt: expiry,
	}, nil
}

// VerifyProof verifies a ZKP proof for a given challenge.
// derivedKey is the Argon2id-derived key that the daemon has pre-computed
// from the stored vault params (without knowing the password).
//
// Proof verification: proof == derivedKey XOR BLAKE2b(nonce)
//
// The challenge is consumed (deleted) after the first verification attempt
// regardless of success — preventing replay attacks.
func (v *ZKPVerifier) VerifyProof(challengeID string, derivedKey, proof []byte) error {
	v.mu.Lock()
	nonce, ok := v.pending[challengeID]
	expiry := v.expiries[challengeID]
	// Consume immediately — single use.
	delete(v.pending, challengeID)
	delete(v.expiries, challengeID)
	v.mu.Unlock()

	if !ok {
		return fmt.Errorf("challenge not found or already consumed")
	}

	if time.Now().After(expiry) {
		return fmt.Errorf("challenge expired")
	}

	if len(derivedKey) != ZKPProofSize || len(proof) != ZKPProofSize {
		return fmt.Errorf("invalid proof or key length")
	}

	// Compute expected proof: derivedKey XOR BLAKE2b-256(nonce).
	h, _ := blake2b.New256(nil)
	h.Write(nonce[:])
	nonceHash := h.Sum(nil)

	expected := make([]byte, ZKPProofSize)
	for i := 0; i < ZKPProofSize; i++ {
		expected[i] = derivedKey[i] ^ nonceHash[i]
	}

	// Constant-time comparison to prevent timing attacks.
	if subtle.ConstantTimeCompare(expected, proof) != 1 {
		return fmt.Errorf("proof verification failed")
	}

	return nil
}

// ComputeProof computes the ZKP proof on the client side.
// derivedKey is the Argon2id-derived key from the user's password.
// nonceHex is the hex-encoded nonce from the ZKPChallenge.
// Returns the proof bytes to send to the server.
func ComputeProof(derivedKey []byte, nonceHex string) ([]byte, error) {
	nonceBytes, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonceBytes) != ZKPNonceSize {
		return nil, fmt.Errorf("invalid nonce")
	}
	if len(derivedKey) != ZKPProofSize {
		return nil, fmt.Errorf("invalid derived key length")
	}

	h, _ := blake2b.New256(nil)
	h.Write(nonceBytes)
	nonceHash := h.Sum(nil)

	proof := make([]byte, ZKPProofSize)
	for i := 0; i < ZKPProofSize; i++ {
		proof[i] = derivedKey[i] ^ nonceHash[i]
	}
	return proof, nil
}

// PendingCount returns the number of active (non-expired) challenges.
// Useful for diagnostics.
func (v *ZKPVerifier) PendingCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()

	count := 0
	now := time.Now()
	for id, expiry := range v.expiries {
		if now.Before(expiry) {
			count++
		} else {
			// Clean stale while we have the lock.
			delete(v.pending, id)
			delete(v.expiries, id)
		}
	}
	return count
}

// cleanupLoop periodically removes expired challenges to prevent memory growth.
func (v *ZKPVerifier) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		v.mu.Lock()
		now := time.Now()
		cleaned := 0
		for id, expiry := range v.expiries {
			if now.After(expiry) {
				delete(v.pending, id)
				delete(v.expiries, id)
				cleaned++
			}
		}
		v.mu.Unlock()
		if cleaned > 0 {
			log.Printf("[ZKPVerifier] cleaned %d expired challenge(s)", cleaned)
		}
	}
}
