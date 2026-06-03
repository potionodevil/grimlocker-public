// Package security (secret_guard.go) implements SecretGuard — a thread-safe
// store for short-lived secrets (passwords, keys, tokens) that must be
// zeroed from memory as soon as they are no longer needed.
//
// Every secret is stored in a named slot. Calling Wipe or WipeAll overwrites
// the backing byte slice with zeros before releasing the reference. This limits
// the window in which a memory dump or GC scan could recover secret material.
//
// SecretGuard is not a substitute for mlock'd memory (see MemoryGuard) — it
// lives in the Go heap and can in principle be paged. Use it for short-lived
// transients (e.g. a password held between receive and derivation). For
// persistent key material (MVK, session keys) use MemoryGuard.AllocLocked.
package security

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"sync"
)

// SecretGuard provides a thread-safe store for short-lived secret byte slices.
// Each secret is identified by an opaque nonce token returned by Store.
// Secrets are zeroed on Wipe or WipeAll.
type SecretGuard struct {
	mu    sync.Mutex
	slots map[string][]byte
}

// NewSecretGuard creates an empty SecretGuard.
func NewSecretGuard() *SecretGuard {
	return &SecretGuard{
		slots: make(map[string][]byte),
	}
}

// Store saves a copy of secret under a freshly generated random nonce and
// returns the nonce token. The caller must call Wipe(token) when done.
// The original secret slice is NOT zeroed by Store — that is the caller's
// responsibility.
func (g *SecretGuard) Store(secret []byte) (token string, err error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token = hex.EncodeToString(raw)

	// Store a copy so we own the memory.
	buf := make([]byte, len(secret))
	copy(buf, secret)

	g.mu.Lock()
	g.slots[token] = buf
	g.mu.Unlock()
	return token, nil
}

// Retrieve returns the secret for the given token (copy) and removes the slot.
// The returned slice should be zeroed by the caller after use.
// Returns (nil, false) if the token is unknown or already wiped.
func (g *SecretGuard) Retrieve(token string) ([]byte, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	buf, ok := g.slots[token]
	if !ok {
		return nil, false
	}
	// Return a copy and wipe the stored copy immediately.
	out := make([]byte, len(buf))
	copy(out, buf)
	zeroize(buf)
	delete(g.slots, token)
	return out, true
}

// Wipe zeros and removes the slot for the given token.
// Safe to call multiple times — subsequent calls are no-ops.
func (g *SecretGuard) Wipe(token string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if buf, ok := g.slots[token]; ok {
		zeroize(buf)
		delete(g.slots, token)
	}
}

// WipeAll zeros and removes all stored secrets.
// Call this during graceful shutdown or lockdown.
func (g *SecretGuard) WipeAll() {
	g.mu.Lock()
	defer g.mu.Unlock()

	count := len(g.slots)
	for token, buf := range g.slots {
		zeroize(buf)
		delete(g.slots, token)
	}
	if count > 0 {
		log.Printf("[SecretGuard] WipeAll — zeroed %d secret slots", count)
	}
}

// Count returns the number of currently stored secret slots (for diagnostics).
func (g *SecretGuard) Count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.slots)
}
