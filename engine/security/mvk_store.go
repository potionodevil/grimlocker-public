package security

import (
	"crypto/rand"
	"fmt"
	"sync"

	gerrors "github.com/grimlocker/grimdb-public/engine/errors"
)

func randomHandle() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("security: CSPRNG failure during handle generation: %v", err))
	}
	return fmt.Sprintf("%x", b)
}

// ─── MVKStore Interface ───────────────────────────────────────────────────────

// MVKStore is the contract for storing, retrieving, and revoking Master Vault
// Key (MVK) material in locked memory. No other module holds actual key bytes —
// they interact with key material exclusively via opaque string handles.
//
// Implementors MUST:
//   - Allocate backing memory via the OS memory-locking API (mlock / VirtualLock)
//   - Zero key material on Revoke and on process exit
//   - Never copy key bytes to heap (return slices only for the current call frame)
type MVKStore interface {
	// Store allocates locked memory, copies key into it, and returns an opaque handle.
	// The original key slice should be zeroed by the caller after this returns.
	Store(key []byte) (handle string, err error)

	// Retrieve returns the raw key bytes for the given handle.
	// Returns (nil, false) if the handle is unknown or has been revoked.
	// IMPORTANT: callers MUST NOT hold the returned slice past the current call frame.
	Retrieve(handle string) (key []byte, ok bool)

	// Revoke zeroes and releases the locked memory for the given handle.
	// Silently ignores unknown handles.
	Revoke(handle string)

	// RevokeAll zeroes and releases all stored handles. Called during shutdown or lockdown.
	RevokeAll()

	// Handles returns the list of active handle strings (for audit purposes).
	// Never returns the key material itself.
	Handles() []string
}

// ─── lockedMVKStore — concrete implementation ─────────────────────────────────

// lockedMVKStore is the MVKStore implementation backed by MemoryGuard.
// It wraps the same locking mechanism as security.Module — use NewLockedMVKStore
// to create a standalone store, or use security.Module which embeds one internally.
type lockedMVKStore struct {
	mu      sync.RWMutex
	guard   MemoryGuard
	handles map[string][]byte // handle → locked memory slice
}

// NewLockedMVKStore creates a standalone MVKStore with the given MemoryGuard.
// Pass a platform-appropriate guard (e.g., NewMemoryGuard() from daemon/internal/security).
// The engine provides a default Go-only guard via NewGoMemoryGuard().
func NewLockedMVKStore(guard MemoryGuard) MVKStore {
	return &lockedMVKStore{
		guard:   guard,
		handles: make(map[string][]byte),
	}
}

// NewGoMemoryGuard returns a Go-only MemoryGuard that zeroizes bytes without
// OS-level memory locking. Used when the real MemoryGuard is not available
// (e.g., in the engine package where mlock is not accessible).
func NewGoMemoryGuard() MemoryGuard {
	return &goMemoryGuard{}
}

type goMemoryGuard struct{}

func (g *goMemoryGuard) Lock(b []byte) error                                            { return nil }
func (g *goMemoryGuard) Unlock(b []byte) error                                          { return nil }
func (g *goMemoryGuard) Zeroize(b []byte)                                               { zeroize(b) }
func (g *goMemoryGuard) CompareConstantTime(a, b []byte) bool                           { return constantTimeEqual(a, b) }
func (g *goMemoryGuard) AllocLocked(size int) ([]byte, error)                           { return make([]byte, size), nil }

func (s *lockedMVKStore) Store(key []byte) (string, error) {
	locked, err := s.guard.AllocLocked(len(key))
	if err != nil {
		return "", gerrors.NewSecurityMemlockError(err)
	}
	copy(locked, key)

	handle := randomHandle() // reuse from module.go
	s.mu.Lock()
	s.handles[handle] = locked
	s.mu.Unlock()
	return handle, nil
}

func (s *lockedMVKStore) Retrieve(handle string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.handles[handle]
	return key, ok
}

func (s *lockedMVKStore) Revoke(handle string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key, ok := s.handles[handle]; ok {
		s.guard.Zeroize(key)
		_ = s.guard.Unlock(key)
		delete(s.handles, handle)
	}
}

func (s *lockedMVKStore) RevokeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for handle, key := range s.handles {
		s.guard.Zeroize(key)
		_ = s.guard.Unlock(key)
		delete(s.handles, handle)
	}
}

func (s *lockedMVKStore) Handles() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.handles))
	for h := range s.handles {
		out = append(out, h)
	}
	return out
}
