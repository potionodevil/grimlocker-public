package security

import (
	"encoding/json"
	"fmt"
	"log"
	"runtime/debug"
	"sync"
	"time"

	"github.com/grimlocker/grimdb-public/kernel"
)

// SessionContext holds the runtime authentication state.
// It never stores plaintext passwords — only the derived MVK handle.
// Thread-safe via RWMutex.
type SessionContext struct {
	mu         sync.RWMutex
	active     bool
	mvkHandle  string
	unlockedAt time.Time
	dispatcher kernel.Dispatcher
}

// NewSessionContext creates an empty session context.
func NewSessionContext() *SessionContext {
	return &SessionContext{}
}

// SetDispatcher injects the bus dispatcher for emitting events.
func (s *SessionContext) SetDispatcher(d kernel.Dispatcher) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dispatcher = d
}

// Unlock marks the session as active with the given MVK handle.
// Emits AUTH.READY to signal the vault is usable.
func (s *SessionContext) Unlock(mvkHandle string) {
	s.mu.Lock()
	s.active = true
	s.mvkHandle = mvkHandle
	s.unlockedAt = time.Now()
	s.mu.Unlock()

	log.Printf("[session] Vault unlocked, handle=%s", mvkHandle)

	if s.dispatcher != nil {
		payload, _ := json.Marshal(map[string]interface{}{
			"unlocked":    true,
			"mvk_handle":  mvkHandle,
			"unlocked_at": s.unlockedAt.Unix(),
		})
		ev := kernel.NewEvent("session", kernel.EvAuthReady, payload)
		_ = s.dispatcher.Dispatch(ev)
	}
}

// Lock clears the session, revoking the active handle reference.
// Emits AUTH.LOGOUT for downstream cleanup.
func (s *SessionContext) Lock() {
	s.mu.Lock()
	wasActive := s.active
	s.active = false
	s.mvkHandle = ""
	s.unlockedAt = time.Time{}
	s.mu.Unlock()

	log.Printf("[session] Vault locked — caller:\n%s", debug.Stack())

	if wasActive && s.dispatcher != nil {
		payload, _ := json.Marshal(map[string]interface{}{
			"reason": "session_locked",
		})
		ev := kernel.NewEvent("session", kernel.EvAuthLogout, payload)
		_ = s.dispatcher.Dispatch(ev)
	}
}

// IsUnlocked reports whether the vault is currently unlocked.
func (s *SessionContext) IsUnlocked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active
}

// MVKHandle returns the active MVK handle, or "" if locked.
func (s *SessionContext) MVKHandle() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mvkHandle
}

// ActiveHandle returns the MVK handle if the session is unlocked,
// or "" if locked. Reads both fields under one lock to prevent TOCTOU.
func (s *SessionContext) ActiveHandle() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.active {
		return ""
	}
	return s.mvkHandle
}

// RequireUnlocked returns nil if unlocked, otherwise an error event payload.
func (s *SessionContext) RequireUnlocked() error {
	if !s.IsUnlocked() {
		return fmt.Errorf("vault locked: no active session")
	}
	return nil
}

// Health returns a JSON-serializable health check result.
func (s *SessionContext) Health() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]interface{}{
		"active":      s.active,
		"mvk_handle":  s.mvkHandle != "",
		"unlocked_at": s.unlockedAt.Unix(),
		"age_seconds": time.Since(s.unlockedAt).Seconds(),
	}
}
