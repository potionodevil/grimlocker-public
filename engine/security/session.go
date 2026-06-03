// Package security (session.go) implements SessionContext — the global
// vault-unlock state shared between the security module, the storage adapter,
// and the API translator.
//
// SessionContext answers one question: "Is the vault currently unlocked?"
// It is the authoritative source of truth for the active MVK handle and
// is consulted by HandshakeStatus so reconnecting WebSocket clients can
// re-attach to an already-unlocked vault without re-entering their password.
//
// Thread-safe: all exported methods acquire the internal mutex.
//
// Lifecycle:
//
//	NewSessionContext()          // create (vault starts locked)
//	sessionCtx.Unlock(handle)   // called after AUTH.KEY_READY
//	sessionCtx.IsUnlocked()     // polled by storage adapter gate check
//	sessionCtx.Lock()           // called on AUTH.LOGOUT
//	sessionCtx.SessionDestroy() // called during graceful shutdown
package security

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/grimlocker/grimdb-public/engine/kernel"
)

// SessionContext holds the runtime authentication state.
// It never stores plaintext passwords — only the derived MVK handle.
// Thread-safe via RWMutex.
type SessionContext struct {
	mu              sync.RWMutex
	active          bool
	mvkHandle       string
	unlockedAt      time.Time
	dispatcher      kernel.Dispatcher
	autoLockMinutes int
	autoLockTimer   *time.Timer
	lastActivity    time.Time
}

// NewSessionContext creates an empty session context.
func NewSessionContext() *SessionContext {
	return &SessionContext{
		autoLockMinutes: 15, // default: 15 minutes
	}
}

// SetAutoLockMinutes configures the inactivity auto-lock interval.
// Set to 0 to disable auto-lock entirely.
func (s *SessionContext) SetAutoLockMinutes(minutes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.autoLockMinutes = minutes
}

// ResetActivity restarts the auto-lock timer on API activity.
// Called by the translator on every non-heartbeat message.
func (s *SessionContext) ResetActivity() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.autoLockTimer != nil {
		s.autoLockTimer.Reset(time.Duration(s.autoLockMinutes) * time.Minute)
	}
}

// SetDispatcher injects the bus dispatcher for emitting events.
func (s *SessionContext) SetDispatcher(d kernel.Dispatcher) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dispatcher = d
}

// Unlock marks the session as active with the given MVK handle.
// Emits AUTH.READY to signal the vault is usable.
// Starts the auto-lock inactivity timer if configured.
func (s *SessionContext) Unlock(mvkHandle string) {
	s.mu.Lock()
	s.active = true
	s.mvkHandle = mvkHandle
	s.unlockedAt = time.Now()
	s.lastActivity = time.Now()

	// Cancel any existing timer before creating a new one
	if s.autoLockTimer != nil {
		s.autoLockTimer.Stop()
	}
	if s.autoLockMinutes > 0 {
		s.autoLockTimer = time.AfterFunc(time.Duration(s.autoLockMinutes)*time.Minute, func() {
			log.Printf("[session] Auto-lock: inactivity timeout (%d min) reached", s.autoLockMinutes)
			s.Lock()
		})
	}
	s.mu.Unlock()

	log.Printf("[session] Vault unlocked (handle=<redacted>)")

	if s.dispatcher != nil {
		// Do NOT include mvkHandle in the event payload — it would propagate
		// through the event bus and potentially end up in logs.
		payload, _ := json.Marshal(map[string]interface{}{
			"unlocked":    true,
			"unlocked_at": s.unlockedAt.Unix(),
		})
		ev := kernel.NewEvent("session", kernel.EvAuthReady, payload)
		_ = s.dispatcher.Dispatch(ev)
	}
}

// Lock clears the session, revoking the active handle reference.
// Emits AUTH.LOGOUT for downstream cleanup.
// Stops the auto-lock timer.
func (s *SessionContext) Lock() {
	s.mu.Lock()
	wasActive := s.active
	s.active = false
	s.mvkHandle = ""
	s.unlockedAt = time.Time{}
	s.lastActivity = time.Time{}
	if s.autoLockTimer != nil {
		s.autoLockTimer.Stop()
	}
	s.mu.Unlock()

	if wasActive {
		log.Printf("[session] Vault locked")
		if s.dispatcher != nil {
			payload, _ := json.Marshal(map[string]string{"reason": "session_locked"})
			ev := kernel.NewEvent("session", kernel.EvAuthLogout, payload)
			_ = s.dispatcher.Dispatch(ev)
		}
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
