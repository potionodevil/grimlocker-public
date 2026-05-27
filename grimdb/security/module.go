package security

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"

	"github.com/grimlocker/grimdb-public/crypto"
	"github.com/grimlocker/grimdb-public/kernel"
)

const moduleID = "security"

// Module implements kernel.Module for the SECURITY and AUTH channels.
// It owns the LockdownManager, AuditLog, MemoryGuard, and the in-memory
// MVK handle table. No other module holds actual key material.
type Module struct {
	mu       sync.RWMutex
	lockdown LockdownManager
	audit    AuditLog
	guard    MemoryGuard

	// mvkHandles maps opaque handle string → locked key bytes.
	mvkHandles map[string][]byte

	entropyPath string
	dispatcher  kernel.Dispatcher
	session     *SessionContext

	// exitFunc is called at the end of a hard lockdown. Defaults to os.Exit.
	// Override in tests to prevent the process from terminating.
	exitFunc func(code int)
}

// NewModule creates the security module. entropyPath is the path to the
// entropy file that must be overwritten on hard lockdown.
func NewModule(cfg LockdownConfig, entropyPath string) *Module {
	m := &Module{
		audit:       NewAuditLog(1024),
		guard:       NewMemoryGuard(),
		mvkHandles:  make(map[string][]byte),
		entropyPath: entropyPath,
		exitFunc:    os.Exit,
	}
	cfg.OnHard = m.hardLockdownCallback
	m.lockdown = NewLockdownManager(cfg)
	return m
}

// WithExitFunc overrides the exit function called at the end of hard lockdown.
// Use in tests to prevent os.Exit from terminating the test process.
func (m *Module) WithExitFunc(f func(int)) *Module {
	m.exitFunc = f
	return m
}

func (m *Module) ID() string         { return moduleID }
func (m *Module) Channels() []string { return []string{"SECURITY", "AUTH"} }

// SetSession links the module to the global SessionContext.
func (m *Module) SetSession(s *SessionContext) {
	m.session = s
}

func (m *Module) Start(ctx context.Context, d kernel.Dispatcher) error {
	m.dispatcher = d
	if m.session != nil {
		m.session.SetDispatcher(d)
	}
	m.audit.Append(SecurityEvent{Level: LevelInfo, Module: moduleID, Message: "security module started"})
	return nil
}

func (m *Module) Stop() error {
	m.mu.Lock()
	for handle, key := range m.mvkHandles {
		m.guard.Zeroize(key)
		_ = m.guard.Unlock(key)
		delete(m.mvkHandles, handle)
	}
	m.mu.Unlock()
	return nil
}

func (m *Module) Handle(e kernel.Event) error {
	switch e.Type {
	case kernel.EvSecAudit:
		var ev SecurityEvent
		if err := json.Unmarshal(e.Payload, &ev); err != nil {
			// Fallback: treat plain-string payloads as simple info messages.
			m.audit.Append(SecurityEvent{Level: LevelInfo, Module: moduleID, Message: string(e.Payload)})
			return nil
		}
		m.audit.Append(ev)
		return nil

	case kernel.EvSecPanic:
		m.audit.Append(SecurityEvent{Level: LevelCritical, Module: moduleID, Message: "PANIC event received — triggering hard lockdown"})
		return m.lockdown.TriggerHard()

	case kernel.EvSecLockdown:
		return m.lockdown.TriggerHard()

	case kernel.EvAuthStatus:
		return m.handleAuthStatus(e)

	case kernel.EvAuthSetup:
		return m.handleAuthSetup(e)

	case kernel.EvAuthResult:
		// Consumed by other modules (e.g., entry handler, translator).
		// No-op here to prevent "unhandled event" error.
		return nil

	case kernel.EvAuthInitReady:
		// Watchdog startup check — no-op.
		return nil

	case kernel.EvAuthUnlock:
		// Handled by makeAuthUnlockHandler subscription in daemon/main.go — no-op here.
		return nil

	case kernel.EvAuthReady:
		// Emitted by SessionContext.Unlock — no-op here.
		return nil

	case kernel.EvAuthLogout:
		// Emitted by SessionContext.Lock — no-op here.
		return nil

	case kernel.EvAuthKeyReady:
		// Emitted after successful unlock+index load — no-op here.
		return nil

	case kernel.EvAuthLockdown:
		// Forward to lockdown manager — can reach hard/soft state.
		return m.lockdown.TriggerHard()

	case kernel.EvAuthGetHandle:
		return m.handleAuthGetHandle(e)

	default:
		return fmt.Errorf("security module: unhandled event %s", e.Type)
	}
}

// StoreMVK stores key material in locked memory and returns an opaque handle.
func (m *Module) StoreMVK(key []byte) (string, error) {
	locked, err := m.guard.AllocLocked(len(key))
	if err != nil {
		return "", fmt.Errorf("alloc locked: %w", err)
	}
	copy(locked, key)

	handle := randomHandle()
	m.mu.Lock()
	m.mvkHandles[handle] = locked
	m.mu.Unlock()
	return handle, nil
}

// RetrieveMVK returns the key bytes for a handle without copying —
// callers MUST NOT hold the returned slice past the current call frame.
func (m *Module) RetrieveMVK(handle string) ([]byte, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key, ok := m.mvkHandles[handle]
	return key, ok
}

// RevokeMVK zeroises and removes the key for the given handle.
func (m *Module) RevokeMVK(handle string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if key, ok := m.mvkHandles[handle]; ok {
		m.guard.Zeroize(key)
		_ = m.guard.Unlock(key)
		delete(m.mvkHandles, handle)
	}
}

// Lockdown returns the current LockdownManager for read-only state queries.
func (m *Module) Lockdown() LockdownManager { return m.lockdown }

// Audit returns the AuditLog.
func (m *Module) Audit() AuditLog { return m.audit }

func (m *Module) handleAuthStatus(e kernel.Event) error {
	state := m.lockdown.State()
	payload, _ := json.Marshal(map[string]interface{}{
		"lockdown_state":     state,
		"remaining_attempts": m.lockdown.RemainingAttempts(),
		"lockdown_until":     m.lockdown.LockdownUntil().Unix(),
	})
	reply := kernel.ReplyEvent(moduleID, kernel.EvAuthResult, e, payload)
	return m.dispatcher.Dispatch(reply)
}

func (m *Module) handleAuthSetup(e kernel.Event) error {
	// AUTH.SETUP is a handshake request from the UI to trigger vault initialization.
	// Reply with auth readiness status.
	payload, _ := json.Marshal(map[string]interface{}{
		"ready": true,
	})
	reply := kernel.ReplyEvent(moduleID, kernel.EvAuthResult, e, payload)
	return m.dispatcher.Dispatch(reply)
}

func (m *Module) handleAuthGetHandle(e kernel.Event) error {
	if m.session == nil {
		reply := kernel.ReplyEvent(moduleID, kernel.EvAuthResult, e, []byte(`{"error":"vault locked"}`))
		return m.dispatcher.Dispatch(reply)
	}
	handle := m.session.ActiveHandle()
	if handle == "" {
		reply := kernel.ReplyEvent(moduleID, kernel.EvAuthResult, e, []byte(`{"error":"vault locked"}`))
		return m.dispatcher.Dispatch(reply)
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"handle": handle,
	})
	reply := kernel.ReplyEvent(moduleID, kernel.EvAuthResult, e, payload)
	return m.dispatcher.Dispatch(reply)
}

func (m *Module) hardLockdownCallback() {
	log.Printf("[security] HARD LOCKDOWN: zeroising all key material")
	m.mu.Lock()
	for handle, key := range m.mvkHandles {
		m.guard.Zeroize(key)
		_ = m.guard.Unlock(key)
		delete(m.mvkHandles, handle)
	}
	m.mu.Unlock()

	overwriteEntropy(m.entropyPath)

	if m.dispatcher != nil {
		ev := kernel.NewEvent(moduleID, kernel.EvSecPanic, []byte(`{"reason":"hard_lockdown"}`))
		_ = m.dispatcher.Dispatch(ev)
	}

	log.Printf("[security] HARD LOCKDOWN: exiting process")
	m.exitFunc(1)
}

func overwriteEntropy(path string) {
	if path == "" {
		return
	}

	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	fileSize := fi.Size()

	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()

	if err := crypto.Shred(f, fileSize); err != nil {
		log.Printf("[security] entropy shred failed: %v — falling back to zero overwrite", err)
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return
		}
		buf := make([]byte, 4096)
		written := 0
		total := int(fileSize)
		for written < total {
			n, writeErr := f.Write(buf[:min(len(buf), total-written)])
			if writeErr != nil {
				break
			}
			written += n
		}
	}
	_ = f.Sync()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func randomHandle() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("security: CSPRNG failure during handle generation: %v", err))
	}
	return fmt.Sprintf("%x", b)
}
