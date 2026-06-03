// Package security (lockdown.go) implements the LockdownManager — a state
// machine that enforces progressive authentication lockout.
//
// States:
//
//	LockdownNone → normal operation, up to Threshold failures allowed.
//	LockdownSoft → threshold exceeded; soft lockout for LockdownMinutes,
//	               up to MaxOverrides additional attempts permitted.
//	LockdownHard → MaxOverrides exhausted (or TriggerHard called directly);
//	               the OnHard callback is invoked (zeroise keys + os.Exit).
//
// Thread-safe: all methods lock m.mu before reading/writing state.
//
// Default values (used when config fields are ≤ 0):
//   - Threshold: 3 failures before soft lockdown
//   - MaxOverrides: 4 additional attempts during soft lockdown
//   - LockdownMinutes: 200 minutes soft lockdown duration
package security

import (
	"sync"
	"time"

	gerrors "github.com/grimlocker/grimdb-public/engine/errors"
)

// LockdownState describes the current lockout level.
type LockdownState int

const (
	LockdownNone LockdownState = 0 // normal operation
	LockdownSoft LockdownState = 1 // attempt limit hit, timer active
	LockdownHard LockdownState = 2 // wipe triggered, daemon must exit
)

// LockdownManager tracks failed authentication attempts and manages the
// progressive lockdown state machine.
type LockdownManager interface {
	RecordFailure() (LockdownState, error)
	RecordSuccess()
	State() LockdownState
	RemainingAttempts() int
	LockdownUntil() time.Time
	// TriggerHard immediately transitions to LockdownHard.
	// The caller is responsible for zeroising secrets and exiting.
	TriggerHard() error
}

type lockdownManager struct {
	mu              sync.Mutex
	failures        int
	threshold       int
	overridesLeft   int
	maxOverrides    int
	lockdownUntil   time.Time
	lockdownMinutes int
	state           LockdownState
	onHard          func() // callback invoked on hard lockdown (e.g. zeroize + exit)
}

// LockdownConfig configures the manager.
type LockdownConfig struct {
	Threshold       int    // failed attempts before soft lockdown
	MaxOverrides    int    // override attempts during soft lockdown
	LockdownMinutes int    // soft lockdown duration
	OnHard          func() // called when hard lockdown is triggered
}

// NewLockdownManager creates a LockdownManager from the given config.
func NewLockdownManager(cfg LockdownConfig) LockdownManager {
	if cfg.Threshold <= 0 {
		cfg.Threshold = 3
	}
	if cfg.MaxOverrides <= 0 {
		cfg.MaxOverrides = 4
	}
	if cfg.LockdownMinutes <= 0 {
		cfg.LockdownMinutes = 200
	}
	return &lockdownManager{
		threshold:       cfg.Threshold,
		overridesLeft:   cfg.MaxOverrides,
		maxOverrides:    cfg.MaxOverrides,
		lockdownMinutes: cfg.LockdownMinutes,
		onHard:          cfg.OnHard,
		state:           LockdownNone,
	}
}

func (m *lockdownManager) RecordFailure() (LockdownState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch m.state {
	case LockdownHard:
		return LockdownHard, gerrors.NewAuthLockdownError(0)

	case LockdownSoft:
		m.overridesLeft--
		if m.overridesLeft <= 0 {
			m.state = LockdownHard
			if m.onHard != nil {
				m.onHard()
			}
			return LockdownHard, gerrors.NewAuthLockdownError(0)
		}
		return LockdownSoft, gerrors.NewAuthLockdownError(m.overridesLeft)

	default:
		m.failures++
		if m.failures >= m.threshold {
			m.state = LockdownSoft
			m.lockdownUntil = time.Now().Add(time.Duration(m.lockdownMinutes) * time.Minute)
			return LockdownSoft, gerrors.NewAuthLockdownError(0)
		}
		remaining := m.threshold - m.failures
		return LockdownNone, gerrors.NewAuthInvalidError("credentials", nil).
			WithDetails("attempts_remaining", remaining)
	}
}

func (m *lockdownManager) RecordSuccess() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.failures = 0
	m.overridesLeft = m.maxOverrides
	m.state = LockdownNone
	m.lockdownUntil = time.Time{}
}

func (m *lockdownManager) State() LockdownState {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Auto-expire soft lockdown after the timer elapses.
	if m.state == LockdownSoft && time.Now().After(m.lockdownUntil) {
		m.state = LockdownNone
		m.failures = 0
		m.overridesLeft = m.maxOverrides
	}
	return m.state
}

func (m *lockdownManager) RemainingAttempts() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch m.state {
	case LockdownSoft:
		return m.overridesLeft
	case LockdownHard:
		return 0
	default:
		return m.threshold - m.failures
	}
}

func (m *lockdownManager) LockdownUntil() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lockdownUntil
}

func (m *lockdownManager) TriggerHard() error {
	m.mu.Lock()
	m.state = LockdownHard
	m.mu.Unlock()

	if m.onHard != nil {
		m.onHard()
	}
	return nil
}
