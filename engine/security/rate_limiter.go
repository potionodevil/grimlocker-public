// Package security (rate_limiter.go) implements RateLimiter — an exponential
// backoff rate limiter for authentication attempts.
//
// Policy (aligned with NIST SP 800-63B guidelines):
//   - Attempts 1-5:   no lockout
//   - Attempt 6:      60 second lockout
//   - Attempt 11:     600 second lockout (10 minutes)
//   - Attempt 16:     3600 second lockout (1 hour)
//   - Attempt 21+:    86400 second lockout (24 hours)
//
// State is stored in-memory only. After a daemon restart, the lockout
// window is reset. For persistent lockout across restarts, integrate
// with the vault index (see TODO below).
package security

import (
	"log"
	"sync"
	"time"
)

// RateLimiter tracks authentication attempts per subject and enforces
// exponential backoff lockouts.
type RateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rateLimitEntry
}

type rateLimitEntry struct {
	attempts    int
	lockedUntil time.Time
	lastAttempt time.Time
}

// NewRateLimiter creates a RateLimiter.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		entries: make(map[string]*rateLimitEntry),
	}
}

// Check returns whether the subject is currently allowed to attempt
// authentication. Returns (allowed=false, lockoutUntil) if locked out.
// Does NOT record a new attempt — call RecordFailure after a failed attempt.
func (r *RateLimiter) Check(subject string) (allowed bool, lockedUntil time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.entries[subject]
	if !ok {
		return true, time.Time{}
	}

	if time.Now().Before(entry.lockedUntil) {
		return false, entry.lockedUntil
	}

	return true, time.Time{}
}

// RecordFailure records a failed authentication attempt for the subject.
// Returns the new lockout duration (0 if no lockout applies yet) and
// the total consecutive failure count.
func (r *RateLimiter) RecordFailure(subject string) (lockoutDuration time.Duration, totalFailures int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.entries[subject]
	if !ok {
		entry = &rateLimitEntry{}
		r.entries[subject] = entry
	}

	entry.attempts++
	entry.lastAttempt = time.Now()
	totalFailures = entry.attempts

	// Exponential backoff lockout policy.
	var lockout time.Duration
	switch {
	case entry.attempts >= 21:
		lockout = 24 * time.Hour
	case entry.attempts >= 16:
		lockout = time.Hour
	case entry.attempts >= 11:
		lockout = 10 * time.Minute
	case entry.attempts >= 6:
		lockout = 60 * time.Second
	default:
		lockout = 0
	}

	if lockout > 0 {
		entry.lockedUntil = time.Now().Add(lockout)
		log.Printf("[RateLimiter] LOCKOUT subject=%q attempts=%d lockout=%s until=%s",
			subject, entry.attempts, lockout, entry.lockedUntil.Format(time.RFC3339))
	} else {
		log.Printf("[RateLimiter] ATTEMPT subject=%q attempts=%d (no lockout yet)",
			subject, entry.attempts)
	}

	return lockout, totalFailures
}

// RecordSuccess resets the failure counter for the subject.
// Call after a successful authentication.
func (r *RateLimiter) RecordSuccess(subject string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if entry, ok := r.entries[subject]; ok {
		if entry.attempts > 0 {
			log.Printf("[RateLimiter] SUCCESS subject=%q — resetting %d failure(s)",
				subject, entry.attempts)
		}
		delete(r.entries, subject)
	}
}

// RemainingAttempts returns how many more failures are allowed before the
// next lockout tier triggers. Returns -1 if the subject is currently locked.
func (r *RateLimiter) RemainingAttempts(subject string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.entries[subject]
	if !ok {
		return 5 // default: 5 attempts before first lockout
	}

	if time.Now().Before(entry.lockedUntil) {
		return -1 // currently locked
	}

	// Calculate attempts until next lockout tier.
	switch {
	case entry.attempts < 5:
		return 5 - entry.attempts
	case entry.attempts < 10:
		return 10 - entry.attempts
	case entry.attempts < 15:
		return 15 - entry.attempts
	case entry.attempts < 20:
		return 20 - entry.attempts
	default:
		return 0
	}
}

// LockoutStatus returns whether the subject is currently locked out
// and the time remaining in the lockout window.
func (r *RateLimiter) LockoutStatus(subject string) (locked bool, remaining time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.entries[subject]
	if !ok {
		return false, 0
	}

	now := time.Now()
	if now.Before(entry.lockedUntil) {
		return true, entry.lockedUntil.Sub(now)
	}
	return false, 0
}
