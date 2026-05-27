package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/grimlocker/grimdb-public/kernel"
)

// IntegrityMonitor computes a SHA-256 baseline of the daemon binary at startup
// and re-verifies it on a configurable interval. A mismatch dispatches
// SECURITY.PANIC to the bus, triggering the hard-lockdown path.
//
// On Windows, if the binary is locked when re-read (e.g. by antivirus),
// the check is skipped with a warning rather than triggering a false positive.
type IntegrityMonitor struct {
	baseline   [32]byte
	execPath   string
	dispatcher kernel.Dispatcher
}

// NewIntegrityMonitor reads the current executable, hashes it with SHA-256,
// and stores the result as the permanent baseline.
func NewIntegrityMonitor(d kernel.Dispatcher) (*IntegrityMonitor, error) {
	path, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("integrity: resolve executable: %w", err)
	}

	baseline, err := hashFile(path)
	if err != nil {
		return nil, fmt.Errorf("integrity: hash baseline: %w", err)
	}

	log.Printf("[integrity] baseline SHA-256: %s", hex.EncodeToString(baseline[:]))

	return &IntegrityMonitor{
		baseline:   baseline,
		execPath:   path,
		dispatcher: d,
	}, nil
}

// Verify re-hashes the binary and returns a non-nil error if it has changed.
func (m *IntegrityMonitor) Verify() error {
	current, err := hashFile(m.execPath)
	if err != nil {
		// On Windows the file may be locked; log and skip rather than false-positive.
		log.Printf("[integrity] WARNING: cannot re-read binary (%v) — skipping check", err)
		return nil
	}

	if current != m.baseline {
		return fmt.Errorf("integrity violation: expected %s got %s",
			hex.EncodeToString(m.baseline[:]),
			hex.EncodeToString(current[:]))
	}
	return nil
}

// StartMonitor launches a background goroutine that calls Verify every interval.
// On violation it dispatches SECURITY.PANIC and stops monitoring.
func (m *IntegrityMonitor) StartMonitor(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := m.Verify(); err != nil {
					log.Printf("[integrity] CRITICAL: %v", err)
					m.dispatchViolation(err)
					return
				}
			}
		}
	}()
}

// Baseline returns the startup SHA-256 hash of the binary.
func (m *IntegrityMonitor) Baseline() [32]byte { return m.baseline }

func (m *IntegrityMonitor) dispatchViolation(verifyErr error) {
	payload, _ := json.Marshal(map[string]string{
		"reason":   "binary_integrity_violation",
		"expected": hex.EncodeToString(m.baseline[:]),
		"error":    verifyErr.Error(),
	})
	ev := kernel.NewEvent("integrity", kernel.EvSecPanic, payload)
	if err := m.dispatcher.Dispatch(ev); err != nil {
		log.Printf("[integrity] dispatch panic failed: %v", err)
	}
}

// hashFile streams the file at path through SHA-256 without reading it all into RAM.
func hashFile(path string) ([32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [32]byte{}, err
	}

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}
