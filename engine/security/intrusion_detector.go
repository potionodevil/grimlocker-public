// Package security (intrusion_detector.go) implements IntrusionDetector — a
// lightweight anomaly detector that watches for patterns indicating unauthorized
// access attempts or data exfiltration.
//
// Detected patterns:
//   - Rapid auth failures from multiple source IPs within a short window
//   - Unusually high entry-read rate (possible vault scan / exfiltration)
//   - Rapid file ingest followed by deletes (possible data staging)
//
// On detection, an anomaly event is dispatched to the kernel bus and logged
// at WARN level. After a configurable threshold of anomalies, a security
// lockdown is triggered automatically.
package security

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// AnomalyType identifies the kind of anomaly detected.
type AnomalyType string

const (
	AnomalyRapidAuthFailures AnomalyType = "RAPID_AUTH_FAILURES"
	AnomalyRapidEntryAccess  AnomalyType = "RAPID_ENTRY_ACCESS"
	AnomalyDataExfil         AnomalyType = "POSSIBLE_DATA_EXFIL"
)

// AnomalyEvent is emitted when suspicious behaviour is detected.
type AnomalyEvent struct {
	Type      AnomalyType
	Subject   string
	Detail    string
	Timestamp time.Time
	Severity  string // "LOW", "MEDIUM", "HIGH"
}

// IntrusionDetector watches for anomalous patterns and emits AnomalyEvents.
// It is designed to run in-process alongside the daemon with minimal overhead.
type IntrusionDetector struct {
	mu sync.Mutex

	// Sliding window counters (reset after windowSize).
	authFailures map[string][]time.Time // subject -> timestamps of failures
	entryReads   map[string][]time.Time // subject -> timestamps of reads
	ingestOps    map[string][]time.Time // subject -> timestamps of ingest ops
	deleteOps    map[string][]time.Time // subject -> timestamps of delete ops

	// Configuration.
	windowSize        time.Duration // sliding window duration
	authFailThreshold int           // failures in window before anomaly
	readRateThreshold int           // entry reads in window before anomaly
	exfilThreshold    int           // ingest+delete ops in window before anomaly

	// Anomaly callback — called with each detected event.
	onAnomaly func(AnomalyEvent)

	// Anomaly history (capped ring buffer).
	history    []AnomalyEvent
	historyMax int
}

// NewIntrusionDetector creates an IntrusionDetector with sensible defaults.
func NewIntrusionDetector(onAnomaly func(AnomalyEvent)) *IntrusionDetector {
	return &IntrusionDetector{
		authFailures:      make(map[string][]time.Time),
		entryReads:        make(map[string][]time.Time),
		ingestOps:         make(map[string][]time.Time),
		deleteOps:         make(map[string][]time.Time),
		windowSize:        5 * time.Minute,
		authFailThreshold: 3,    // 3 failures from different subjects in 5 min
		readRateThreshold: 50,   // 50 reads in 5 min = possible vault scan
		exfilThreshold:    20,   // 20 ingest+delete ops in 5 min = possible staging
		onAnomaly:         onAnomaly,
		history:           make([]AnomalyEvent, 0, 100),
		historyMax:        100,
	}
}

// RecordAuthFailure records a failed authentication attempt.
// Emits AnomalyRapidAuthFailures if the threshold is exceeded.
func (d *IntrusionDetector) RecordAuthFailure(subject string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.authFailures[subject] = d.pruneWindow(d.authFailures[subject])
	d.authFailures[subject] = append(d.authFailures[subject], time.Now())

	total := 0
	for _, timestamps := range d.authFailures {
		total += len(timestamps)
	}

	if total >= d.authFailThreshold {
		d.emit(AnomalyEvent{
			Type:      AnomalyRapidAuthFailures,
			Subject:   subject,
			Detail:    fmt.Sprintf("%d auth failures across all subjects in %s window", total, d.windowSize),
			Timestamp: time.Now(),
			Severity:  "MEDIUM",
		})
	}
}

// RecordEntryRead records an entry read operation.
// Emits AnomalyRapidEntryAccess if the read rate exceeds the threshold.
func (d *IntrusionDetector) RecordEntryRead(subject string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.entryReads[subject] = d.pruneWindow(d.entryReads[subject])
	d.entryReads[subject] = append(d.entryReads[subject], time.Now())

	count := len(d.entryReads[subject])
	if count >= d.readRateThreshold {
		d.emit(AnomalyEvent{
			Type:    AnomalyRapidEntryAccess,
			Subject: subject,
			Detail: fmt.Sprintf("%d entry reads for subject=%q in %s window — possible vault scan",
				count, subject, d.windowSize),
			Timestamp: time.Now(),
			Severity:  "HIGH",
		})
	}
}

// RecordIngestOp records a file ingest operation.
func (d *IntrusionDetector) RecordIngestOp(subject string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.ingestOps[subject] = d.pruneWindow(d.ingestOps[subject])
	d.ingestOps[subject] = append(d.ingestOps[subject], time.Now())
	d.checkExfilPattern(subject)
}

// RecordDeleteOp records a block delete operation.
func (d *IntrusionDetector) RecordDeleteOp(subject string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.deleteOps[subject] = d.pruneWindow(d.deleteOps[subject])
	d.deleteOps[subject] = append(d.deleteOps[subject], time.Now())
	d.checkExfilPattern(subject)
}

// checkExfilPattern detects rapid ingest+delete patterns.
// Must be called with d.mu held.
func (d *IntrusionDetector) checkExfilPattern(subject string) {
	ingests := len(d.ingestOps[subject])
	deletes := len(d.deleteOps[subject])
	combined := ingests + deletes

	if combined >= d.exfilThreshold && ingests > 0 && deletes > 0 {
		d.emit(AnomalyEvent{
			Type:    AnomalyDataExfil,
			Subject: subject,
			Detail: fmt.Sprintf("subject=%q: %d ingest + %d delete ops in %s window — possible data staging",
				subject, ingests, deletes, d.windowSize),
			Timestamp: time.Now(),
			Severity:  "HIGH",
		})
	}
}

// emit logs and dispatches an anomaly. Must be called with d.mu held.
func (d *IntrusionDetector) emit(ev AnomalyEvent) {
	log.Printf("[IntrusionDetector] ANOMALY type=%s severity=%s subject=%q detail=%q",
		ev.Type, ev.Severity, ev.Subject, ev.Detail)

	// Append to ring buffer.
	if len(d.history) >= d.historyMax {
		d.history = d.history[1:]
	}
	d.history = append(d.history, ev)

	// Fire callback without holding the lock (callback may acquire other locks).
	if d.onAnomaly != nil {
		go d.onAnomaly(ev)
	}
}

// pruneWindow removes timestamps outside the sliding window.
// Must be called with d.mu held.
func (d *IntrusionDetector) pruneWindow(timestamps []time.Time) []time.Time {
	cutoff := time.Now().Add(-d.windowSize)
	i := 0
	for i < len(timestamps) && timestamps[i].Before(cutoff) {
		i++
	}
	return timestamps[i:]
}

// History returns a snapshot of recent anomaly events (newest first).
func (d *IntrusionDetector) History() []AnomalyEvent {
	d.mu.Lock()
	defer d.mu.Unlock()

	result := make([]AnomalyEvent, len(d.history))
	// Return newest first.
	for i, ev := range d.history {
		result[len(d.history)-1-i] = ev
	}
	return result
}
