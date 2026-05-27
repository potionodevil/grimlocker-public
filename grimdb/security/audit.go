package security

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"
)

// Level constants for SecurityEvent.
const (
	LevelInfo     = "INFO"
	LevelWarn     = "WARN"
	LevelCritical = "CRITICAL"
)

// SecurityEvent is an immutable audit record with cryptographic chaining.
type SecurityEvent struct {
	Timestamp int64  `json:"timestamp"`
	Level     string `json:"level"`
	Module    string `json:"module"`
	Message   string `json:"message"`
	SubjectID string `json:"subject_id,omitempty"`   // Who triggered the action
	PrevHash  []byte `json:"prev_hash,omitempty"`    // Hash of previous entry
	Hash      []byte `json:"hash,omitempty"`         // SHA-256 of this entry
}

// AuditLog is a thread-safe append-only ring buffer of SecurityEvents.
type AuditLog interface {
	Append(e SecurityEvent)
	Recent(n int) []SecurityEvent
	Drain() []SecurityEvent
}

type ringAuditLog struct {
	mu       sync.Mutex
	ring     []SecurityEvent
	cap      int
	head     int
	size     int
	lastHash [32]byte  // SHA-256 of the most recent entry
}

// NewAuditLog creates an AuditLog with the given ring buffer capacity.
func NewAuditLog(capacity int) AuditLog {
	if capacity <= 0 {
		capacity = 1024
	}
	return &ringAuditLog{
		ring: make([]SecurityEvent, capacity),
		cap:  capacity,
	}
}

func (a *ringAuditLog) Append(e SecurityEvent) {
	if e.Timestamp == 0 {
		e.Timestamp = time.Now().UnixNano()
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	// Cryptographic chaining: hash = SHA-256(prevHash || timestamp || level || module || message || subjectID)
	e.PrevHash = a.lastHash[:]
	h := sha256.New()
	h.Write(a.lastHash[:])
	_ = binary.Write(h, binary.BigEndian, e.Timestamp)
	h.Write([]byte(e.Level))
	h.Write([]byte(e.Module))
	h.Write([]byte(e.Message))
	h.Write([]byte(e.SubjectID))
	e.Hash = h.Sum(nil)
	copy(a.lastHash[:], e.Hash)

	idx := (a.head + a.size) % a.cap
	a.ring[idx] = e
	if a.size < a.cap {
		a.size++
	} else {
		a.head = (a.head + 1) % a.cap
	}
}

func (a *ringAuditLog) Recent(n int) []SecurityEvent {
	a.mu.Lock()
	defer a.mu.Unlock()

	if n > a.size {
		n = a.size
	}

	result := make([]SecurityEvent, n)
	start := (a.head + a.size - n + a.cap) % a.cap
	for i := 0; i < n; i++ {
		result[i] = a.ring[(start+i)%a.cap]
	}
	return result
}

func (a *ringAuditLog) Drain() []SecurityEvent {
	a.mu.Lock()
	defer a.mu.Unlock()

	result := make([]SecurityEvent, a.size)
	for i := 0; i < a.size; i++ {
		result[i] = a.ring[(a.head+i)%a.cap]
	}
	a.size = 0
	a.head = 0
	return result
}
