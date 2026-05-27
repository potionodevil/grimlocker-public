package kernel

import (
	"context"
	"math/rand"
	"time"
)

// EventType is the channel address of an event. The prefix before "." is the
// owning module's channel (e.g. "CRYPTO" for all CRYPTO.* events).
type EventType string

const (
	// AUTH channel — owned by security.Module
	EvAuthSetup     EventType = "AUTH.SETUP"
	EvAuthUnlock    EventType = "AUTH.UNLOCK"
	EvAuthResult    EventType = "AUTH.RESULT"
	EvAuthLockdown  EventType = "AUTH.LOCKDOWN"
	EvAuthLogout    EventType = "AUTH.LOGOUT"
	EvAuthStatus    EventType = "AUTH.STATUS"
	EvAuthInitReady EventType = "AUTH.INIT_READY"
	EvAuthKeyReady  EventType = "AUTH.KEY_READY"
	EvAuthReady     EventType = "AUTH.READY"
	EvAuthGetHandle EventType = "AUTH.GET_HANDLE"

	// SECURITY channel — owned by security.Module
	EvSecMemLock  EventType = "SECURITY.MEM_LOCK"
	EvSecZeroize  EventType = "SECURITY.ZEROIZE"
	EvSecAudit    EventType = "SECURITY.AUDIT"
	EvSecPanic    EventType = "SECURITY.PANIC"
	EvSecLockdown EventType = "SECURITY.LOCKDOWN"
)

// Event is the unit of communication between modules. Payloads are JSON.
type Event struct {
	ID        string    `json:"id"`
	Type      EventType `json:"type"`
	Payload   []byte    `json:"payload,omitempty"`
	ReplyTo   string    `json:"reply_to,omitempty"`
	Origin    string    `json:"origin,omitempty"`
	Timestamp int64     `json:"timestamp"`
	TTL       int       `json:"ttl"`
}

// Dispatcher is the sole communication interface between modules.
type Dispatcher interface {
	Dispatch(e Event) error
	Request(ctx context.Context, e Event) (Event, error)
	Subscribe(eventType EventType, handler Handler) (unsubscribe func())
	Register(m Module) error
	Unregister(moduleID string)
	Shutdown(ctx context.Context) error
}

// Handler is a function that processes a delivered event.
type Handler func(Event) error

// Module is the contract every module must satisfy to plug into the kernel.
type Module interface {
	ID() string
	Channels() []string
	Handle(Event) error
	Start(ctx context.Context, d Dispatcher) error
	Stop() error
}

// NewEvent creates an event with a generated UUID and current timestamp.
func NewEvent(origin string, eventType EventType, payload []byte) Event {
	return Event{
		ID:        generateUUID(),
		Origin:    origin,
		Type:      eventType,
		Payload:   payload,
		Timestamp: currentTimestamp(),
		TTL:       32,
	}
}

// ReplyEvent creates a reply event for a given request event.
func ReplyEvent(origin string, eventType EventType, req Event, payload []byte) Event {
	return Event{
		ID:        generateUUID(),
		Origin:    origin,
		Type:      eventType,
		Payload:   payload,
		ReplyTo:   req.ID,
		Timestamp: currentTimestamp(),
		TTL:       32,
	}
}

// Channel extracts the routing prefix from an EventType.
func (et EventType) Channel() string {
	s := string(et)
	for i, c := range s {
		if c == '.' {
			return s[:i]
		}
	}
	return s
}

// Placeholder implementations (these would normally come from uuid and time modules)
func generateUUID() string {
	const charset = "0123456789abcdef"
	b := make([]byte, 36)
	for i := 0; i < 36; i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			b[i] = '-'
		} else {
			b[i] = charset[rand.Intn(len(charset))]
		}
	}
	return string(b)
}

func currentTimestamp() int64 {
	return time.Now().UnixNano()
}
