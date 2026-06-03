// Package kernel implements the event bus that is the central nervous system of
// the Grimlocker daemon. All inter-module communication MUST go through the
// Dispatcher — modules never import or call each other directly.
//
// Core concepts:
//
//   - Event: the unit of communication (typed JSON payload with TTL and ID).
//   - Dispatcher: routes events to registered handlers by channel prefix.
//   - Module: a stateful component that owns one or more channels (e.g. "CRYPTO").
//   - Handler: a func(Event) error called in a dedicated goroutine per event.
//   - Gate: the STORAGE channel is blocked until AUTH.KEY_READY is received,
//     preventing any block reads/writes before the vault is unlocked.
//
// Bus lifecycle:
//
//  1. NewBus(opts...) — create the bus (with optional gated channels).
//  2. Register(module) — subscribe a Module to its declared channels.
//  3. StartAll(ctx) — call Start() on every registered Module in order.
//  4. Dispatch(event) / Request(ctx, event) — send events.
//  5. Shutdown(ctx) — drain and stop all modules.
package kernel

import (
	"context"
	"fmt"
	"log"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// defaultTTL is the starting hop count for every event.
const defaultTTL = 8

// bus is the concrete Dispatcher. It routes events by channel prefix,
// runs each handler in its own goroutine, and supports synchronous
// Request/response via per-event reply channels.
type bus struct {
	mu sync.RWMutex

	// modules maps module ID → Module
	modules map[string]Module

	// channelHandlers maps channel prefix → ordered list of handlers
	channelHandlers map[string][]namedHandler

	// typeHandlers maps exact EventType → extra handlers (from Subscribe calls)
	typeHandlers map[EventType][]namedHandler

	// pending holds reply channels for in-flight Request calls, keyed by event ID
	pending   map[string]chan Event
	pendingMu sync.Mutex

	// gateBlocks events whose channel matches a prefix until the gate is lifted.
	gateMu        sync.RWMutex
	gatedChannels map[string]bool
	gateOpen      bool

	ctx    context.Context
	cancel context.CancelFunc
}

// BusOption configures a bus.
type BusOption func(*bus)

// WithGatedChannels returns a BusOption that marks the given channel prefixes
// as gated. Gated events are silently dropped until OpenGate() is called.
func WithGatedChannels(channels ...string) BusOption {
	return func(b *bus) {
		b.gatedChannels = make(map[string]bool)
		for _, ch := range channels {
			b.gatedChannels[strings.ToUpper(ch)] = true
		}
	}
}

type namedHandler struct {
	id      string
	handler Handler
}

// NewBus constructs and returns a ready-to-use Dispatcher.
func NewBus(opts ...BusOption) Dispatcher {
	ctx, cancel := context.WithCancel(context.Background())
	b := &bus{
		modules:         make(map[string]Module),
		channelHandlers: make(map[string][]namedHandler),
		typeHandlers:    make(map[EventType][]namedHandler),
		pending:         make(map[string]chan Event),
		ctx:             ctx,
		cancel:          cancel,
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// OpenGate lifts the gate, allowing previously gated events to flow.
func (b *bus) OpenGate() {
	b.gateMu.Lock()
	b.gateOpen = true
	b.gateMu.Unlock()
	log.Printf("[bus] Gate opened — gated channels now flow")
}

// CloseGate drops the gate, blocking gated channels again.
func (b *bus) CloseGate() {
	b.gateMu.Lock()
	b.gateOpen = false
	b.gateMu.Unlock()
	log.Printf("[bus] Gate closed — gated channels blocked")
}

func (b *bus) Register(m Module) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.modules[m.ID()]; exists {
		return fmt.Errorf("module %q already registered", m.ID())
	}

	b.modules[m.ID()] = m

	for _, ch := range m.Channels() {
		ch = strings.ToUpper(ch)
		b.channelHandlers[ch] = append(b.channelHandlers[ch], namedHandler{
			id:      m.ID(),
			handler: m.Handle,
		})
	}

	return nil
}

func (b *bus) Unregister(moduleID string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	m, exists := b.modules[moduleID]
	if !exists {
		return
	}

	for _, ch := range m.Channels() {
		ch = strings.ToUpper(ch)
		handlers := b.channelHandlers[ch]
		filtered := handlers[:0]
		for _, h := range handlers {
			if h.id != moduleID {
				filtered = append(filtered, h)
			}
		}
		b.channelHandlers[ch] = filtered
	}

	delete(b.modules, moduleID)
}

func (b *bus) Subscribe(eventType EventType, handler Handler) (unsubscribe func()) {
	if handler == nil {
		panic(fmt.Sprintf("bus: Subscribe called with nil handler for %s", eventType))
	}
	id := newID()
	b.mu.Lock()
	b.typeHandlers[eventType] = append(b.typeHandlers[eventType], namedHandler{id: id, handler: handler})
	b.mu.Unlock()

	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		handlers := b.typeHandlers[eventType]
		filtered := handlers[:0]
		for _, h := range handlers {
			if h.id != id {
				filtered = append(filtered, h)
			}
		}
		b.typeHandlers[eventType] = filtered
	}
}

func (b *bus) Dispatch(e Event) error {
	if e.TTL <= 0 {
		if e.TTL == 0 {
			e.TTL = defaultTTL
		} else {
			log.Printf("[bus] event %s dropped: TTL exhausted", e.Type)
			return nil
		}
	}
	e.TTL--

	if e.Timestamp == 0 {
		e.Timestamp = time.Now().UnixNano()
	}

	// If this event is a response (has ReplyTo), signal any waiting Request.
	if e.ReplyTo != "" {
		b.pendingMu.Lock()
		ch, found := b.pending[e.ReplyTo]
		b.pendingMu.Unlock()
		if found {
			select {
			case ch <- e:
			default:
			}
		}
	}

	channel := e.Type.Channel()

	// Gate check: drop events for gated channels until the gate is open.
	b.gateMu.RLock()
	isGated := b.gatedChannels[channel]
	open := b.gateOpen
	b.gateMu.RUnlock()
	if isGated && !open {
		log.Printf("[bus] event %s dropped: gate closed for channel %s", e.Type, channel)
		return nil
	}

	b.mu.RLock()
	chHandlers := make([]Handler, 0)
	for _, h := range b.channelHandlers[channel] {
		chHandlers = append(chHandlers, h.handler)
	}
	for _, h := range b.typeHandlers[e.Type] {
		chHandlers = append(chHandlers, h.handler)
	}
	b.mu.RUnlock()

	for _, h := range chHandlers {
		h := h
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[bus] PANIC in handler for %s: %v\nStack:\n%s",
						e.Type, r, debug.Stack())
				}
			}()
			if err := h(e); err != nil {
				log.Printf("[bus] handler error for %s: %v", e.Type, err)
			}
		}()
	}

	return nil
}

func (b *bus) Request(ctx context.Context, e Event) (Event, error) {
	if e.ID == "" {
		e.ID = newID()
	}

	replyCh := make(chan Event, 1)

	b.pendingMu.Lock()
	b.pending[e.ID] = replyCh
	b.pendingMu.Unlock()

	defer func() {
		b.pendingMu.Lock()
		delete(b.pending, e.ID)
		b.pendingMu.Unlock()
	}()

	if err := b.Dispatch(e); err != nil {
		return Event{}, err
	}

	select {
	case reply := <-replyCh:
		return reply, nil
	case <-ctx.Done():
		return Event{}, ctx.Err()
	case <-b.ctx.Done():
		return Event{}, fmt.Errorf("bus shut down")
	}
}

func (b *bus) Shutdown(ctx context.Context) error {
	b.mu.RLock()
	mods := make([]Module, 0, len(b.modules))
	for _, m := range b.modules {
		mods = append(mods, m)
	}
	b.mu.RUnlock()

	var wg sync.WaitGroup
	for _, m := range mods {
		m := m
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.Stop(); err != nil {
				log.Printf("[bus] module %s stop error: %v", m.ID(), err)
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}

	b.cancel()
	return nil
}

// NewEvent creates an outbound event with a fresh UUID and current timestamp.
func NewEvent(origin string, t EventType, payload []byte) Event {
	return Event{
		ID:        newID(),
		Type:      t,
		Payload:   payload,
		Origin:    origin,
		Timestamp: time.Now().UnixNano(),
		TTL:       defaultTTL,
	}
}

// ReplyEvent creates a response event for a given request event.
func ReplyEvent(origin string, t EventType, req Event, payload []byte) Event {
	e := NewEvent(origin, t, payload)
	e.ReplyTo = req.ID
	return e
}
