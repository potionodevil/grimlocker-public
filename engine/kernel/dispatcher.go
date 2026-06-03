package kernel

import "context"

// Dispatcher is the sole communication interface between modules.
// Modules MUST NOT import each other; they interact exclusively through Dispatch.
type Dispatcher interface {
	// Dispatch sends an event to all registered handlers for its channel.
	// It is asynchronous — handlers run in their own goroutines.
	Dispatch(e Event) error

	// Request dispatches e and blocks until a response event arrives with
	// ReplyTo == e.ID, or the context is cancelled.
	Request(ctx context.Context, e Event) (Event, error)

	// Subscribe registers a handler for a specific event type.
	// Returns an unsubscribe function that removes the handler.
	Subscribe(eventType EventType, handler Handler) (unsubscribe func())

	// Register adds a Module to the bus, subscribing it to its declared channels.
	Register(m Module) error

	// Unregister removes a module and all its subscriptions.
	Unregister(moduleID string)

	// Shutdown drains in-flight events and stops the bus.
	Shutdown(ctx context.Context) error
}

// Handler is a function that processes a delivered event.
// A non-nil error is logged; it does not stop the bus.
type Handler func(Event) error

// Module is the contract every module must satisfy to plug into the kernel.
type Module interface {
	// ID returns the unique identifier for this module (e.g. "crypto", "storage").
	ID() string

	// Channels returns the event-type channel prefixes this module owns.
	// The bus routes all events whose prefix matches to this module's Handle method.
	// Example: ["CRYPTO"] causes the module to receive all CRYPTO.* events.
	Channels() []string

	// Handle processes a routed event. Called in a dedicated goroutine per event.
	Handle(Event) error

	// Start is called once after registration, before the first event is delivered.
	Start(ctx context.Context, d Dispatcher) error

	// Stop is called during bus Shutdown.
	Stop() error
}
