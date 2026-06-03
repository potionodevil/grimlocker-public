// Package kernel (handler.go) provides the HandlerBuilder — a fluent API for
// composing bus.Handler functions with cross-cutting concerns.
//
// Instead of writing raw handler functions that mix business logic with
// error recovery and logging, use HandlerBuilder to layer decorators:
//
//	h := kernel.NewHandlerBuilder(myHandlerFunc).
//	    WithRecovery("[mymodule]"). // catches panics → converts to error
//	    WithLogging("[mymodule]").  // logs timing + errors
//	    Build()
//	bus.Subscribe(kernel.EvMyEvent, h)
//
// Decorators are applied outermost-first, so the first decorator added
// becomes the outermost layer (e.g. Recovery wraps Logging wraps the base).
package kernel

import (
	"log"
	"runtime/debug"
	"time"
)

// ─── HandlerBuilder ───────────────────────────────────────────────────────────

// HandlerBuilder constructs a Handler by layering decorators over a base function.
// Call Build() to obtain the final composed Handler.
//
// Usage:
//
//	h := kernel.NewHandlerBuilder(myHandlerFunc).
//	    WithLogging("[mymodule]").
//	    WithRecovery("[mymodule]").
//	    Build()
//	bus.Subscribe(kernel.EvMyEvent, h)
type HandlerBuilder struct {
	base       Handler
	decorators []func(Handler) Handler
}

// NewHandlerBuilder creates a HandlerBuilder wrapping the given base Handler.
func NewHandlerBuilder(h Handler) *HandlerBuilder {
	return &HandlerBuilder{base: h}
}

// WithRecovery adds a panic-recovery layer. Any panic in the inner handler is
// caught, logged with a stack trace, and converted to a non-nil error return.
// This prevents a misbehaving handler from killing the goroutine silently.
func (b *HandlerBuilder) WithRecovery(modulePrefix string) *HandlerBuilder {
	b.decorators = append(b.decorators, func(next Handler) Handler {
		return func(e Event) (retErr error) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("%s PANIC in handler for %s: %v\nStack:\n%s",
						modulePrefix, e.Type, r, debug.Stack())
					// Do not re-panic — return an error instead so the bus
					// can log it and continue serving other events.
					retErr = &handlerPanicError{event: string(e.Type), value: r}
				}
			}()
			return next(e)
		}
	})
	return b
}

// WithLogging adds structured logging before and after the handler.
// At DEBUG level: logs entry + exit timing.
// On error: logs the error with event type.
func (b *HandlerBuilder) WithLogging(modulePrefix string) *HandlerBuilder {
	b.decorators = append(b.decorators, func(next Handler) Handler {
		return func(e Event) error {
			start := time.Now()
			err := next(e)
			if err != nil {
				log.Printf("%s handler error event=%s elapsed=%s err=%v",
					modulePrefix, e.Type, time.Since(start).Round(time.Microsecond), err)
			} else {
				log.Printf("%s [DEBUG] handler ok event=%s elapsed=%s",
					modulePrefix, e.Type, time.Since(start).Round(time.Microsecond))
			}
			return err
		}
	})
	return b
}

// WithMetrics adds basic timing metrics. Currently logs to the standard logger;
// replace the implementation with your metrics backend (Prometheus, etc.).
func (b *HandlerBuilder) WithMetrics(modulePrefix, eventLabel string) *HandlerBuilder {
	b.decorators = append(b.decorators, func(next Handler) Handler {
		return func(e Event) error {
			start := time.Now()
			err := next(e)
			status := "ok"
			if err != nil {
				status = "error"
			}
			log.Printf("%s [METRIC] event=%s status=%s duration_us=%d",
				modulePrefix, eventLabel, status, time.Since(start).Microseconds())
			return err
		}
	})
	return b
}

// Build applies all registered decorators (outermost-first) and returns the
// final composed Handler ready for registration with the bus.
func (b *HandlerBuilder) Build() Handler {
	h := b.base
	// Apply in reverse so that the first decorator added is the outermost layer.
	for i := len(b.decorators) - 1; i >= 0; i-- {
		h = b.decorators[i](h)
	}
	return h
}

// ─── Standalone Decorator Functions ──────────────────────────────────────────

// WithRecovery wraps a single Handler with panic recovery. Prefer HandlerBuilder
// for chaining multiple decorators; use this for one-off subscriptions.
func WithRecovery(modulePrefix string, h Handler) Handler {
	return NewHandlerBuilder(h).WithRecovery(modulePrefix).Build()
}

// WithLogging wraps a single Handler with entry/exit logging.
func WithLogging(modulePrefix string, h Handler) Handler {
	return NewHandlerBuilder(h).WithLogging(modulePrefix).Build()
}

// ─── Internal types ───────────────────────────────────────────────────────────

// handlerPanicError is the synthetic error produced by WithRecovery.
type handlerPanicError struct {
	event string
	value interface{}
}

func (e *handlerPanicError) Error() string {
	return "panic in handler for " + e.event + ": recovered"
}
