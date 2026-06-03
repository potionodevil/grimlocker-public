package kernel

import (
	"context"
	"fmt"
)

// Registry wraps a Dispatcher and provides ordered module startup.
type Registry struct {
	bus     Dispatcher
	started []Module
}

// NewRegistry creates a Registry backed by the given Dispatcher.
func NewRegistry(d Dispatcher) *Registry {
	return &Registry{bus: d}
}

// Add registers a module with the bus and records it for ordered startup.
func (r *Registry) Add(m Module) error {
	if err := r.bus.Register(m); err != nil {
		return fmt.Errorf("register %s: %w", m.ID(), err)
	}
	r.started = append(r.started, m)
	return nil
}

// StartAll calls Start on every registered module in registration order.
func (r *Registry) StartAll(ctx context.Context) error {
	for _, m := range r.started {
		if err := m.Start(ctx, r.bus); err != nil {
			return fmt.Errorf("start %s: %w", m.ID(), err)
		}
	}
	return nil
}

// Bus returns the underlying Dispatcher for use by non-module code (e.g. api layer).
func (r *Registry) Bus() Dispatcher {
	return r.bus
}

// Modules returns a copy of the registered module list.
func (r *Registry) Modules() []Module {
	mods := make([]Module, len(r.started))
	copy(mods, r.started)
	return mods
}
