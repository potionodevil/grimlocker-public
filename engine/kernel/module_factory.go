// Package kernel (module_factory.go) provides the ModuleConfig, ModuleFactory,
// and BaseModule types that standardise how kernel.Module implementations are
// constructed and registered.
//
// Every Module should:
//  1. Embed BaseModule to get ID()/Channels() for free.
//  2. Accept a ModuleConfig in its constructor instead of positional params.
//  3. Optionally implement ModuleFactory to support generic registration.
//
// Example:
//
//	type MyModule struct {
//	    kernel.BaseModule
//	    // ... fields
//	}
//	func NewMyModule(cfg kernel.ModuleConfig) *MyModule {
//	    return &MyModule{BaseModule: kernel.NewBaseModule(cfg)}
//	}
package kernel

import "context"

// ─── ModuleConfig ─────────────────────────────────────────────────────────────

// ModuleConfig is the canonical set of parameters passed to every Module
// constructor. Using a config struct instead of positional parameters makes
// it easy to add new optional fields without breaking existing call sites.
//
// Modules that do not need all fields simply ignore the unused ones.
type ModuleConfig struct {
	// ID is the unique module identifier (e.g. "crypto", "storage").
	// Must not be empty. Must be unique within the bus.
	ID string

	// Channels lists the channel prefixes this module owns.
	// Example: []string{"CRYPTO"} → module receives all CRYPTO.* events.
	Channels []string

	// Context is the parent context for the module's lifetime.
	// If nil, context.Background() is used.
	Context context.Context

	// DebugLogging enables verbose handler entry/exit logs.
	DebugLogging bool
}

// ─── ModuleFactory ────────────────────────────────────────────────────────────

// ModuleFactory is the interface for creating kernel.Module instances from
// a ModuleConfig. Implementing this interface lets modules be constructed
// generically and registered without knowing their concrete type.
//
// Example:
//
//	type CryptoFactory struct{ provider crypto.Provider }
//	func (f *CryptoFactory) Create(cfg kernel.ModuleConfig) (kernel.Module, error) {
//	    return crypto.NewModule(cfg, f.provider), nil
//	}
type ModuleFactory interface {
	Create(cfg ModuleConfig) (Module, error)
}

// FactoryFunc is a function adapter that implements ModuleFactory.
// Use it to convert a plain constructor function into a ModuleFactory:
//
//	f := kernel.FactoryFunc(func(cfg kernel.ModuleConfig) (kernel.Module, error) {
//	    return mymodule.New(cfg), nil
//	})
type FactoryFunc func(cfg ModuleConfig) (Module, error)

func (f FactoryFunc) Create(cfg ModuleConfig) (Module, error) {
	return f(cfg)
}

// ─── BaseModule ───────────────────────────────────────────────────────────────

// BaseModule provides a default implementation of the ID() and Channels()
// methods of the kernel.Module interface. Embed it in your module struct to
// avoid boilerplate and ensure consistent ID/Channels behaviour.
//
// Modules MUST still implement Handle(), Start(), and Stop() themselves.
//
// Example:
//
//	type MyModule struct {
//	    kernel.BaseModule
//	    // ... other fields
//	}
//	func NewMyModule(cfg kernel.ModuleConfig) *MyModule {
//	    return &MyModule{BaseModule: kernel.NewBaseModule(cfg)}
//	}
type BaseModule struct {
	id       string
	channels []string
}

// NewBaseModule creates a BaseModule from a ModuleConfig.
func NewBaseModule(cfg ModuleConfig) BaseModule {
	return BaseModule{id: cfg.ID, channels: cfg.Channels}
}

// ID implements kernel.Module.
func (b *BaseModule) ID() string { return b.id }

// Channels implements kernel.Module.
func (b *BaseModule) Channels() []string { return b.channels }
