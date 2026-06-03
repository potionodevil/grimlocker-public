package kernel_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/grimlocker/grimdb-public/engine/kernel"
)

// ─── HandlerBuilder — WithRecovery ────────────────────────────────────────────

func TestWithRecovery_NoPanic(t *testing.T) {
	called := false
	h := kernel.NewHandlerBuilder(func(e kernel.Event) error {
		called = true
		return nil
	}).WithRecovery("[test]").Build()

	err := h(kernel.Event{Type: "TEST.EVENT"})
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
	if !called {
		t.Error("handler was not called")
	}
}

func TestWithRecovery_CatchesPanic(t *testing.T) {
	h := kernel.NewHandlerBuilder(func(e kernel.Event) error {
		panic("deliberate test panic")
	}).WithRecovery("[test]").Build()

	// Should NOT panic out of the test; should return an error instead.
	err := h(kernel.Event{Type: "TEST.PANIC"})
	if err == nil {
		t.Error("expected a non-nil error from a recovered panic")
	}
	if !strings.Contains(err.Error(), "panic") {
		t.Errorf("error message should mention panic, got: %s", err.Error())
	}
}

func TestWithRecovery_PropagatesError(t *testing.T) {
	sentinel := errors.New("handler error")
	h := kernel.NewHandlerBuilder(func(e kernel.Event) error {
		return sentinel
	}).WithRecovery("[test]").Build()

	err := h(kernel.Event{Type: "TEST.ERR"})
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got: %v", err)
	}
}

// ─── HandlerBuilder — WithLogging ─────────────────────────────────────────────

func TestWithLogging_DoesNotChangeReturn(t *testing.T) {
	sentinel := errors.New("log test error")
	h := kernel.NewHandlerBuilder(func(e kernel.Event) error {
		return sentinel
	}).WithLogging("[test]").Build()

	err := h(kernel.Event{Type: "TEST.LOG"})
	if !errors.Is(err, sentinel) {
		t.Errorf("WithLogging changed return value, got: %v", err)
	}
}

func TestWithLogging_SuccessReturnsNil(t *testing.T) {
	h := kernel.NewHandlerBuilder(func(e kernel.Event) error {
		return nil
	}).WithLogging("[test]").Build()

	if err := h(kernel.Event{Type: "TEST.OK"}); err != nil {
		t.Errorf("expected nil, got: %v", err)
	}
}

// ─── Decorator Chaining ───────────────────────────────────────────────────────

func TestChaining_RecoveryAndLogging(t *testing.T) {
	order := []string{}
	h := kernel.NewHandlerBuilder(func(e kernel.Event) error {
		order = append(order, "handler")
		return nil
	}).
		WithLogging("[test]").
		WithRecovery("[test]").
		Build()

	if err := h(kernel.Event{Type: "TEST.CHAIN"}); err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
	if len(order) != 1 || order[0] != "handler" {
		t.Errorf("handler not called correctly, order=%v", order)
	}
}

func TestChaining_PanicWithLogging(t *testing.T) {
	// Recovery should still work when logging is also applied.
	h := kernel.NewHandlerBuilder(func(e kernel.Event) error {
		panic("chained panic")
	}).
		WithLogging("[test]").
		WithRecovery("[test]").
		Build()

	err := h(kernel.Event{Type: "TEST.CHAIN_PANIC"})
	if err == nil {
		t.Error("expected error from chained panic recovery")
	}
}

// ─── Standalone Decorators ────────────────────────────────────────────────────

func TestWithRecovery_Standalone(t *testing.T) {
	h := kernel.WithRecovery("[standalone]", func(e kernel.Event) error {
		panic("standalone panic")
	})
	if err := h(kernel.Event{Type: "TEST.STANDALONE"}); err == nil {
		t.Error("expected error from standalone panic recovery")
	}
}

func TestWithLogging_Standalone(t *testing.T) {
	sentinel := errors.New("standalone log error")
	h := kernel.WithLogging("[standalone]", func(e kernel.Event) error {
		return sentinel
	})
	if !errors.Is(h(kernel.Event{Type: "TEST.STANDALONE"}), sentinel) {
		t.Error("WithLogging standalone changed return value")
	}
}

// ─── BaseModule ───────────────────────────────────────────────────────────────

func TestBaseModule_IDAndChannels(t *testing.T) {
	cfg := kernel.ModuleConfig{
		ID:       "test-module",
		Channels: []string{"TEST", "EXTRA"},
	}
	bm := kernel.NewBaseModule(cfg)

	if bm.ID() != "test-module" {
		t.Errorf("ID() = %q, want %q", bm.ID(), "test-module")
	}
	if len(bm.Channels()) != 2 {
		t.Errorf("Channels() len = %d, want 2", len(bm.Channels()))
	}
}
