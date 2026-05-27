//go:build windows

package security

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsMemoryGuard struct{}

// NewMemoryGuard returns a Windows VirtualLock-based MemoryGuard.
func NewMemoryGuard() MemoryGuard { return &windowsMemoryGuard{} }

func (g *windowsMemoryGuard) Lock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if err := windows.VirtualLock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b))); err != nil {
		return fmt.Errorf("VirtualLock: %w", err)
	}
	return nil
}

func (g *windowsMemoryGuard) Unlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if err := windows.VirtualUnlock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b))); err != nil {
		return fmt.Errorf("VirtualUnlock: %w", err)
	}
	return nil
}

func (g *windowsMemoryGuard) Zeroize(b []byte) { zeroize(b) }

func (g *windowsMemoryGuard) CompareConstantTime(a, b []byte) bool {
	return constantTimeEqual(a, b)
}

func (g *windowsMemoryGuard) AllocLocked(size int) ([]byte, error) {
	b := make([]byte, size)
	if err := g.Lock(b); err != nil {
		return nil, err
	}
	return b, nil
}
