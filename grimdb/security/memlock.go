package security

import "unsafe"

// MemoryGuard provides OS-level memory protection primitives.
// Implementations are platform-specific (memlock_unix.go / memlock_windows.go).
type MemoryGuard interface {
	// Lock pins the memory region, preventing it from being swapped to disk.
	Lock(b []byte) error

	// Unlock releases a previously locked region.
	Unlock(b []byte) error

	// Zeroize overwrites b with zeros in a way the compiler cannot elide.
	Zeroize(b []byte)

	// CompareConstantTime returns true iff a and b are equal.
	// The comparison runs in constant time regardless of content.
	CompareConstantTime(a, b []byte) bool

	// AllocLocked allocates a zeroed, memory-locked buffer of the given size.
	AllocLocked(size int) ([]byte, error)
}

// zeroize overwrites b with zeros in a way the compiler cannot elide.
// Used by all platform implementations.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
	// Prevent the compiler from optimising out the loop.
	_ = *(*byte)(unsafe.Pointer(&b))
}
