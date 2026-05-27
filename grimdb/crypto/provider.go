package crypto

import (
	"unsafe"

	rustbridge "github.com/grimlocker/grimdb-public/cgo"
)

// provider is the concrete implementation of Provider.
// It is stateless; all methods are pure functions.
type provider struct{}

// New returns the default Provider implementation.
func New() Provider {
	return &provider{}
}

// SecureZero overwrites b with zeros in a way the compiler cannot elide.
// When CGO is enabled, delegates to Rust's 7-pass secure wipe for added security.
func (p *provider) SecureZero(b []byte) {
	rustbridge.SecureZero(b)
	_ = *(*byte)(unsafe.Pointer(&b))
}

// DeriveWorkspaceKey derives a workspace-specific key from the master key using HKDF-SHA256.
func (p *provider) DeriveWorkspaceKey(masterKey []byte, workspaceID string) ([32]byte, error) {
	return rustbridge.DeriveWorkspaceKey(masterKey, workspaceID)
}
