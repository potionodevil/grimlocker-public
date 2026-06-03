package crypto

import (
	"github.com/grimlocker/grimdb-public/engine/bridge"
)

// provider is the concrete implementation of Provider.
// It delegates Rust-enclave operations to the injected bridge.
type provider struct {
	rb bridge.RustBridge
}

// New returns a Provider backed by the given RustBridge.
// Pass the DefaultBridge for pure Go fallback (no Rust enclave).
func New(rb bridge.RustBridge) Provider {
	return &provider{rb: rb}
}

// Bridge returns the underlying RustBridge instance.
// Used by consumers that need direct access to enclave operations.
func (p *provider) Bridge() bridge.RustBridge {
	return p.rb
}

// SecureZero overwrites b with zeros.
func (p *provider) SecureZero(b []byte) {
	p.rb.SecureZero(b)
}

// DeriveCoordinate delegates to the bridge for BLAKE3-accelerated path.
func (p *provider) DeriveCoordinate(entropyData []byte, offsets []int64) ([]byte, error) {
	return p.rb.DeriveCoordinate(entropyData, offsets)
}

// DeriveWorkspaceKey delegates to the bridge for enclave-accelerated derivation.
func (p *provider) DeriveWorkspaceKey(masterKey []byte, workspaceID string) ([32]byte, error) {
	return p.rb.DeriveWorkspaceKey(masterKey, workspaceID)
}
