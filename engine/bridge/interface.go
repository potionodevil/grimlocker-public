// Package bridge provides the interface to the Rust secure enclave.
//
// The engine uses this interface for optional hardware-accelerated crypto.
// When the Rust enclave is not available, the DefaultBridge provides pure Go
// fallback implementations.
package bridge

// RustBridge abstracts the Rust secure enclave operations.
type RustBridge interface {
	// InitCore initializes the Rust enclave. Returns nil if unavailable.
	InitCore() error

	// ShutdownCore tears down the Rust enclave.
	ShutdownCore()

	// SecureZero overwrites b with zeros in a compiler-resistant way.
	// When the Rust enclave is available, uses 7-pass secure wipe.
	SecureZero(b []byte)

	// DeriveCoordinate runs BLAKE3→HKDF on entropy data via the enclave.
	// Falls back to SHA-256→HKDF when the enclave is unavailable.
	DeriveCoordinate(entropyData []byte, offsets []int64) ([]byte, error)

	// DeriveWorkspaceKey derives a workspace-specific key from master key.
	DeriveWorkspaceKey(masterKey []byte, workspaceID string) ([32]byte, error)

	// MVKStore stores an MVK in the enclave and returns a handle.
	MVKStore(mvk []byte) (string, error)

	// MVKRevoke revokes an MVK handle in the enclave.
	MVKRevoke(handle string)

	// EncryptHandle encrypts data using a session key handle in the enclave.
	EncryptHandle(handle string, plaintext, aad []byte) ([]byte, error)

	// DecryptHandle decrypts data using a session key handle in the enclave.
	DecryptHandle(handle string, ciphertext, aad []byte) ([]byte, error)

	// GenerateEntropyFile generates an entropy file via the enclave.
	GenerateEntropyFile(path string, lineCount int) error
}

// DefaultBridge provides pure Go fallback implementations for the RustBridge interface.
type DefaultBridge struct{}

func (DefaultBridge) InitCore() error                                         { return nil }
func (DefaultBridge) ShutdownCore()                                           {}
func (DefaultBridge) SecureZero(b []byte)                                     { GoSecureZero(b) }
func (DefaultBridge) DeriveCoordinate(entropyData []byte, offsets []int64) ([]byte, error)     { return GoDeriveCoordinate(entropyData, offsets) }
func (DefaultBridge) DeriveWorkspaceKey(masterKey []byte, workspaceID string) ([32]byte, error) { return GoDeriveWorkspaceKey(masterKey, workspaceID) }
func (DefaultBridge) MVKStore(mvk []byte) (string, error)                    { return "", nil }
func (DefaultBridge) MVKRevoke(handle string)                                 {}
func (DefaultBridge) EncryptHandle(handle string, plaintext, aad []byte) ([]byte, error) { return nil, nil }
func (DefaultBridge) DecryptHandle(handle string, ciphertext, aad []byte) ([]byte, error) { return nil, nil }
func (DefaultBridge) GenerateEntropyFile(path string, lineCount int) error    { return nil }
