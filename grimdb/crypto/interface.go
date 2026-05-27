package crypto

// KDFOptions parameterises the Argon2id key derivation function.
type KDFOptions struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
	Salt    []byte
}

// DefaultKDFOptions matches the parameters used in the existing GrimDB format.
var DefaultKDFOptions = KDFOptions{
	Time:    3,
	Memory:  65536,
	Threads: 2,
	KeyLen:  32,
}

// Provider is the interface for all pure cryptographic operations.
// Implementations MUST be stateless and perform NO file I/O.
type Provider interface {
	// Encrypt returns ChaCha20-Poly1305 ciphertext.
	Encrypt(key, nonce, plaintext, aad []byte) (ciphertext []byte, err error)

	// Decrypt verifies the tag and returns plaintext.
	Decrypt(key, nonce, ciphertext, aad []byte) (plaintext []byte, err error)

	// NewNonce generates a cryptographically-random 12-byte nonce.
	NewNonce() ([12]byte, error)

	// DeriveArgon2id derives a key from password using Argon2id.
	DeriveArgon2id(password []byte, opts KDFOptions) ([]byte, error)

	// DeriveHKDF expands secret into keyLen bytes using HKDF-SHA256.
	DeriveHKDF(secret, salt, info []byte, keyLen int) ([]byte, error)

	// DeriveCoordinate extracts bytes at the given offsets from entropyData,
	// then runs BLAKE3→HKDF to produce a 32-byte key.
	// entropyData is the raw entropy file content (caller loads it).
	DeriveCoordinate(entropyData []byte, offsets []int64) ([]byte, error)

	// DeriveCoordinateOffsets converts an Argon2id hash into 32 file offsets
	// suitable for DeriveXORAsMVK.
	DeriveCoordinateOffsets(argonHash []byte, fileSize int64) ([32]int64, error)

	// DeriveXORAsMVK XORs entropy bytes at the given offsets to produce a 32-byte MVK.
	DeriveXORAsMVK(entropyData []byte, offsets [32]int64) ([32]byte, error)

	// HMACKey derives a 32-byte HMAC key from a MVK.
	HMACKey(mvk []byte) [32]byte

	// SecureZero overwrites b with zeros in a compiler-resistant way.
	SecureZero(b []byte)

	// GenerateEntropyFileWithProgress generates a 2MB entropy file with progress callbacks.
	// progressFn is called periodically with percentage complete (0.0–1.0) and a message.
	GenerateEntropyFileWithProgress(path string, progressFn func(pct float64, msg string)) error

	// DeriveWorkspaceKey derives a workspace-specific encryption key from a master key.
	// Uses HKDF-SHA256 with the workspace ID as the info parameter.
	DeriveWorkspaceKey(masterKey []byte, workspaceID string) ([32]byte, error)
}
