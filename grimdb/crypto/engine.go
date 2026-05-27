package crypto

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// KeyLen is the required length for all ChaCha20-Poly1305 keys.
const KeyLen = chacha20poly1305.KeySize // 32

// ValidateKeyLength returns nil if key is exactly 32 bytes, otherwise an error.
func ValidateKeyLength(key []byte) error {
	if len(key) == 0 {
		return fmt.Errorf("crypto/engine: key is empty (vault may be locked)")
	}
	if len(key) != KeyLen {
		return fmt.Errorf("crypto/engine: invalid key length %d (want %d)", len(key), KeyLen)
	}
	return nil
}

// ValidateAndNewCipher wraps chacha20poly1305.New with strict key-length checking.
// It returns a more informative error than the standard library's opaque message.
func ValidateAndNewCipher(key []byte) (cipher interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}, err error) {
	if err := ValidateKeyLength(key); err != nil {
		return nil, err
	}
	c, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("crypto/engine: cipher creation failed: %w", err)
	}
	return c, nil
}
