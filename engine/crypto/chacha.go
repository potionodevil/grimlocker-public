package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Encrypt returns ChaCha20-Poly1305 AEAD ciphertext.
// key must be 32 bytes. nonce must be 12 bytes.
func (p *provider) Encrypt(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("chacha: invalid key")
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("chacha: invalid nonce")
	}

	cipher, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("chacha: create cipher: %w", err)
	}

	return cipher.Seal(nil, nonce, plaintext, aad), nil
}

// Decrypt verifies the authentication tag and returns plaintext.
func (p *provider) Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("chacha: invalid key")
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("chacha: invalid nonce")
	}

	cipher, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("chacha: create cipher: %w", err)
	}

	plaintext, err := cipher.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("chacha: authentication failed")
	}
	return plaintext, nil
}

// NewNonce generates a cryptographically-random 12-byte nonce.
func (p *provider) NewNonce() ([12]byte, error) {
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, fmt.Errorf("nonce: %w", err)
	}
	return nonce, nil
}
