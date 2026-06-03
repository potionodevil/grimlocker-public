package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// DeriveArgon2id derives a key from password using Argon2id.
func (p *provider) DeriveArgon2id(password []byte, opts KDFOptions) ([]byte, error) {
	if len(opts.Salt) == 0 {
		return nil, fmt.Errorf("argon2id: salt is required")
	}
	if opts.KeyLen == 0 {
		opts.KeyLen = 32
	}
	if opts.Time == 0 {
		opts.Time = DefaultKDFOptions.Time
	}
	if opts.Memory == 0 {
		opts.Memory = DefaultKDFOptions.Memory
	}
	if opts.Threads == 0 {
		opts.Threads = DefaultKDFOptions.Threads
	}

	key := argon2.IDKey(password, opts.Salt, opts.Time, opts.Memory, opts.Threads, opts.KeyLen)
	return key, nil
}

// HMACKey derives a 32-byte HMAC key from mvk using HMAC-SHA256.
func (p *provider) HMACKey(mvk []byte) [32]byte {
	h := hmac.New(sha256.New, mvk)
	h.Write([]byte("grimlocker-hmac-v1"))
	result := h.Sum(nil)
	var key [32]byte
	copy(key[:], result)
	return key
}
