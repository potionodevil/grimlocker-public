package bridge

import (
	"crypto/sha256"
	"fmt"
	"io"
	"unsafe"

	"golang.org/x/crypto/hkdf"
)

// GoSecureZero overwrites b with zeros in a way the compiler cannot elide.
func GoSecureZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	_ = *(*byte)(unsafe.Pointer(&b))
}

// GoDeriveCoordinate extracts bytes at given offsets from entropyData,
// then runs SHA-256→HKDF to produce a 32-byte key.
func GoDeriveCoordinate(entropyData []byte, offsets []int64) ([]byte, error) {
	extracted := make([]byte, len(offsets))
	for i, off := range offsets {
		if off < 0 || int(off) >= len(entropyData) {
			return nil, fmt.Errorf("coordinate: offset %d out of range", off)
		}
		extracted[i] = entropyData[off]
	}
	h := sha256.Sum256(extracted)
	r := hkdf.New(sha256.New, h[:], nil, []byte("grimlocker-coordinate-salt-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("coordinate: hkdf: %w", err)
	}
	return key, nil
}

// GoDeriveWorkspaceKey derives a workspace-specific key using HKDF-SHA256.
func GoDeriveWorkspaceKey(masterKey []byte, workspaceID string) ([32]byte, error) {
	var key [32]byte
	r := hkdf.New(sha256.New, masterKey, nil, []byte("grimlocker-workspace-v1:"+workspaceID))
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return key, fmt.Errorf("workspace key: hkdf: %w", err)
	}
	return key, nil
}
