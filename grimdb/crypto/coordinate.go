package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	rustbridge "github.com/grimlocker/grimdb-public/cgo"
)

func (p *provider) DeriveXORAsMVK(entropyData []byte, offsets [32]int64) ([32]byte, error) {
	var mvk [32]byte
	for i, off := range offsets {
		if off < 0 || int(off) >= len(entropyData) {
			return mvk, fmt.Errorf("mvk: offset %d out of bounds (file size %d)", off, len(entropyData))
		}
		mvk[i] ^= entropyData[off]
	}
	return mvk, nil
}

func (p *provider) DeriveCoordinate(entropyData []byte, offsets []int64) ([]byte, error) {
	result, err := rustbridge.DeriveCoordinate(entropyData, offsets)
	if err == nil {
		return result, nil
	}

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

func (p *provider) DeriveCoordinateOffsets(argonHash []byte, fileSize int64) ([32]int64, error) {
	if fileSize <= 0 {
		return [32]int64{}, fmt.Errorf("coordinate offsets: invalid file size %d", fileSize)
	}

	r := hkdf.New(sha256.New, argonHash, nil, []byte("grimlocker-coordinates-v1"))
	buf := make([]byte, 128)
	if _, err := io.ReadFull(r, buf); err != nil {
		return [32]int64{}, fmt.Errorf("coordinate offsets: hkdf: %w", err)
	}

	var offsets [32]int64
	for i := 0; i < 32; i++ {
		val := binary.BigEndian.Uint32(buf[i*4 : i*4+4])
		offsets[i] = int64(uint64(val) % uint64(fileSize))
	}
	return offsets, nil
}
