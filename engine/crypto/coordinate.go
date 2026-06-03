package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
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
