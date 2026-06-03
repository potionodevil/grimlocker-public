package crypto

import (
	"crypto/rand"
	"fmt"
	"io"
)

const shredPasses = 7
const shredBufSize = 65536

// Shred overwrites the entire content of w with shredPasses passes of random data.
// The caller is responsible for opening the file, truncating it, and syncing after.
// This design ensures /crypto performs zero file I/O itself.
func Shred(w io.WriteSeeker, fileSize int64) error {
	buf := make([]byte, shredBufSize)

	for pass := 0; pass < shredPasses; pass++ {
		if _, err := w.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("shred pass %d seek: %w", pass, err)
		}

		remaining := fileSize
		for remaining > 0 {
			chunk := int64(len(buf))
			if remaining < chunk {
				chunk = remaining
			}
			if _, err := rand.Read(buf[:chunk]); err != nil {
				return fmt.Errorf("shred pass %d rand: %w", pass, err)
			}
			if _, err := w.Write(buf[:chunk]); err != nil {
				return fmt.Errorf("shred pass %d write: %w", pass, err)
			}
			remaining -= chunk
		}
	}

	return nil
}
