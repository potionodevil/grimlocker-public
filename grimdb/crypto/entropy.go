package crypto

import (
	"crypto/rand"
	"fmt"
	"os"
)

// GenerateEntropyFileWithProgress generates a random entropy file at the given path,
// calling progressFn periodically with the percentage complete (0.0–1.0) and a message.
// Writes are done in chunks; the total size is 2MB (2097152 bytes).
func (p *provider) GenerateEntropyFileWithProgress(path string, progressFn func(pct float64, msg string)) error {
	const totalSize = 2 * 1024 * 1024 // 2MB
	const chunkSize = 64 * 1024        // 64KB chunks

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open entropy file: %w", err)
	}
	defer f.Close()

	buf := make([]byte, chunkSize)
	written := 0

	for written < totalSize {
		if _, err := rand.Read(buf); err != nil {
			return fmt.Errorf("read entropy: %w", err)
		}

		toWrite := totalSize - written
		if toWrite > len(buf) {
			toWrite = len(buf)
		}

		if _, err := f.Write(buf[:toWrite]); err != nil {
			return fmt.Errorf("write entropy: %w", err)
		}

		written += toWrite

		// Report progress
		pct := float64(written) / float64(totalSize)
		progressFn(pct, fmt.Sprintf("Generated %d / %d bytes", written, totalSize))
	}

	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync entropy file: %w", err)
	}

	return nil
}
