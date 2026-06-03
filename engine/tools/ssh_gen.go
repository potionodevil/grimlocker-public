package tools

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// SSHKeyPair holds a freshly generated Ed25519 key pair in OpenSSH-compatible
// formats. The private key is in PEM-encoded OpenSSH private key format so it
// can be written directly to ~/.ssh/id_ed25519. The public key is in the
// authorized_keys line format ("ssh-ed25519 AAAA… comment").
type SSHKeyPair struct {
	// PublicKey is the OpenSSH authorized_keys format, e.g.
	// "ssh-ed25519 AAAAC3Nza… user@host"
	PublicKey string `json:"public_key"`

	// PrivateKeyPEM is the OpenSSH PEM-encoded private key.
	// This is the sensitive field — it must be stored encrypted in the vault.
	PrivateKeyPEM []byte `json:"-"` // never serialized in JSON responses

	// Fingerprint is the SHA-256 fingerprint in the format "SHA256:…"
	Fingerprint string `json:"fingerprint"`

	// Comment is the key comment appended to the public key line.
	Comment string `json:"comment"`

	// EntryID is populated after the key pair is saved to the vault.
	EntryID string `json:"entry_id,omitempty"`
}

// GenerateEd25519Pair creates a fresh Ed25519 key pair using crypto/rand.
// comment is appended to the public key line (e.g. "user@host" or a label).
// passphrase, if non-empty, is used to encrypt the private key PEM. Pass an
// empty string for an unencrypted PEM (still safe; encryption is provided by
// the vault's MVK layer).
// Returns an SSHKeyPair with PrivateKeyPEM encoded in OpenSSH PEM format.
func GenerateEd25519Pair(comment string, passphrase string) (SSHKeyPair, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SSHKeyPair{}, fmt.Errorf("generate Ed25519 key: %w", err)
	}

	// Marshal the public key into the OpenSSH authorized_keys format.
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return SSHKeyPair{}, fmt.Errorf("marshal SSH public key: %w", err)
	}

	pubLine := string(ssh.MarshalAuthorizedKey(sshPub))
	// ssh.MarshalAuthorizedKey appends a newline — strip it, then append the
	// caller-supplied comment manually so the label is fully controlled.
	if comment != "" {
		if len(pubLine) > 0 && pubLine[len(pubLine)-1] == '\n' {
			pubLine = pubLine[:len(pubLine)-1]
		}
		pubLine = pubLine + " " + comment + "\n"
	}

	// Compute fingerprint (SHA-256 in base64).
	fingerprint := ssh.FingerprintSHA256(sshPub)

	// Marshal the private key in OpenSSH PEM format.
	var privPEM []byte
	if passphrase != "" {
		privPEM, err = marshalEd25519PrivateKeyWithPassphrase(privKey, comment, passphrase)
	} else {
		privPEM, err = marshalEd25519PrivateKey(privKey, comment)
	}
	if err != nil {
		return SSHKeyPair{}, fmt.Errorf("marshal private key: %w", err)
	}

	return SSHKeyPair{
		PublicKey:     pubLine,
		PrivateKeyPEM: privPEM,
		Fingerprint:   fingerprint,
		Comment:       comment,
	}, nil
}

// marshalEd25519PrivateKey encodes an Ed25519 private key as an unencrypted
// OpenSSH PEM block using golang.org/x/crypto/ssh's MarshalPrivateKey function.
func marshalEd25519PrivateKey(key ed25519.PrivateKey, comment string) ([]byte, error) {
	pemBlock, err := ssh.MarshalPrivateKey(key, comment)
	if err != nil {
		return nil, fmt.Errorf("MarshalPrivateKey: %w", err)
	}
	return pem.EncodeToMemory(pemBlock), nil
}

// marshalEd25519PrivateKeyWithPassphrase encodes an Ed25519 private key as a
// passphrase-encrypted OpenSSH PEM block.
func marshalEd25519PrivateKeyWithPassphrase(key ed25519.PrivateKey, comment string, passphrase string) ([]byte, error) {
	pemBlock, err := ssh.MarshalPrivateKeyWithPassphrase(key, comment, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("MarshalPrivateKeyWithPassphrase: %w", err)
	}
	return pem.EncodeToMemory(pemBlock), nil
}

// generateSecurePassphrase generates a cryptographically secure passphrase.
func generateSecurePassphrase(length int) (string, error) {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("passphrase: %w", err)
	}
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b), nil
}
