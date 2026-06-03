package tools

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenerateEd25519Pair_BasicShape(t *testing.T) {
	pair, err := GenerateEd25519Pair("test@grimlocker", "")
	if err != nil {
		t.Fatalf("GenerateEd25519Pair: %v", err)
	}

	// Public key line must start with the OpenSSH type prefix.
	if !strings.HasPrefix(pair.PublicKey, "ssh-ed25519 ") {
		t.Errorf("public key does not start with 'ssh-ed25519 ': %q", pair.PublicKey[:min(50, len(pair.PublicKey))])
	}

	// Public key line must contain the comment.
	if !strings.Contains(pair.PublicKey, "test@grimlocker") {
		t.Errorf("public key line missing comment: %q", pair.PublicKey)
	}

	// Private key PEM must be a valid OpenSSH key block.
	if !bytes.Contains(pair.PrivateKeyPEM, []byte("OPENSSH PRIVATE KEY")) {
		t.Errorf("private key PEM missing OPENSSH PRIVATE KEY header")
	}

	// Fingerprint must start with "SHA256:".
	if !strings.HasPrefix(pair.Fingerprint, "SHA256:") {
		t.Errorf("fingerprint unexpected format: %q", pair.Fingerprint)
	}
}

func TestGenerateEd25519Pair_UniqueEachCall(t *testing.T) {
	p1, err := GenerateEd25519Pair("user1", "")
	if err != nil {
		t.Fatalf("GenerateEd25519Pair 1: %v", err)
	}
	p2, err := GenerateEd25519Pair("user2", "")
	if err != nil {
		t.Fatalf("GenerateEd25519Pair 2: %v", err)
	}

	if p1.PublicKey == p2.PublicKey {
		t.Error("two generated key pairs have identical public keys — CSPRNG failure?")
	}
	if p1.Fingerprint == p2.Fingerprint {
		t.Error("two generated key pairs have identical fingerprints")
	}
}

func TestGenerateEd25519Pair_PublicKeyValid(t *testing.T) {
	pair, err := GenerateEd25519Pair("verify@grimlocker", "")
	if err != nil {
		t.Fatalf("GenerateEd25519Pair: %v", err)
	}

	// Parse the OpenSSH authorized_keys line to verify it's a valid Ed25519 key.
	parsed, comment, options, rest, parseErr := ssh.ParseAuthorizedKey([]byte(pair.PublicKey))
	if parseErr != nil {
		t.Fatalf("ssh.ParseAuthorizedKey: %v", parseErr)
	}
	_ = options
	_ = rest

	if parsed.Type() != ssh.KeyAlgoED25519 {
		t.Errorf("expected Ed25519 key type, got %s", parsed.Type())
	}

	if comment != "verify@grimlocker" {
		t.Errorf("expected comment %q, got %q", "verify@grimlocker", comment)
	}

	// The Ed25519 public key is 32 bytes — verify via the CryptoPublicKey interface.
	if cryptoPub, ok := parsed.(ssh.CryptoPublicKey); ok {
		edPub, ok := cryptoPub.CryptoPublicKey().(ed25519.PublicKey)
		if !ok {
			t.Fatal("CryptoPublicKey is not ed25519.PublicKey")
		}
		if len(edPub) != ed25519.PublicKeySize {
			t.Errorf("Ed25519 public key size: got %d, want %d", len(edPub), ed25519.PublicKeySize)
		}
	} else {
		t.Fatal("parsed key does not implement ssh.CryptoPublicKey")
	}
}

func TestGenerateEd25519Pair_EmptyComment(t *testing.T) {
	pair, err := GenerateEd25519Pair("", "")
	if err != nil {
		t.Fatalf("GenerateEd25519Pair with empty comment: %v", err)
	}
	// Must still produce a valid public key line.
	if !strings.HasPrefix(pair.PublicKey, "ssh-ed25519 ") {
		t.Errorf("unexpected public key format: %q", pair.PublicKey)
	}
}

func TestGenerateEd25519Pair_PrivateKeyParseable(t *testing.T) {
	pair, err := GenerateEd25519Pair("parse@test", "")
	if err != nil {
		t.Fatalf("GenerateEd25519Pair: %v", err)
	}

	// Ensure the PEM block is parseable by golang.org/x/crypto/ssh.
	privKey, err := ssh.ParseRawPrivateKey(pair.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("ssh.ParseRawPrivateKey: %v", err)
	}

	ed, ok := privKey.(*ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected *ed25519.PrivateKey, got %T", privKey)
	}

	if len(*ed) != ed25519.PrivateKeySize {
		t.Errorf("private key size: got %d, want %d", len(*ed), ed25519.PrivateKeySize)
	}
}

func TestGenerateEd25519Pair_WithPassphrase(t *testing.T) {
	pair, err := GenerateEd25519Pair("passphrase@test", "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("GenerateEd25519Pair with passphrase: %v", err)
	}

	// The PEM should still be a valid OpenSSH private key block.
	if !bytes.Contains(pair.PrivateKeyPEM, []byte("OPENSSH PRIVATE KEY")) {
		t.Errorf("encrypted private key PEM missing OPENSSH PRIVATE KEY header")
	}

	// Attempting to parse without passphrase must fail.
	_, err = ssh.ParseRawPrivateKey(pair.PrivateKeyPEM)
	if err == nil {
		t.Fatal("expected error when parsing passphrase-protected key without passphrase, got nil")
	}

	// Parsing with the correct passphrase must succeed.
	_, err = ssh.ParseRawPrivateKeyWithPassphrase(pair.PrivateKeyPEM, []byte("correct-horse-battery-staple"))
	if err != nil {
		t.Fatalf("ssh.ParseRawPrivateKeyWithPassphrase: %v", err)
	}
}

func TestGenerateSecurePassphrase(t *testing.T) {
	p1, err := generateSecurePassphrase(32)
	if err != nil {
		t.Fatalf("generateSecurePassphrase: %v", err)
	}
	if len(p1) != 32 {
		t.Errorf("expected passphrase length 32, got %d", len(p1))
	}
	p2, err := generateSecurePassphrase(32)
	if err != nil {
		t.Fatalf("generateSecurePassphrase 2: %v", err)
	}
	if p1 == p2 {
		t.Error("two generated passphrases are identical — CSPRNG failure?")
	}
}
