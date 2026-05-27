package crypto

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/grimlocker/grimdb-public/kernel"
)

const moduleID = "crypto"

// encryptPayload is the JSON schema for CRYPTO.ENCRYPT events.
type encryptPayload struct {
	KeyHandle string `json:"key_handle"`
	Plaintext []byte `json:"plaintext"`
	AAD       []byte `json:"aad,omitempty"`
}

// decryptPayload is the JSON schema for CRYPTO.DECRYPT events.
type decryptPayload struct {
	KeyHandle  string `json:"key_handle"`
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
	AAD        []byte `json:"aad,omitempty"`
}

// derivePayload is the JSON schema for CRYPTO.DERIVE_KEY events.
type derivePayload struct {
	Password []byte     `json:"password"`
	Salt     []byte     `json:"salt"`
	Opts     KDFOptions `json:"opts"`
}

// cryptoResult is the JSON schema for CRYPTO.RESULT events.
type cryptoResult struct {
	Data  []byte `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

// KeyResolver is called by the CryptoModule to retrieve raw key bytes from a
// handle. It is provided by the security.Module to keep key material isolated.
type KeyResolver func(handle string) ([]byte, bool)

// Module is the kernel.Module that handles all CRYPTO.* events.
// It holds no key material itself — keys are fetched via KeyResolver per event.
type Module struct {
	provider    Provider
	keyResolver KeyResolver
	dispatcher  kernel.Dispatcher
}

// NewModule creates the crypto module.
func NewModule(p Provider, kr KeyResolver) *Module {
	return &Module{provider: p, keyResolver: kr}
}

func (m *Module) ID() string         { return moduleID }
func (m *Module) Channels() []string { return []string{"CRYPTO"} }

func (m *Module) Start(ctx context.Context, d kernel.Dispatcher) error {
	m.dispatcher = d
	return nil
}

func (m *Module) Stop() error { return nil }

func (m *Module) Handle(e kernel.Event) error {
	switch e.Type {
	case kernel.EvCryptoEncrypt:
		return m.handleEncrypt(e)
	case kernel.EvCryptoDecrypt:
		return m.handleDecrypt(e)
	case kernel.EvCryptoDerive:
		return m.handleDerive(e)
	default:
		return fmt.Errorf("crypto module: unhandled event %s", e.Type)
	}
}

func (m *Module) handleEncrypt(e kernel.Event) error {
	var p encryptPayload
	if err := json.Unmarshal(e.Payload, &p); err != nil {
		return m.replyError(e, fmt.Errorf("encrypt: unmarshal: %w", err))
	}

	key, ok := m.keyResolver(p.KeyHandle)
	if !ok {
		return m.replyError(e, fmt.Errorf("encrypt: unknown key handle"))
	}

	nonce, err := m.provider.NewNonce()
	if err != nil {
		return m.replyError(e, err)
	}

	ct, err := m.provider.Encrypt(key, nonce[:], p.Plaintext, p.AAD)
	if err != nil {
		return m.replyError(e, err)
	}

	// Prepend nonce to ciphertext so the caller gets a self-contained blob.
	blob := append(nonce[:], ct...)
	return m.replyOK(e, blob)
}

func (m *Module) handleDecrypt(e kernel.Event) error {
	var p decryptPayload
	if err := json.Unmarshal(e.Payload, &p); err != nil {
		return m.replyError(e, fmt.Errorf("decrypt: unmarshal: %w", err))
	}

	key, ok := m.keyResolver(p.KeyHandle)
	if !ok {
		return m.replyError(e, fmt.Errorf("decrypt: unknown key handle"))
	}

	pt, err := m.provider.Decrypt(key, p.Nonce, p.Ciphertext, p.AAD)
	if err != nil {
		return m.replyError(e, err)
	}

	return m.replyOK(e, pt)
}

func (m *Module) handleDerive(e kernel.Event) error {
	var p derivePayload
	if err := json.Unmarshal(e.Payload, &p); err != nil {
		return m.replyError(e, fmt.Errorf("derive: unmarshal: %w", err))
	}

	if p.Opts.KeyLen == 0 {
		p.Opts.KeyLen = 32
	}

	key, err := m.provider.DeriveArgon2id(p.Password, p.Opts)
	if err != nil {
		return m.replyError(e, err)
	}

	return m.replyOK(e, key)
}

func (m *Module) replyOK(req kernel.Event, data []byte) error {
	res, _ := json.Marshal(cryptoResult{Data: data})
	reply := kernel.ReplyEvent(moduleID, kernel.EvCryptoResult, req, res)
	return m.dispatcher.Dispatch(reply)
}

func (m *Module) replyError(req kernel.Event, err error) error {
	res, _ := json.Marshal(cryptoResult{Error: err.Error()})
	reply := kernel.ReplyEvent(moduleID, kernel.EvCryptoResult, req, res)
	if dErr := m.dispatcher.Dispatch(reply); dErr != nil {
		return fmt.Errorf("%w (reply dispatch failed: %v)", err, dErr)
	}
	return err
}
