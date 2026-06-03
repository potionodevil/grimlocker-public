// Package provider defines the tier-agnostic abstraction layer for Grimlocker.
//
// The kernel (cmd/daemon/main.go) depends ONLY on the interfaces in this package.
// Concrete implementations live in config/single (LocalAuth, LocalStorage) and
// config/enterprise (IAMProvider, RemoteVault). The event-bus design is
// NOT changed — only the handler implementations are encapsulated here.
package provider

import (
	"github.com/grimlocker/grimdb-public/engine/crypto"
	"github.com/grimlocker/grimdb-public/engine/kernel"
	"github.com/grimlocker/grimdb-public/engine/security"
	"github.com/grimlocker/grimdb-public/engine/storage"
)

// AuthProvider encapsulates the complete authentication logic for a tier.
// The kernel calls HandleUnlockEvent and subscribes it to kernel.EvAuthUnlock.
// Concrete: config/single.LocalAuth (Argon2id) or config/enterprise.OIDCProvider (JWT/OIDC).
type AuthProvider interface {
	// HandleUnlockEvent returns a kernel.Handler that implements the full
	// unlock flow (Steps 0–7 from makeAuthUnlockHandler):
	//   0. Lockdown check
	//   1. Derive & verify MVK
	//   2. Store key in locked memory
	//   3. Wire MVK into blockstore
	//   4. Load block index
	//   5. Dispatch AUTH.KEY_READY to open STORAGE gate
	//   6. Mark session as unlocked
	//   7. Generate session key, record success, emit AUTH.RESULT
	HandleUnlockEvent(
		bus kernel.Dispatcher,
		sessionCtx *security.SessionContext,
		onSessionKey func(key []byte, handle string),
	) kernel.Handler

	// Key-material access — delegated to security.Module internally.
	StoreMVK(key []byte) (string, error)
	RetrieveMVK(handle string) ([]byte, bool)
	RevokeMVK(handle string)

	// Lockdown state and audit log access.
	Lockdown() security.LockdownManager
	AuditLog() security.AuditLog

	// Tier returns the auth mechanism identifier ("local-argon2id" or "oidc-jwt").
	Tier() string
}

// IdentityProvider is an optional extension point for federated identity systems.
// Concrete: future SAML 2.0, LDAP/AD, or multi-tenant IAM implementations.
// Not required for Phase 1 (OIDC is handled directly by OIDCProvider).
type IdentityProvider interface {
	// Protocol returns the identity protocol ("saml2", "ldap", "oidc").
	Protocol() string

	// Validate checks a credential (token, assertion, or bind result) and
	// returns the canonical subject identifier or an error.
	Validate(credential []byte) (subjectID string, err error)
}

// UserAuthenticator manages user identities and credentials for RBAC.
// Single mode: local DB check against stored Argon2id hashes.
// Enterprise mode: delegates to OIDC/LDAP providers.
type UserAuthenticator interface {
	// Authenticate validates a user credential and returns the subject ID.
	// Returns an error if the credential is invalid, expired, or the user
	// does not exist in the identity store.
	Authenticate(credential []byte) (subjectID string, err error)

	// CreateIdentity provisions a new user in the identity store.
	// Single mode: stores Argon2id hash locally.
	// Enterprise mode: no-op (managed by external IAM).
	CreateIdentity(subjectID string, credential []byte) error

	// RevokeIdentity removes a user from the identity store.
	RevokeIdentity(subjectID string) error

	// Lists all known subject IDs.
	ListIdentities() ([]string, error)
}

// AuditLogger records security-relevant operations to a persistent log.
// Concrete: security/audit.go (in-memory ring buffer + optional file sink).
type AuditLogger interface {
	// Log records an event with severity, module, and message.
	Log(level, module, message string, details map[string]string)

	// Query returns recent audit events matching optional filters.
	Query(level string, module string, limit int) []AuditEntry

	// Flush persists buffered audit entries to the configured sink.
	Flush() error
}

// AuditEntry is a single record in the audit log.
type AuditEntry struct {
	Timestamp int64             `json:"timestamp"`
	Level     string            `json:"level"`
	Module    string            `json:"module"`
	Message   string            `json:"message"`
	Details   map[string]string `json:"details,omitempty"`
}

// StorageProvider encapsulates a storage backend for a tier.
// Embeds storage.BlockStore so existing code paths continue to work unchanged.
// Concrete: config/single.LocalStorage (file-backed) or config/enterprise.RemoteVault (S3/MinIO).
type StorageProvider interface {
	storage.BlockStore // WriteBlock/ReadBlock/DeleteBlock/ListBlocks/Flush/Close

	// SetMVKFunc wires the key-retrieval callback used for block encryption.
	SetMVKFunc(fn func() []byte)

	// LoadIndex loads the block index from disk after vault unlock.
	LoadIndex() error

	// KernelModule returns the kernel.Module implementation (the storage adapter)
	// so the daemon can register it with the event bus via reg.Add().
	KernelModule() kernel.Module
}

// VaultProvider is the single entry-point the kernel receives at startup.
// It carries all providers for a specific tier.
// main.go must not import config/single or config/enterprise directly —
// only this interface.
type VaultProvider interface {
	Auth() AuthProvider
	Storage() StorageProvider
	Crypto() crypto.Provider

	// Tier returns a human-readable tier identifier ("single" or "enterprise").
	Tier() string

	// KernelModules returns all kernel.Module instances that must be registered
	// on the event bus (security, crypto, storage adapter — in registration order).
	KernelModules() []kernel.Module
}
