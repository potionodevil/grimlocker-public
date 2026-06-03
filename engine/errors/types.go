package errors

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ─── Error Code Ranges ────────────────────────────────────────────────────────
//
//	1000-1999  Vault / Auth
//	2000-2999  Storage / GrimDB
//	3000-3999  Crypto / Key-material
//	4000-4999  Security / Lockdown / Memory
//	5000-5999  Kernel / Bus / Event
//	6000-6999  API / Protocol / Transport

// ─── Auth Errors (1000-1999) ──────────────────────────────────────────────────

const (
	ErrCodeVaultLocked         = 1001 // Vault must be unlocked first
	ErrCodeVaultNotInitialized = 1002 // Vault has not been set up yet
	ErrCodeAuthInvalid         = 1003 // Password or token is wrong
	ErrCodeAuthTimeout         = 1004 // Auth operation timed out
	ErrCodeAuthLockdown        = 1005 // Too many failed attempts; vault is locked out
	ErrCodeAuthSetupFailed     = 1006 // Vault initialization failed
	ErrCodeAuthTokenExpired    = 1007 // OIDC/JWT token expired (enterprise)
)

// ─── Storage Errors (2000-2999) ───────────────────────────────────────────────

const (
	ErrCodeStorageIO           = 2001 // Disk read/write failure
	ErrCodeStorageCorruption   = 2002 // HMAC mismatch or JSON malformed — data may be tampered
	ErrCodeStorageNotFound     = 2003 // Block ID does not exist in index
	ErrCodeStorageQuota        = 2004 // Storage quota exceeded
	ErrCodeStorageIndexFailed  = 2005 // Index persist or load failed
	ErrCodeStorageNonceFailed  = 2006 // Nonce generation failed (CSPRNG)
)

// ─── Crypto Errors (3000-3999) ────────────────────────────────────────────────

const (
	ErrCodeCryptoKeyDerivation = 3001 // Argon2id / HKDF derivation failed
	ErrCodeCryptoEncryption    = 3002 // ChaCha20-Poly1305 Seal failed
	ErrCodeCryptoDecryption    = 3003 // ChaCha20-Poly1305 Open failed (wrong key or tampered)
	ErrCodeCryptoInvalidKey    = 3004 // Key material nil or wrong length (must be 32 bytes)
	ErrCodeCryptoEntropyFailed = 3005 // CSPRNG / entropy source failed
	ErrCodeCryptoHandleUnknown = 3006 // Key handle not found in security module
)

// ─── Security Errors (4000-4999) ──────────────────────────────────────────────

const (
	ErrCodeSecurityMemlock     = 4001 // mlock / VirtualLock failed — cannot protect key in memory
	ErrCodeSecurityLockdown    = 4002 // Hard lockdown triggered; key material zeroed
	ErrCodeSecurityIntegrity   = 4003 // Binary integrity check failed
	ErrCodeSecurityUnauthorized = 4004 // Operation denied by security policy
	ErrCodeSecurityMVKMissing  = 4005 // MVK handle missing or revoked
)

// ─── Kernel / Bus Errors (5000-5999) ─────────────────────────────────────────

const (
	ErrCodeBusShutdown        = 5001 // Bus is shutting down; cannot dispatch
	ErrCodeBusTimeout         = 5002 // Request timed out waiting for reply
	ErrCodeBusGated           = 5003 // Event dropped: channel is gated (vault locked)
	ErrCodeBusTTL             = 5004 // Event dropped: TTL exhausted
	ErrCodeBusModuleDuplicate = 5005 // Module with this ID already registered
	ErrCodeBusNilHandler      = 5006 // Subscribe called with nil handler
)

// ─── API / Protocol Errors (6000-6999) ───────────────────────────────────────

const (
	ErrCodeProtocolInvalid  = 6001 // Binary frame malformed or unknown message type
	ErrCodeProtocolTimeout  = 6002 // Client request timed out
	ErrCodeProtocolUnhandled = 6003 // No handler registered for action
	ErrCodeProtocolAuth     = 6004 // WebSocket / IPC authentication failed
)

// ─── Core Error Type ──────────────────────────────────────────────────────────

// ErrorContext carries structured diagnostic data attached to every GrimlockError.
// Fields are optional — only fill what is relevant for the error site.
type ErrorContext struct {
	// BlockID is the GrimDB block identifier (for storage errors).
	BlockID string `json:"block_id,omitempty"`

	// Operation is the logical operation that failed (e.g. "read_block", "decrypt_index").
	Operation string `json:"operation,omitempty"`

	// Details holds additional key-value pairs for debugging.
	Details map[string]string `json:"details,omitempty"`
}

// GrimlockError is the unified error type returned by all Grimlocker modules.
// It wraps a cause, carries a numeric error code, and optionally captures
// a stacktrace at the creation site.
type GrimlockError struct {
	// Code is one of the ErrCode* constants defined above.
	Code int `json:"code"`

	// Message is a short, human-readable description.
	Message string `json:"message"`

	// Ctx carries structured diagnostic information.
	Ctx ErrorContext `json:"context,omitempty"`

	// Stack is the captured call-stack at error creation.
	// Only populated when CaptureStack is true in the constructor.
	Stack []StackFrame `json:"stacktrace,omitempty"`

	// Cause is the underlying error from a standard library or third-party package.
	Cause error `json:"-"`

	// Timestamp is when the error was created (Unix nanoseconds).
	Timestamp int64 `json:"timestamp"`

	// ModuleID identifies which module produced the error.
	ModuleID string `json:"module_id,omitempty"`

	// EventType is the bus event type during which the error occurred.
	EventType string `json:"event_type,omitempty"`
}

// Error implements the error interface.
func (e *GrimlockError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%d] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%d] %s", e.Code, e.Message)
}

// Unwrap implements errors.Unwrap — allows errors.Is / errors.As to traverse the chain.
func (e *GrimlockError) Unwrap() error { return e.Cause }

// Is returns true if the target is a *GrimlockError with the same Code.
func (e *GrimlockError) Is(target error) bool {
	t, ok := target.(*GrimlockError)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

// HTTPStatus maps an error code to an appropriate HTTP status code.
func (e *GrimlockError) HTTPStatus() int {
	switch {
	case e.Code == ErrCodeVaultLocked:
		return http.StatusLocked // 423
	case e.Code == ErrCodeVaultNotInitialized:
		return http.StatusNotFound // 404
	case e.Code == ErrCodeAuthInvalid, e.Code == ErrCodeAuthTokenExpired:
		return http.StatusUnauthorized // 401
	case e.Code == ErrCodeAuthLockdown:
		return http.StatusTooManyRequests // 429
	case e.Code == ErrCodeStorageNotFound:
		return http.StatusNotFound // 404
	case e.Code == ErrCodeStorageCorruption, e.Code == ErrCodeCryptoDecryption:
		return http.StatusUnprocessableEntity // 422
	case e.Code == ErrCodeSecurityUnauthorized, e.Code == ErrCodeSecurityLockdown:
		return http.StatusForbidden // 403
	case e.Code == ErrCodeProtocolInvalid:
		return http.StatusBadRequest // 400
	case e.Code == ErrCodeBusTimeout, e.Code == ErrCodeProtocolTimeout:
		return http.StatusGatewayTimeout // 504
	default:
		return http.StatusInternalServerError // 500
	}
}

// MarshalJSON produces a JSON representation safe for sending to clients.
// The Cause chain is not serialized — only Message + Code + Context.
func (e *GrimlockError) MarshalJSON() ([]byte, error) {
	type wire struct {
		Code      int          `json:"code"`
		Message   string       `json:"message"`
		Ctx       ErrorContext `json:"context,omitempty"`
		Stack     []StackFrame `json:"stacktrace,omitempty"`
		Timestamp int64        `json:"timestamp"`
		ModuleID  string       `json:"module_id,omitempty"`
		EventType string       `json:"event_type,omitempty"`
	}
	return json.Marshal(wire{
		Code:      e.Code,
		Message:   e.Message,
		Ctx:       e.Ctx,
		Stack:     e.Stack,
		Timestamp: e.Timestamp,
		ModuleID:  e.ModuleID,
		EventType: e.EventType,
	})
}

// ─── Constructor Helpers ──────────────────────────────────────────────────────

func newError(code int, msg string, cause error, ctx ErrorContext, captureStack bool) *GrimlockError {
	var stack []StackFrame
	if captureStack {
		// skip=2: skip newError + the public constructor above it
		stack = CaptureStacktrace(2)
	}
	return &GrimlockError{
		Code:      code,
		Message:   msg,
		Cause:     cause,
		Ctx:       ctx,
		Stack:     stack,
		Timestamp: time.Now().UnixNano(),
	}
}

// ─── Auth Constructors ────────────────────────────────────────────────────────

// NewVaultLockedError is returned when an operation requires an unlocked vault.
func NewVaultLockedError() *GrimlockError {
	return newError(ErrCodeVaultLocked, "vault is locked", nil,
		ErrorContext{Operation: "vault_access"}, false)
}

// NewAuthInvalidError is returned when a password or token is wrong.
func NewAuthInvalidError(operation string, cause error) *GrimlockError {
	return newError(ErrCodeAuthInvalid, "authentication failed", cause,
		ErrorContext{Operation: operation}, true)
}

// NewAuthLockdownError is returned when too many failed attempts trigger lockout.
func NewAuthLockdownError(attemptsRemaining int) *GrimlockError {
	return newError(ErrCodeAuthLockdown, "vault locked out after too many failed attempts", nil,
		ErrorContext{
			Operation: "auth_lockdown",
			Details:   map[string]string{"remaining_attempts": fmt.Sprintf("%d", attemptsRemaining)},
		}, false)
}

// NewVaultNotInitializedError is returned when the vault has not been set up.
func NewVaultNotInitializedError() *GrimlockError {
	return newError(ErrCodeVaultNotInitialized, "vault not initialized — run setup first", nil,
		ErrorContext{Operation: "vault_init_check"}, false)
}

// ─── Storage Constructors ─────────────────────────────────────────────────────

// NewStorageIOError wraps a low-level I/O failure with block and operation context.
func NewStorageIOError(operation, blockID string, cause error) *GrimlockError {
	return newError(ErrCodeStorageIO, "storage I/O failure", cause,
		ErrorContext{Operation: operation, BlockID: blockID}, true)
}

// NewStorageCorruptionError is returned when an HMAC check or JSON parse fails —
// the data on disk may have been tampered with.
func NewStorageCorruptionError(operation, blockID string, details map[string]string) *GrimlockError {
	return newError(ErrCodeStorageCorruption, "storage data corruption detected", nil,
		ErrorContext{Operation: operation, BlockID: blockID, Details: details}, true)
}

// NewStorageNotFoundError is returned when a block ID is missing from the index.
func NewStorageNotFoundError(blockID string) *GrimlockError {
	return newError(ErrCodeStorageNotFound, fmt.Sprintf("block not found: %s", blockID), nil,
		ErrorContext{Operation: "block_lookup", BlockID: blockID}, false)
}

// NewStorageIndexError wraps a failure during index persist or load.
func NewStorageIndexError(operation string, cause error) *GrimlockError {
	return newError(ErrCodeStorageIndexFailed, "vault index operation failed", cause,
		ErrorContext{Operation: operation}, true)
}

// ─── Crypto Constructors ──────────────────────────────────────────────────────

// NewCryptoDecryptionError is returned when ChaCha20-Poly1305 Open fails.
// This means either wrong key material or tampered ciphertext.
func NewCryptoDecryptionError(blockID string, cause error) *GrimlockError {
	return newError(ErrCodeCryptoDecryption, "decryption failed — wrong key or data tampered", cause,
		ErrorContext{Operation: "chacha20poly1305_open", BlockID: blockID}, true)
}

// NewCryptoEncryptionError is returned when Seal fails.
func NewCryptoEncryptionError(operation string, cause error) *GrimlockError {
	return newError(ErrCodeCryptoEncryption, "encryption failed", cause,
		ErrorContext{Operation: operation}, true)
}

// NewCryptoKeyDerivationError is returned when Argon2id or HKDF fails.
func NewCryptoKeyDerivationError(operation string, cause error) *GrimlockError {
	return newError(ErrCodeCryptoKeyDerivation, "key derivation failed", cause,
		ErrorContext{Operation: operation}, true)
}

// NewCryptoInvalidKeyError is returned when key material is nil or wrong length.
func NewCryptoInvalidKeyError(got int) *GrimlockError {
	return newError(ErrCodeCryptoInvalidKey,
		fmt.Sprintf("invalid key length: got %d bytes, need 32", got), nil,
		ErrorContext{Operation: "key_validation",
			Details: map[string]string{"got_bytes": fmt.Sprintf("%d", got)}}, true)
}

// NewCryptoHandleUnknownError is returned when a key handle is not found.
func NewCryptoHandleUnknownError(handle string) *GrimlockError {
	return newError(ErrCodeCryptoHandleUnknown, "key handle not found", nil,
		ErrorContext{Operation: "key_resolve",
			Details: map[string]string{"handle_prefix": safePrefix(handle, 8)}}, false)
}

// ─── Security Constructors ────────────────────────────────────────────────────

// NewSecurityMemlockError is returned when mlock or VirtualLock fails.
func NewSecurityMemlockError(cause error) *GrimlockError {
	return newError(ErrCodeSecurityMemlock, "cannot lock memory — key material may be swappable", cause,
		ErrorContext{Operation: "memlock_alloc"}, true)
}

// NewSecurityLockdownError is returned when a hard lockdown is triggered.
func NewSecurityLockdownError(reason string, details map[string]string) *GrimlockError {
	return newError(ErrCodeSecurityLockdown, "hard lockdown triggered — all key material zeroed", nil,
		ErrorContext{Operation: "hard_lockdown", Details: details}, true)
}

// NewSecurityMVKMissingError is returned when an MVK handle is not found or revoked.
func NewSecurityMVKMissingError(operation string) *GrimlockError {
	return newError(ErrCodeSecurityMVKMissing, "master vault key not available — vault locked?", nil,
		ErrorContext{Operation: operation}, false)
}

// ─── Kernel / Bus Constructors ────────────────────────────────────────────────

// NewBusTimeoutError is returned when a Request times out.
func NewBusTimeoutError(eventType string) *GrimlockError {
	return newError(ErrCodeBusTimeout, "event request timed out", nil,
		ErrorContext{Operation: "bus_request",
			Details: map[string]string{"event_type": eventType}}, false)
}

// NewBusShutdownError is returned when a dispatch is attempted after shutdown.
func NewBusShutdownError() *GrimlockError {
	return newError(ErrCodeBusShutdown, "bus is shutting down", nil,
		ErrorContext{Operation: "bus_dispatch"}, false)
}

// NewBusGatedError is returned when an event is dropped because the gate is closed.
func NewBusGatedError(eventType, channel string) *GrimlockError {
	return newError(ErrCodeBusGated, "event dropped: vault not unlocked", nil,
		ErrorContext{Operation: "gate_check",
			Details: map[string]string{
				"event_type": eventType,
				"channel":    channel,
			}}, false)
}

// ─── API / Protocol Constructors ─────────────────────────────────────────────

// NewProtocolError is returned when a binary frame or JSON payload is malformed.
func NewProtocolError(operation string, cause error) *GrimlockError {
	return newError(ErrCodeProtocolInvalid, "protocol error — invalid message format", cause,
		ErrorContext{Operation: operation}, true)
}

// ─── Utility ─────────────────────────────────────────────────────────────────

// safePrefix returns the first n chars of s, or s if shorter.
// Used to include partial handle info in errors without leaking full handles.
func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Wrap converts a plain error into a GrimlockError with the given code.
// If err is already a *GrimlockError it is returned unchanged.
// Useful for wrapping third-party errors at module boundaries.
func Wrap(code int, msg string, err error) *GrimlockError {
	if err == nil {
		return nil
	}
	if ge, ok := err.(*GrimlockError); ok {
		return ge
	}
	return newError(code, msg, err, ErrorContext{}, true)
}

// Sentinel returns a GrimlockError that can be used with errors.Is comparisons.
// Sentinels never capture a stacktrace (they are value types, not instances).
func Sentinel(code int, msg string) *GrimlockError {
	return &GrimlockError{Code: code, Message: msg}
}

// WithDetails adds a key-value pair to the error's context details.
// Returns the same *GrimlockError for chaining.
func (e *GrimlockError) WithDetails(key string, value interface{}) *GrimlockError {
	if e.Ctx.Details == nil {
		e.Ctx.Details = make(map[string]string)
	}
	e.Ctx.Details[key] = fmt.Sprintf("%v", value)
	return e
}

// WithModule sets the ModuleID field and returns the same error for chaining.
func (e *GrimlockError) WithModule(moduleID string) *GrimlockError {
	e.ModuleID = moduleID
	return e
}

// WithEvent sets the EventType field and returns the same error for chaining.
func (e *GrimlockError) WithEvent(eventType string) *GrimlockError {
	e.EventType = eventType
	return e
}
