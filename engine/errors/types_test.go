package errors_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	gerrors "github.com/grimlocker/grimdb-public/engine/errors"
)

// ─── Error Code Constants ─────────────────────────────────────────────────────

func TestErrorCodeConstants(t *testing.T) {
	cases := []struct {
		name string
		code int
		low  int
		high int
	}{
		{"VaultLocked", gerrors.ErrCodeVaultLocked, 1000, 1999},
		{"AuthInvalid", gerrors.ErrCodeAuthInvalid, 1000, 1999},
		{"AuthLockdown", gerrors.ErrCodeAuthLockdown, 1000, 1999},
		{"StorageIO", gerrors.ErrCodeStorageIO, 2000, 2999},
		{"StorageCorruption", gerrors.ErrCodeStorageCorruption, 2000, 2999},
		{"StorageNotFound", gerrors.ErrCodeStorageNotFound, 2000, 2999},
		{"CryptoDecryption", gerrors.ErrCodeCryptoDecryption, 3000, 3999},
		{"CryptoEncryption", gerrors.ErrCodeCryptoEncryption, 3000, 3999},
		{"CryptoKeyDerivation", gerrors.ErrCodeCryptoKeyDerivation, 3000, 3999},
		{"SecurityMemlock", gerrors.ErrCodeSecurityMemlock, 4000, 4999},
		{"SecurityLockdown", gerrors.ErrCodeSecurityLockdown, 4000, 4999},
		{"BusTimeout", gerrors.ErrCodeBusTimeout, 5000, 5999},
		{"BusShutdown", gerrors.ErrCodeBusShutdown, 5000, 5999},
		{"ProtocolInvalid", gerrors.ErrCodeProtocolInvalid, 6000, 6999},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.code < tc.low || tc.code > tc.high {
				t.Errorf("code %d out of expected range [%d, %d]", tc.code, tc.low, tc.high)
			}
		})
	}
}

// ─── Error() Formatting ───────────────────────────────────────────────────────

func TestGrimlockError_Error_WithCause(t *testing.T) {
	cause := errors.New("disk full")
	e := gerrors.NewStorageIOError("write_block", "block-abc", cause)

	msg := e.Error()
	if !strings.Contains(msg, "2001") {
		t.Errorf("expected error code in message, got: %s", msg)
	}
	if !strings.Contains(msg, "disk full") {
		t.Errorf("expected cause in message, got: %s", msg)
	}
}

func TestGrimlockError_Error_WithoutCause(t *testing.T) {
	e := gerrors.NewVaultLockedError()
	msg := e.Error()
	if !strings.Contains(msg, "1001") {
		t.Errorf("expected error code 1001 in message, got: %s", msg)
	}
	if !strings.Contains(msg, "vault is locked") {
		t.Errorf("expected message text, got: %s", msg)
	}
}

// ─── Unwrap / errors.Is ───────────────────────────────────────────────────────

func TestGrimlockError_Unwrap(t *testing.T) {
	cause := errors.New("original cause")
	e := gerrors.NewStorageIOError("write_block", "id", cause)

	if !errors.Is(e, cause) {
		t.Error("errors.Is should find the wrapped cause via Unwrap()")
	}
}

func TestGrimlockError_Is_SameCode(t *testing.T) {
	e1 := gerrors.NewVaultLockedError()
	sentinel := gerrors.Sentinel(gerrors.ErrCodeVaultLocked, "vault locked")

	if !errors.Is(e1, sentinel) {
		t.Error("errors.Is should match GrimlockErrors with the same code")
	}
}

func TestGrimlockError_Is_DifferentCode(t *testing.T) {
	e1 := gerrors.NewVaultLockedError()
	e2 := gerrors.NewStorageNotFoundError("block-xyz")

	if errors.Is(e1, e2) {
		t.Error("errors.Is should NOT match GrimlockErrors with different codes")
	}
}

// ─── HTTP Status Mapping ──────────────────────────────────────────────────────

func TestHTTPStatus(t *testing.T) {
	cases := []struct {
		err      *gerrors.GrimlockError
		expected int
	}{
		{gerrors.NewVaultLockedError(), http.StatusLocked},
		{gerrors.NewAuthInvalidError("password", nil), http.StatusUnauthorized},
		{gerrors.NewAuthLockdownError(0), http.StatusTooManyRequests},
		{gerrors.NewStorageNotFoundError("x"), http.StatusNotFound},
		{gerrors.NewStorageCorruptionError("hmac", "x", nil), http.StatusUnprocessableEntity},
		{gerrors.NewCryptoDecryptionError("x", nil), http.StatusUnprocessableEntity},
		{gerrors.NewBusTimeoutError("STORAGE.READ"), http.StatusGatewayTimeout},
		{gerrors.NewProtocolError("parse", nil), http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.err.Message, func(t *testing.T) {
			got := tc.err.HTTPStatus()
			if got != tc.expected {
				t.Errorf("HTTPStatus() = %d, want %d", got, tc.expected)
			}
		})
	}
}

// ─── MarshalJSON ──────────────────────────────────────────────────────────────

func TestGrimlockError_MarshalJSON(t *testing.T) {
	e := gerrors.NewStorageIOError("write_block", "block-123", errors.New("disk full"))
	data, err := e.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "2001") {
		t.Errorf("expected code in JSON, got: %s", s)
	}
	if !strings.Contains(s, "block-123") {
		t.Errorf("expected block_id in JSON, got: %s", s)
	}
	// Cause should NOT appear as plain text (it is excluded from JSON)
	// but the message should appear.
	if !strings.Contains(s, "storage I/O failure") {
		t.Errorf("expected message in JSON, got: %s", s)
	}
}

// ─── Stacktrace ───────────────────────────────────────────────────────────────

func TestGrimlockError_StacktracePresent(t *testing.T) {
	// Storage IO errors capture a stacktrace.
	e := gerrors.NewStorageIOError("write_block", "id", errors.New("oops"))
	if len(e.Stack) == 0 {
		t.Error("expected stacktrace to be captured for StorageIOError")
	}
}

func TestGrimlockError_NoStacktraceForVaultLocked(t *testing.T) {
	// VaultLocked is a hot-path — no stacktrace overhead.
	e := gerrors.NewVaultLockedError()
	if len(e.Stack) != 0 {
		t.Error("VaultLockedError should not capture a stacktrace")
	}
}

// ─── Wrap ─────────────────────────────────────────────────────────────────────

func TestWrap_PlainError(t *testing.T) {
	plain := errors.New("some stdlib error")
	wrapped := gerrors.Wrap(gerrors.ErrCodeStorageIO, "storage failed", plain)
	if wrapped.Code != gerrors.ErrCodeStorageIO {
		t.Errorf("Wrap() code = %d, want %d", wrapped.Code, gerrors.ErrCodeStorageIO)
	}
	if !errors.Is(wrapped, plain) {
		t.Error("Wrap() should wrap the original error")
	}
}

func TestWrap_AlreadyGrimlockError(t *testing.T) {
	original := gerrors.NewVaultLockedError()
	wrapped := gerrors.Wrap(gerrors.ErrCodeStorageIO, "ignored msg", original)
	// Should return the original unchanged.
	if wrapped.Code != gerrors.ErrCodeVaultLocked {
		t.Errorf("Wrap() of GrimlockError should return original, got code %d", wrapped.Code)
	}
}

func TestWrap_Nil(t *testing.T) {
	if gerrors.Wrap(gerrors.ErrCodeStorageIO, "msg", nil) != nil {
		t.Error("Wrap(nil) should return nil")
	}
}
