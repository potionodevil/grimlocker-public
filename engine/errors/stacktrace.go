// Package errors provides the unified typed error system for Grimlocker Omega+.
//
// Every module returns *GrimlockError instead of plain Go errors.
// This gives each failure a numeric code, structured context (block ID,
// operation name, key-value details), an optional stacktrace captured at the
// error creation site, and an HTTP status mapping for the REST/WebSocket API.
//
// Error code ranges:
//
//	1000–1999  Vault / Authentication  (ErrCodeVaultLocked, ErrCodeAuthInvalid …)
//	2000–2999  Storage / GrimDB        (ErrCodeStorageIO, ErrCodeStorageCorruption …)
//	3000–3999  Cryptography            (ErrCodeCryptoDecryption, ErrCodeCryptoInvalidKey …)
//	4000–4999  Security / Lockdown     (ErrCodeSecurityMemlock, ErrCodeSecurityLockdown …)
//	5000–5999  Kernel / Bus            (ErrCodeBusTimeout, ErrCodeBusGated …)
//	6000–6999  API / Protocol          (ErrCodeProtocolInvalid …)
//
// Quick usage:
//
//	return gerrors.NewStorageIOError("read_block", blockID, err)
//
//	return gerrors.NewAuthInvalidError("jwt_verification", err).
//	    WithModule("oidc-auth").
//	    WithDetails("subject", claims.Subject)
//
//	wrapped := gerrors.Wrap(gerrors.ErrCodeStorageIO, "blockstore failed", err)
//
// See docs/ERROR_CODES.md for a full per-code reference with recovery steps.
// See docs/API_REFERENCE.md for the complete GrimlockError struct/method docs.
package errors

import (
	"fmt"
	"runtime"
)

const maxStackFrames = 20

// StackFrame is a single call-stack frame.
type StackFrame struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Function string `json:"function"`
}

func (f StackFrame) String() string {
	return fmt.Sprintf("%s:%d in %s", f.File, f.Line, f.Function)
}

// CaptureStacktrace captures up to maxStackFrames of call stack,
// skipping `skip` additional frames above the caller.
// skip=0 → first frame is the direct caller of CaptureStacktrace.
// skip=1 → first frame is the caller's caller (use this from error constructors).
func CaptureStacktrace(skip int) []StackFrame {
	pcs := make([]uintptr, maxStackFrames)
	// +2: skip runtime.Callers itself and this function
	n := runtime.Callers(skip+2, pcs)
	if n == 0 {
		return nil
	}

	frames := runtime.CallersFrames(pcs[:n])
	result := make([]StackFrame, 0, n)
	for {
		frame, more := frames.Next()
		result = append(result, StackFrame{
			File:     frame.File,
			Line:     frame.Line,
			Function: frame.Function,
		})
		if !more {
			break
		}
	}
	return result
}
