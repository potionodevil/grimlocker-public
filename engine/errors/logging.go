// Package errors (logging.go) defines StructuredLogger — the logging interface
// used across all Grimlocker modules — and StdLogger, its standard-library
// implementation.
//
// Modules should accept a StructuredLogger as a dependency rather than calling
// log.Printf directly. This decouples business logic from log formatting and
// makes log output testable.
//
// To attach a GrimlockError to a log entry with its full context (code,
// operation, block ID, stacktrace), use the Log method on the error itself:
//
//	if ge, ok := err.(*errors.GrimlockError); ok {
//	    ge.WithModule("storage").Log(logger)
//	}
//
// To replace StdLogger with zerolog, zap, or slog, implement the three-method
// StructuredLogger interface and inject it into the module constructors.
package errors

import (
	"fmt"
	"log"
	"strings"
)

// ErrorLevel classifies the severity of a GrimlockError for terminal display.
type ErrorLevel int

const (
	LevelInfo     ErrorLevel = iota // Informational — no action required
	LevelWarn                       // Warning — degraded operation
	LevelError                      // Error — operation failed
	LevelCritical                   // Critical — system stability at risk
	LevelSecurity                   // Security event — auth/policy/lockdown
)

// levelLabel returns the terminal label for an error level.
func levelLabel(level ErrorLevel) string {
	switch level {
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelCritical:
		return "CRITICAL"
	case LevelSecurity:
		return "SECURITY"
	default:
		return "ERROR"
	}
}

// ErrorRemediation maps error codes to a brief recovery hint shown in the
// terminal output. Operators use this to diagnose issues without reading source.
var ErrorRemediation = map[int]string{
	ErrCodeVaultLocked:         "Unlock the vault first (send AUTH.UNLOCK)",
	ErrCodeVaultNotInitialized: "Run vault setup (send VAULT.INIT)",
	ErrCodeAuthInvalid:         "Check your password and try again",
	ErrCodeAuthLockdown:        "Too many failed attempts — wait for lockout to expire",
	ErrCodeStorageIO:           "Check vault file permissions and available disk space",
	ErrCodeStorageCorruption:   "Vault data may be corrupted — check HMAC and backup",
	ErrCodeStorageNotFound:     "Block does not exist — it may have been deleted",
	ErrCodeStorageIndexFailed:  "Index persist failed — check disk space and permissions",
	ErrCodeCryptoDecryption:    "Decryption failed — wrong key or tampered data",
	ErrCodeCryptoInvalidKey:    "Key material is nil or wrong length (need 32 bytes)",
	ErrCodeSecurityMemlock:     "Cannot lock memory — check OS limits (ulimit -l)",
	ErrCodeSecurityLockdown:    "Hard lockdown — restart daemon and re-enter password",
	ErrCodeSecurityMVKMissing:  "Vault is locked — unlock before this operation",
	ErrCodeBusTimeout:          "Request timed out — daemon may be overloaded",
	ErrCodeProtocolInvalid:     "Binary frame is malformed — check client version",
}

// Remediation returns a human-readable recovery hint for this error.
// Returns a generic message if no specific hint is registered.
func (e *GrimlockError) Remediation() string {
	if hint, ok := ErrorRemediation[e.Code]; ok {
		return hint
	}
	return "Check daemon logs for details"
}

// ConsoleFormat formats the error for readable terminal output.
// Shows code, message, operation, cause, and remediation hint.
// Does NOT include stacktrace (use Log for that).
func (e *GrimlockError) ConsoleFormat() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("[Code %d] %s", e.Code, e.Message))
	if e.Ctx.Operation != "" {
		b.WriteString(fmt.Sprintf("\n        Operation:   %s", e.Ctx.Operation))
	}
	if e.Ctx.BlockID != "" {
		b.WriteString(fmt.Sprintf("\n        BlockID:     %s", e.Ctx.BlockID))
	}
	if e.Cause != nil {
		b.WriteString(fmt.Sprintf("\n        Cause:       %s", e.Cause.Error()))
	}
	for k, v := range e.Ctx.Details {
		b.WriteString(fmt.Sprintf("\n        %s: %s", k, v))
	}
	b.WriteString(fmt.Sprintf("\n        Remediation: %s", e.Remediation()))
	return b.String()
}

// ─── StructuredLogger interface ───────────────────────────────────────────────

// StructuredLogger is the logging interface used across all Grimlocker modules.
// Pass it as a dependency — never call log.Printf directly from module code.
type StructuredLogger interface {
	Debug(msg string, fields map[string]any)
	Info(msg string, fields map[string]any)
	Warn(msg string, fields map[string]any)
	Error(msg string, err error, fields map[string]any)
	Fatal(msg string, err error, fields map[string]any)
}

// ─── Log method on GrimlockError ─────────────────────────────────────────────

// Log writes a structured representation of this error to the provided logger.
// Call this at the top of a handler after receiving a GrimlockError.
func (e *GrimlockError) Log(logger StructuredLogger) {
	fields := map[string]any{
		"error_code": e.Code,
		"module":     e.ModuleID,
		"operation":  e.Ctx.Operation,
	}
	if e.Ctx.BlockID != "" {
		fields["block_id"] = e.Ctx.BlockID
	}
	for k, v := range e.Ctx.Details {
		fields["detail_"+k] = v
	}
	if e.EventType != "" {
		fields["event_type"] = e.EventType
	}
	if len(e.Stack) > 0 {
		frames := make([]string, 0, len(e.Stack))
		for _, f := range e.Stack {
			frames = append(frames, f.String())
		}
		fields["stacktrace"] = frames
	}

	logger.Error(e.Message, e.Cause, fields)
}

// ─── StdLogger — wraps the standard library log package ──────────────────────

// StdLogger wraps the standard library log package as a StructuredLogger.
// Each field is appended as key=value to the log line.
// Replace with a structured logging library (zerolog, zap, slog) in production.
type StdLogger struct {
	// Prefix is prepended to every log line, e.g. "[security]".
	Prefix string
	// DebugEnabled controls whether Debug messages are emitted.
	DebugEnabled bool
}

func (l *StdLogger) format(level, msg string, fields map[string]any) string {
	var b strings.Builder
	if l.Prefix != "" {
		b.WriteString(l.Prefix)
		b.WriteString(" ")
	}
	b.WriteString(fmt.Sprintf("[%s] %s", level, msg))
	for k, v := range fields {
		b.WriteString(fmt.Sprintf(" %s=%v", k, v))
	}
	return b.String()
}

func (l *StdLogger) Debug(msg string, fields map[string]any) {
	if !l.DebugEnabled {
		return
	}
	log.Print(l.format("DEBUG", msg, fields))
}

func (l *StdLogger) Info(msg string, fields map[string]any) {
	log.Print(l.format("INFO", msg, fields))
}

func (l *StdLogger) Warn(msg string, fields map[string]any) {
	log.Print(l.format("WARN", msg, fields))
}

func (l *StdLogger) Error(msg string, err error, fields map[string]any) {
	if err != nil {
		if fields == nil {
			fields = make(map[string]any)
		}
		// If the error is a GrimlockError, use ConsoleFormat for richer output.
		if ge, ok := err.(*GrimlockError); ok {
			fields["grimlock_error"] = ge.ConsoleFormat()
		} else {
			fields["error"] = err.Error()
		}
	}
	log.Print(l.format("ERROR", msg, fields))
}

func (l *StdLogger) Fatal(msg string, err error, fields map[string]any) {
	if err != nil {
		if fields == nil {
			fields = make(map[string]any)
		}
		fields["error"] = err.Error()
	}
	log.Fatal(l.format("FATAL", msg, fields))
}

// NewStdLogger creates a StdLogger for the given module prefix.
func NewStdLogger(modulePrefix string) *StdLogger {
	return &StdLogger{Prefix: modulePrefix}
}

// NewDebugLogger creates a StdLogger with debug output enabled.
func NewDebugLogger(modulePrefix string) *StdLogger {
	return &StdLogger{Prefix: modulePrefix, DebugEnabled: true}
}
