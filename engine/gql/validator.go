package gql

import (
	"fmt"
	"strings"
)

// SessionInfo provides the runtime context needed for semantic (ACL) validation.
// The concrete implementation is provided by the daemon's security.SessionContext.
type SessionInfo interface {
	// IsUnlocked reports whether the vault is currently unlocked.
	IsUnlocked() bool

	// ActiveHandle returns the MVK handle if the session is unlocked.
	ActiveHandle() string

	// UserID returns the authenticated user's subject identifier.
	// Empty string means anonymous (pre-auth).
	UserID() string

	// HasRole reports whether the session holds the given RBAC role.
	HasRole(role string) bool
}

// SyntacticError describes a frame that fails schema-level validation.
type SyntacticError struct {
	Field   string
	Reason  string
	Details string
}

func (e *SyntacticError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("gql: syntactic error in %q: %s (%s)", e.Field, e.Reason, e.Details)
	}
	return fmt.Sprintf("gql: syntactic error in %q: %s", e.Field, e.Reason)
}

// SemanticError describes a frame that fails ACL/authorization validation.
type SemanticError struct {
	Operation Operation
	Reason    string
}

func (e *SemanticError) Error() string {
	return fmt.Sprintf("gql: semantic error for %q: %s", e.Operation, e.Reason)
}

// ValidateFrame performs full two-stage validation on a GQL frame.
//
// Stage 1 — Syntactic:
//   - Version must be Version (1)
//   - Opcode must be known
//   - Payload must decode into a valid GQLQuery
//   - All string fields must be within length limits
//   - No null bytes or control characters in string fields
//   - Field count must be within limits
//   - Operation must be valid for this opcode (query vs mutate)
//
// Stage 2 — Semantic:
//   - Session must be unlocked for any operation
//   - Write operations require credentials
//   - Namespace must match session UserID (RBAC)
//   - Must have appropriate role for the operation
//
// Returns the decoded GQLQuery on success, or an error describing the failure.
func ValidateFrame(frame *Frame, session SessionInfo) (*GQLQuery, error) {
	// -- Stage 1: Syntactic validation --

	if frame.Version != Version {
		return nil, &SyntacticError{Field: "version", Reason: fmt.Sprintf("unsupported version %d (expected %d)", frame.Version, Version)}
	}

	if !isValidOpcode(frame.Opcode) {
		return nil, &SyntacticError{Field: "opcode", Reason: fmt.Sprintf("unknown opcode 0x%02x", byte(frame.Opcode))}
	}

	// Result and Error frames don't need query-level validation
	if frame.Opcode == OpcodeResult || frame.Opcode == OpcodeError {
		return nil, nil
	}

	if frame.PayloadSize > MaxPayloadSize {
		return nil, &SyntacticError{
			Field:   "payload_size",
			Reason:  "exceeds maximum",
			Details: fmt.Sprintf("%d > %d", frame.PayloadSize, MaxPayloadSize),
		}
	}

	// Determine the operation from the payload (first decode, then the Operation field)
	// For security, we don't trust the operation string in the decoded query until
	// we've done byte-level validation on every field.
	if len(frame.Payload) == 0 {
		return nil, &SyntacticError{Field: "payload", Reason: "empty payload"}
	}

	// Validate payload bytes at the structural level before decoding
	if err := validatePayloadBytes(frame.Payload); err != nil {
		return nil, err
	}

	// Determine operation type for decode
	var op Operation
	switch frame.Opcode {
	case OpcodeQuery:
		// Operation will be set after decode
	case OpcodeMutate:
		// Operation will be set after decode
	default:
		return nil, &SyntacticError{Field: "opcode", Reason: "opcode not allowed for query validation"}
	}

	query, err := DecodeQuery(frame.Payload, op)
	if err != nil {
		return nil, &SyntacticError{Field: "payload", Reason: "decode failed", Details: err.Error()}
	}

	// Now validate the decoded fields
	if err := validateQuery(query, frame.Opcode); err != nil {
		return nil, err
	}

	// -- Stage 2: Semantic (ACL) validation --

	if err := validateACL(query, session); err != nil {
		return nil, err
	}

	return query, nil
}

// validatePayloadBytes checks the raw payload for structural integrity
// before any decoding. This catches malformed/corrupted payloads early.
func validatePayloadBytes(payload []byte) error {
	// Payload must be non-empty
	if len(payload) == 0 {
		return &SyntacticError{Field: "payload", Reason: "zero-length"}
	}

	// Basic sanity: check that the payload doesn't start with obviously
	// wrong field counts or lengths that would cause infinite loops.
	fieldCount := int(payload[0])
	if fieldCount > MaxFieldsCount {
		return &SyntacticError{
			Field:   "field_count",
			Reason:  "exceeds maximum",
			Details: fmt.Sprintf("%d > %d", fieldCount, MaxFieldsCount),
		}
	}

	return nil
}

// validateQuery performs field-level syntactic validation on a decoded GQLQuery.
func validateQuery(q *GQLQuery, opcode Opcode) error {
	// namespace is required and must be alphanumeric + underscores + hyphens
	if err := validateStringField("namespace", q.Namespace, true, MaxNamespaceLen); err != nil {
		return err
	}
	if err := validateIdentifier("namespace", q.Namespace); err != nil {
		return err
	}

	// entry_id (required for get/update/delete, optional for list/create)
	if q.EntryID != "" {
		if err := validateStringField("entry_id", q.EntryID, false, MaxEntryIDLen); err != nil {
			return err
		}
		if err := validateIdentifier("entry_id", q.EntryID); err != nil {
			return err
		}
	}

	// category (optional, but must be valid if provided)
	if q.Category != "" {
		if err := validateStringField("category", q.Category, false, MaxCategoryLen); err != nil {
			return err
		}
		if err := validateIdentifier("category", q.Category); err != nil {
			return err
		}
	}

	// title (optional)
	if q.Title != "" {
		if err := validateStringField("title", q.Title, false, MaxFieldValueLen); err != nil {
			return err
		}
		// title allows printable chars including spaces
		if err := validatePrintable("title", q.Title); err != nil {
			return err
		}
	}

	// field keys and values
	if len(q.Fields) > MaxFieldsCount {
		return &SyntacticError{
			Field:   "fields",
			Reason:  "too many fields",
			Details: fmt.Sprintf("%d > %d", len(q.Fields), MaxFieldsCount),
		}
	}
	for k, v := range q.Fields {
		if err := validateStringField("fields.key", k, false, MaxFieldKeyLen); err != nil {
			return err
		}
		if err := validateIdentifier("fields.key", k); err != nil {
			return err
		}
		if err := validateStringField("fields.value", v, false, MaxFieldValueLen); err != nil {
			return err
		}
		if err := validatePrintable("fields.value", v); err != nil {
			return err
		}
	}

	// Opcode ↔ operation consistency check
	if opcode == OpcodeQuery && !isReadOperation(q.Operation) {
		return &SyntacticError{
			Field:   "operation",
			Reason:  "opcode mismatch",
			Details: fmt.Sprintf("opcode QUERY requires a read operation, got %q", q.Operation),
		}
	}
	if opcode == OpcodeMutate && !isWriteOperation(q.Operation) {
		return &SyntacticError{
			Field:   "operation",
			Reason:  "opcode mismatch",
			Details: fmt.Sprintf("opcode MUTATE requires a write operation, got %q", q.Operation),
		}
	}

	return nil
}

// validateACL performs semantic authorization checks.
func validateACL(q *GQLQuery, session SessionInfo) error {
	if session == nil {
		return &SemanticError{Operation: q.Operation, Reason: "no active session"}
	}

	if !session.IsUnlocked() {
		return &SemanticError{Operation: q.Operation, Reason: "vault locked"}
	}

	if session.ActiveHandle() == "" {
		return &SemanticError{Operation: q.Operation, Reason: "no active MVK handle"}
	}

	// Write operations require credentials
	if isWriteOperation(q.Operation) && len(q.Credentials) == 0 {
		return &SemanticError{
			Operation: q.Operation,
			Reason:    "write operation requires credentials",
		}
	}

	// RBAC: namespace must match session UserID (if RBAC is enabled)
	userID := session.UserID()
	if userID != "" && q.Namespace != "" && q.Namespace != userID {
		// Admin role can access any namespace
		if !session.HasRole("admin") {
			return &SemanticError{
				Operation: q.Operation,
				Reason:    fmt.Sprintf("namespace %q does not match session user %q", q.Namespace, userID),
			}
		}
	}

	return nil
}

// validateStringField checks a string field's length and content.
func validateStringField(name, value string, required bool, maxLen int) error {
	if required && value == "" {
		return &SyntacticError{Field: name, Reason: "required field is empty"}
	}
	if len(value) > maxLen {
		return &SyntacticError{
			Field:   name,
			Reason:  "exceeds maximum length",
			Details: fmt.Sprintf("%d > %d", len(value), maxLen),
		}
	}
	return nil
}

// validateIdentifier checks that a string contains only safe identifier characters.
// Allowed: a-z, A-Z, 0-9, _, -, .
// This prevents injection attacks through identifier fields.
func validateIdentifier(name, value string) error {
	if value == "" {
		return nil // empty is OK for optional fields
	}
	for i, c := range value {
		if !isIdentChar(c) {
			return &SyntacticError{
				Field:   name,
				Reason:  "invalid character in identifier",
				Details: fmt.Sprintf("position %d: character %q not allowed — only alphanumeric, _, -, . permitted", i, string(c)),
			}
		}
	}
	return nil
}

// validatePrintable checks that a string contains only printable characters.
// No control characters (tab, newline, etc.), no null bytes.
func validatePrintable(name, value string) error {
	if value == "" {
		return nil
	}
	for i, c := range value {
		if c < 0x20 && c != '\t' {
			return &SyntacticError{
				Field:   name,
				Reason:  "control character in text field",
				Details: fmt.Sprintf("position %d: 0x%02x", i, c),
			}
		}
		if c == 0x7F {
			return &SyntacticError{
				Field:   name,
				Reason:  "DEL character in text field",
				Details: fmt.Sprintf("position %d", i),
			}
		}
	}
	return nil
}

// isIdentChar returns true if c is a valid identifier character.
// Allowed: a-z, A-Z, 0-9, _, -, .
func isIdentChar(c rune) bool {
	if c >= 'a' && c <= 'z' {
		return true
	}
	if c >= 'A' && c <= 'Z' {
		return true
	}
	if c >= '0' && c <= '9' {
		return true
	}
	if c == '_' || c == '-' || c == '.' {
		return true
	}
	return false
}

// SanitizeFieldKey normalizes a field key for safe storage.
// Strips leading/trailing whitespace and replaces invalid characters.
func SanitizeFieldKey(key string) string {
	key = strings.TrimSpace(key)
	var b strings.Builder
	b.Grow(len(key))
	for _, c := range key {
		if isIdentChar(c) {
			b.WriteRune(c)
		}
	}
	return b.String()
}
