package gql

import (
	"encoding/binary"
	"testing"
)

type mockSession struct {
	unlocked bool
	handle   string
	userID   string
	roles    map[string]bool
}

func (s *mockSession) IsUnlocked() bool     { return s.unlocked }
func (s *mockSession) ActiveHandle() string { return s.handle }
func (s *mockSession) UserID() string       { return s.userID }
func (s *mockSession) HasRole(role string) bool {
	if s.roles == nil {
		return false
	}
	return s.roles[role]
}

func unlockedSession() *mockSession {
	return &mockSession{unlocked: true, handle: "mvk:test1234", userID: "default"}
}

func lockedSession() *mockSession {
	return &mockSession{unlocked: false}
}

// --- Frame Tests ---

func TestDecodeFrameValid(t *testing.T) {
	query := &GQLQuery{Namespace: "default", Operation: OpListEntries}
	frame := NewQueryFrame(query)
	data := frame.Encode()

	decoded, err := DecodeFrame(data)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if decoded.Version != Version {
		t.Errorf("version: got %d, want %d", decoded.Version, Version)
	}
	if decoded.Opcode != OpcodeQuery {
		t.Errorf("opcode: got 0x%02x, want 0x%02x", decoded.Opcode, OpcodeQuery)
	}
}

func TestDecodeFrameWrongVersion(t *testing.T) {
	data := []byte{0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := DecodeFrame(data)
	if err == nil {
		t.Fatal("expected error for wrong version")
	}
}

func TestDecodeFrameTooShort(t *testing.T) {
	_, err := DecodeFrame([]byte{0x01, 0x01, 0x00})
	if err == nil {
		t.Fatal("expected error for frame too short")
	}
}

func TestDecodeFrameSizeMismatch(t *testing.T) {
	data := []byte{0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	_, err := DecodeFrame(data)
	if err == nil {
		t.Fatal("expected error for size mismatch")
	}
}

func TestDecodeFrameUnknownOpcode(t *testing.T) {
	data := []byte{0x01, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := DecodeFrame(data)
	if err == nil {
		t.Fatal("expected error for unknown opcode")
	}
}

func TestDecodeFrameOversizedPayload(t *testing.T) {
	data := []byte{0x01, 0x01, 0x00, 0x00}
	data = append(data, make([]byte, 4)...)
	binary.BigEndian.PutUint32(data[4:8], MaxPayloadSize+1)
	_, err := DecodeFrame(data)
	if err == nil {
		t.Fatal("expected error for oversized payload")
	}
}

// --- Query Encode/Decode Tests ---

func TestQueryEncodeDecodeRoundtrip(t *testing.T) {
	original := &GQLQuery{
		Namespace: "default",
		Operation: OpCreateEntry,
		EntryID:   "test-id-123",
		Category:  "PASSWORD",
		Title:     "My Test Entry",
		Fields: map[string]string{
			"username": "alice",
			"url":      "https://example.com",
		},
		Limit:       50,
		Offset:      0,
		Credentials: []byte("proof"),
	}

	encoded := original.Encode()
	decoded, err := DecodeQuery(encoded, OpCreateEntry)
	if err != nil {
		t.Fatalf("DecodeQuery: %v", err)
	}

	if decoded.Namespace != original.Namespace {
		t.Errorf("namespace: got %q, want %q", decoded.Namespace, original.Namespace)
	}
	if decoded.EntryID != original.EntryID {
		t.Errorf("entry_id: got %q, want %q", decoded.EntryID, original.EntryID)
	}
	if decoded.Category != original.Category {
		t.Errorf("category: got %q, want %q", decoded.Category, original.Category)
	}
	if decoded.Title != original.Title {
		t.Errorf("title: got %q, want %q", decoded.Title, original.Title)
	}
	if len(decoded.Fields) != len(original.Fields) {
		t.Errorf("fields count: got %d, want %d", len(decoded.Fields), len(original.Fields))
	}
	for k, v := range original.Fields {
		if decoded.Fields[k] != v {
			t.Errorf("field[%q]: got %q, want %q", k, decoded.Fields[k], v)
		}
	}
	if decoded.Limit != original.Limit {
		t.Errorf("limit: got %d, want %d", decoded.Limit, original.Limit)
	}
	if decoded.Offset != original.Offset {
		t.Errorf("offset: got %d, want %d", decoded.Offset, original.Offset)
	}
}

func TestDecodeQueryTruncated(t *testing.T) {
	_, err := DecodeQuery([]byte{}, OpListEntries)
	if err == nil {
		t.Fatal("expected error for empty payload")
	}

	_, err = DecodeQuery([]byte{0x01, 0x00, 0x03, 'a', 'b'}, OpListEntries)
	if err == nil {
		t.Fatal("expected error for truncated payload")
	}
}

// --- Validator Tests ---

func TestValidateEmptyNamespace(t *testing.T) {
	query := &GQLQuery{Namespace: "", Operation: OpListEntries}
	frame := NewQueryFrame(query)
	_, err := ValidateFrame(frame, unlockedSession())
	if err == nil {
		t.Fatal("expected error for empty namespace")
	}
}

func TestValidateValidQuery(t *testing.T) {
	query := &GQLQuery{Namespace: "default", Operation: OpListEntries, Limit: 50}
	frame := NewQueryFrame(query)
	decoded, err := ValidateFrame(frame, unlockedSession())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decoded.Namespace != "default" {
		t.Errorf("namespace: got %q", decoded.Namespace)
	}
}

func TestValidateLockedVault(t *testing.T) {
	query := &GQLQuery{Namespace: "default", Operation: OpListEntries}
	frame := NewQueryFrame(query)
	_, err := ValidateFrame(frame, lockedSession())
	if err == nil {
		t.Fatal("expected error for locked vault")
	}
}

func TestValidateNilSession(t *testing.T) {
	query := &GQLQuery{Namespace: "default", Operation: OpListEntries}
	frame := NewQueryFrame(query)
	_, err := ValidateFrame(frame, nil)
	if err == nil {
		t.Fatal("expected error for nil session")
	}
}

func TestValidateMismatchedOpcode(t *testing.T) {
	query := &GQLQuery{Namespace: "default", Operation: OpCreateEntry}
	frame := NewQueryFrame(query)
	frame.Opcode = OpcodeQuery // set to query opcode but operation is mutate
	_, err := ValidateFrame(frame, unlockedSession())
	if err == nil {
		t.Fatal("expected error for opcode/operation mismatch")
	}
}

func TestValidateMutateWithoutCredentials(t *testing.T) {
	query := &GQLQuery{
		Namespace:   "default",
		Operation:   OpCreateEntry,
		Title:       "test",
		Category:    "PASSWORD",
		Fields:      map[string]string{"user": "alice"},
		Credentials: nil, // missing!
	}
	frame := NewQueryFrame(query)
	_, err := ValidateFrame(frame, unlockedSession())
	if err == nil {
		t.Fatal("expected error for missing credentials on write")
	}
}

func TestValidateRBACNamespaceMismatch(t *testing.T) {
	query := &GQLQuery{
		Namespace:   "other-namespace",
		Operation:   OpCreateEntry,
		Title:       "test",
		Credentials: []byte("proof"),
	}
	frame := NewQueryFrame(query)
	session := unlockedSession()
	session.userID = "default" // session user is "default", query says "other-namespace"
	_, err := ValidateFrame(frame, session)
	if err == nil {
		t.Fatal("expected error for namespace mismatch")
	}
}

func TestValidateAdminBypassesRBAC(t *testing.T) {
	query := &GQLQuery{
		Namespace: "other-namespace",
		Operation: OpListEntries,
	}
	frame := NewQueryFrame(query)
	session := unlockedSession()
	session.userID = "default"
	session.roles = map[string]bool{"admin": true}
	_, err := ValidateFrame(frame, session)
	if err != nil {
		t.Fatalf("unexpected error for admin bypass: %v", err)
	}
}

func TestValidateSQLInjectionInNamespace(t *testing.T) {
	query := &GQLQuery{
		Namespace: "default'; DROP TABLE blocks; --",
		Operation: OpListEntries,
	}
	frame := NewQueryFrame(query)
	_, err := ValidateFrame(frame, unlockedSession())
	if err == nil {
		t.Fatal("expected error for SQL injection in namespace")
	}
}

func TestValidateNullByteInCategory(t *testing.T) {
	query := &GQLQuery{
		Namespace: "default",
		Operation: OpQueryEntries,
		Category:  "PASSWORD\x00HIDDEN",
	}
	frame := NewQueryFrame(query)
	_, err := ValidateFrame(frame, unlockedSession())
	if err == nil {
		t.Fatal("expected error for null byte in category")
	}
}

func TestValidateControlCharsInTitle(t *testing.T) {
	query := &GQLQuery{
		Namespace:   "default",
		Operation:   OpCreateEntry,
		Title:       "test\x01control",
		Credentials: []byte("proof"),
	}
	frame := NewQueryFrame(query)
	_, err := ValidateFrame(frame, unlockedSession())
	if err == nil {
		t.Fatal("expected error for control chars in title")
	}
}

// --- Fuzz Test ---

func TestFuzzDecodeFrame(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping fuzz test in short mode")
	}
	// Test that random bytes never cause a panic in DecodeFrame
	for i := 0; i < 10000; i++ {
		size := 1 + i%4096
		data := make([]byte, size)
		// Use a simple deterministic source for reproducibility
		for j := range data {
			data[j] = byte(j * 2654435761 % 256)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic at iteration %d (size %d): %v", i, size, r)
				}
			}()
			frame, err := DecodeFrame(data)
			if err != nil {
				return
			}
			ValidateFrame(frame, unlockedSession())
		}()
	}
}

// --- Benchmark ---

func BenchmarkEncodeDecode(b *testing.B) {
	query := &GQLQuery{
		Namespace: "default",
		Operation: OpListEntries,
		Limit:     50,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		frame := NewQueryFrame(query)
		data := frame.Encode()
		DecodeFrame(data)
	}
}

func BenchmarkValidate(b *testing.B) {
	query := &GQLQuery{Namespace: "default", Operation: OpListEntries, Limit: 50}
	frame := NewQueryFrame(query)
	session := unlockedSession()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidateFrame(frame, session)
	}
}
