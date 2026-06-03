package gql

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// GQLQuery is the deserialized form of a GQL query or mutate request.
// This is the canonical internal representation passed between the frame
// decoder, validator, and dispatcher.
type GQLQuery struct {
	Namespace   string            // Workspace or user ID (required)
	Operation   Operation         // The GQL operation to perform
	EntryID     string            // Target entry ID (for get/update/delete)
	Category    string            // Filter category (PASSWORD, SSH_KEY, etc.)
	Title       string            // Entry title (for create/update)
	Fields      map[string]string // Key-value fields for the entry
	Credentials []byte            // SKE-encrypted MVK handle proof (for write ops)
	Limit       uint32            // Max results, 0 = use default (50)
	Offset      uint32            // Pagination offset
}

// GQLEntry is a single entry in a GQL result set.
type GQLEntry struct {
	ID        string            `json:"id"`
	Category  string            `json:"category"`
	Type      string            `json:"type,omitempty"`
	Title     string            `json:"title,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
	CreatedAt int64             `json:"created_at"`
	UpdatedAt int64             `json:"updated_at"`
}

// GQLResult is the server response for a GQL query or mutate.
type GQLResult struct {
	RequestID  string     `json:"request_id,omitempty"`
	Success    bool       `json:"success"`
	Entries    []GQLEntry `json:"entries,omitempty"`
	TotalCount uint32     `json:"total_count,omitempty"`
	ErrorCode  int32      `json:"error_code,omitempty"`
	ErrorMsg   string     `json:"error_msg,omitempty"`
}

// serializeField serializes a string field in length-prefixed binary format.
// Format: length(2 bytes big-endian) + data(bytes).
func serializeField(buf []byte, offset int, s string) int {
	l := len(s)
	binary.BigEndian.PutUint16(buf[offset:], uint16(l))
	offset += 2
	copy(buf[offset:], s)
	return offset + l
}

// deserializeField reads a length-prefixed string from a byte slice.
// Returns the string and the number of bytes consumed.
func deserializeField(data []byte) (string, int, error) {
	if len(data) < 2 {
		return "", 0, fmt.Errorf("gql: field too short for length prefix")
	}
	l := int(binary.BigEndian.Uint16(data[:2]))
	if len(data) < 2+l {
		return "", 0, fmt.Errorf("gql: field truncated: need %d bytes, have %d", 2+l, len(data))
	}
	return string(data[2 : 2+l]), 2 + l, nil
}

// fieldSize returns the serialized size of a string field (2 + len(s)).
func fieldSize(s string) int { return 2 + len(s) }

// Encode serializes a GQLQuery into a binary payload.
//
// Binary layout (all multi-byte integers are big-endian):
//
//	[0:1]   field_count    uint8   (number of fields in the Fields map)
//	[1:3]   operation_len  uint16
//	[3:n]   operation      bytes   (e.g. "list_entries", "create_entry")
//	[n:n+2] namespace_len  uint16
//	[n+2:m] namespace      bytes
//	[n:n+2] entry_id_len   uint16
//	[n+2:m] entry_id       bytes
//	[m:m+2] category_len   uint16
//	[m+2:p] category       bytes
//	[p:p+2] title_len      uint16
//	[p+2:q] title          bytes
//	[q:r]   field entries  (each: key_len(2) + key + value_len(2) + value)
//	[r:r+4] limit          uint32
//	[s:s+4] offset         uint32
//	[t:t+2] creds_len      uint16
//	[t+2:u] credentials    bytes
func (q *GQLQuery) Encode() []byte {
	size := 1 // field_count
	size += fieldSize(string(q.Operation))
	size += fieldSize(q.Namespace)
	size += fieldSize(q.EntryID)
	size += fieldSize(q.Category)
	size += fieldSize(q.Title)
	for k, v := range q.Fields {
		size += fieldSize(k) + fieldSize(v)
	}
	size += 4 // limit
	size += 4 // offset
	size += fieldSize(string(q.Credentials))

	buf := make([]byte, size)
	off := 0

	// field_count
	fc := uint8(len(q.Fields))
	if fc > MaxFieldsCount {
		fc = MaxFieldsCount
	}
	buf[off] = fc
	off++

	// operation
	off = serializeField(buf, off, string(q.Operation))

	// namespace
	off = serializeField(buf, off, q.Namespace)

	// entry_id
	off = serializeField(buf, off, q.EntryID)

	// category
	off = serializeField(buf, off, q.Category)

	// title
	off = serializeField(buf, off, q.Title)

	// fields
	for k, v := range q.Fields {
		off = serializeField(buf, off, k)
		off = serializeField(buf, off, v)
	}

	// limit
	binary.BigEndian.PutUint32(buf[off:], q.Limit)
	off += 4

	// offset
	binary.BigEndian.PutUint32(buf[off:], q.Offset)
	off += 4

	// credentials
	serializeField(buf, off, string(q.Credentials))

	return buf
}

// DecodeQuery deserializes a GQLQuery from a binary payload.
func DecodeQuery(payload []byte, op Operation) (*GQLQuery, error) {
	if len(payload) < 1 {
		return nil, fmt.Errorf("gql: payload too short for field_count")
	}

	off := 0
	fieldCount := int(payload[off])
	off++
	if fieldCount > MaxFieldsCount {
		return nil, fmt.Errorf("gql: field_count %d exceeds max %d", fieldCount, MaxFieldsCount)
	}

	q := &GQLQuery{
		Operation: op,
		Fields:    make(map[string]string),
	}

	// operation (override from payload if present)
	s, n, err := deserializeField(payload[off:])
	if err != nil {
		return nil, fmt.Errorf("gql: operation: %w", err)
	}
	if s != "" {
		q.Operation = Operation(s)
	}
	off += n

	// namespace
	s, n, err = deserializeField(payload[off:])
	if err != nil {
		return nil, fmt.Errorf("gql: namespace: %w", err)
	}
	q.Namespace = s
	off += n

	// entry_id
	s, n, err = deserializeField(payload[off:])
	if err != nil {
		return nil, fmt.Errorf("gql: entry_id: %w", err)
	}
	q.EntryID = s
	off += n

	// category
	s, n, err = deserializeField(payload[off:])
	if err != nil {
		return nil, fmt.Errorf("gql: category: %w", err)
	}
	q.Category = s
	off += n

	// title
	s, n, err = deserializeField(payload[off:])
	if err != nil {
		return nil, fmt.Errorf("gql: title: %w", err)
	}
	q.Title = s
	off += n

	// fields
	for i := 0; i < fieldCount; i++ {
		if off >= len(payload) {
			return nil, fmt.Errorf("gql: truncated at field %d", i)
		}
		k, kn, kerr := deserializeField(payload[off:])
		if kerr != nil {
			return nil, fmt.Errorf("gql: field[%d].key: %w", i, kerr)
		}
		off += kn

		if off >= len(payload) {
			return nil, fmt.Errorf("gql: truncated at field[%d].value", i)
		}
		v, vn, verr := deserializeField(payload[off:])
		if verr != nil {
			return nil, fmt.Errorf("gql: field[%d].value: %w", i, verr)
		}
		off += vn

		q.Fields[k] = v
	}

	// limit
	if off+4 > len(payload) {
		return nil, fmt.Errorf("gql: truncated at limit")
	}
	q.Limit = binary.BigEndian.Uint32(payload[off:])
	off += 4

	// offset
	if off+4 > len(payload) {
		return nil, fmt.Errorf("gql: truncated at offset")
	}
	q.Offset = binary.BigEndian.Uint32(payload[off:])
	off += 4

	// credentials (optional — may be empty)
	if off < len(payload) {
		s, n, err = deserializeField(payload[off:])
		if err != nil {
			return nil, fmt.Errorf("gql: credentials: %w", err)
		}
		q.Credentials = []byte(s)
		off += n
	}

	return q, nil
}

// EncodeResult serializes a GQLResult into a JSON byte slice for wire transport.
// Results use JSON for easy frontend consumption; queries use binary for security.
func (r *GQLResult) EncodeResult() ([]byte, error) {
	return json.Marshal(r)
}
