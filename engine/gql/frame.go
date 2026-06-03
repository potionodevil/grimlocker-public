package gql

import (
	"encoding/binary"
	"fmt"
)

// Frame is the wire-format representation of a GQL message.
// It contains the 8-byte header and the optional binary payload.
type Frame struct {
	Version     byte
	Opcode      Opcode
	Flags       Flag
	PayloadSize uint32
	Payload     []byte
}

// Encode serializes a Frame into its wire-format byte representation.
func (f *Frame) Encode() []byte {
	buf := make([]byte, FrameHeaderSize+len(f.Payload))
	buf[0] = f.Version
	buf[1] = byte(f.Opcode)
	binary.BigEndian.PutUint16(buf[2:4], uint16(f.Flags))
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(f.Payload)))
	copy(buf[8:], f.Payload)
	return buf
}

// DecodeFrame deserializes a byte slice into a Frame.
// Returns an error if the data is too short, version is wrong, or payload size
// doesn't match the actual data length.
func DecodeFrame(data []byte) (*Frame, error) {
	if len(data) < FrameHeaderSize {
		return nil, fmt.Errorf("gql: frame too short: %d bytes (min %d)", len(data), FrameHeaderSize)
	}

	version := data[0]
	opcode := Opcode(data[1])
	flags := Flag(binary.BigEndian.Uint16(data[2:4]))
	payloadSize := binary.BigEndian.Uint32(data[4:8])

	if version != Version {
		return nil, fmt.Errorf("gql: unsupported version %d (expected %d)", version, Version)
	}

	if !isValidOpcode(opcode) {
		return nil, fmt.Errorf("gql: unknown opcode 0x%02x", opcode)
	}

	if payloadSize > MaxPayloadSize {
		return nil, fmt.Errorf("gql: payload size %d exceeds max %d", payloadSize, MaxPayloadSize)
	}

	expectedLen := FrameHeaderSize + int(payloadSize)
	if len(data) != expectedLen {
		return nil, fmt.Errorf("gql: frame length mismatch: have %d bytes, header says %d", len(data), expectedLen)
	}

	var payload []byte
	if payloadSize > 0 {
		payload = make([]byte, payloadSize)
		copy(payload, data[8:])
	}

	return &Frame{
		Version:     version,
		Opcode:      opcode,
		Flags:       flags,
		PayloadSize: payloadSize,
		Payload:     payload,
	}, nil
}

// NewQueryFrame creates a Frame from a GQLQuery and operation.
func NewQueryFrame(query *GQLQuery) *Frame {
	payload := query.Encode()
	opcode := OpcodeQuery
	if isWriteOperation(query.Operation) {
		opcode = OpcodeMutate
	}
	return &Frame{
		Version:     Version,
		Opcode:      opcode,
		Flags:       FlagNone,
		PayloadSize: uint32(len(payload)),
		Payload:     payload,
	}
}

// NewResultFrame creates a Frame for a successful result.
func NewResultFrame(result *GQLResult) *Frame {
	payload, _ := result.EncodeResult()
	return &Frame{
		Version:     Version,
		Opcode:      OpcodeResult,
		Flags:       FlagNone,
		PayloadSize: uint32(len(payload)),
		Payload:     payload,
	}
}

// NewErrorFrame creates a Frame for an error response.
func NewErrorFrame(code int32, msg string) *Frame {
	result := &GQLResult{
		Success:   false,
		ErrorCode: code,
		ErrorMsg:  msg,
	}
	payload, _ := result.EncodeResult()
	return &Frame{
		Version:     Version,
		Opcode:      OpcodeError,
		Flags:       FlagNone,
		PayloadSize: uint32(len(payload)),
		Payload:     payload,
	}
}
