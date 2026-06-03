// Package gql implements the GrimQueryLanguage (GQL) binary frame protocol.
//
// GQL is a binary-only query protocol using FlatBuffers-style schema validation.
// No text parsing occurs at any point — every field is length-prefixed binary,
// providing Total Injection Immunity. Every frame passes through a two-stage
// validator (syntactic + semantic/ACL) before reaching the dispatcher.
//
// Frame format (8-byte header + payload):
//
//	Byte 0    : Version       (uint8)
//	Byte 1    : Opcode        (uint8)
//	Bytes 2-3 : Flags         (uint16, big-endian)
//	Bytes 4-7 : PayloadSize   (uint32, big-endian)
//	Bytes 8+  : Payload       (binary-encoded GQLQuery)
//
//	Version 1: Current protocol version.
//	         Anything else → rejected by syntactic validator.
package gql

// Version is the current GQL frame protocol version.
const Version byte = 1

// Opcode identifies the frame operation type.
type Opcode byte

const (
	OpcodeQuery  Opcode = 0x01 // Read-only query (list, get, search)
	OpcodeMutate Opcode = 0x02 // Write operation (create, update, delete)
	OpcodeResult Opcode = 0x03 // Server → client: successful result
	OpcodeError  Opcode = 0x04 // Server → client: error response
)

// Flag is a bitmask applied in the frame header flags field.
type Flag uint16

const (
	FlagNone       Flag = 0x0000
	FlagCompressed Flag = 0x0001 // Payload is zstd-compressed
	FlagEncrypted  Flag = 0x0002 // Payload is SKE-encrypted
)

// Operation identifies the specific GQL operation within a query or mutate frame.
type Operation string

// Query operations (read-only, OpcodeQuery).
const (
	OpListEntries  Operation = "list_entries"
	OpGetEntry     Operation = "get_entry"
	OpQueryEntries Operation = "query_entries"
)

// Mutate operations (write, OpcodeMutate).
const (
	OpCreateEntry Operation = "create_entry"
	OpUpdateEntry Operation = "update_entry"
	OpDeleteEntry Operation = "delete_entry"
)

// Search operations.
const (
	OpSearchEntries Operation = "search_entries"
)

// File Vault operations.
const (
	OpFileListFolder   Operation = "file.list_folder"
	OpFileCreateFolder Operation = "file.create_folder"
	OpFileRenameFolder Operation = "file.rename_folder"
	OpFileDeleteFolder Operation = "file.delete_folder"
	OpFileMove         Operation = "file.move"
	OpFileIngest       Operation = "file.ingest"
	OpFileDownload     Operation = "file.download"
	OpFileUploadStatus Operation = "file.upload_progress"
)

// Workspace operations.
const (
	OpWorkspaceList   Operation = "workspace.list"
	OpWorkspaceCreate Operation = "workspace.create"
	OpWorkspaceSwitch Operation = "workspace.switch"
	OpWorkspaceRename Operation = "workspace.rename"
	OpWorkspaceDelete Operation = "workspace.delete"
)

// Sync operations.
const (
	OpSyncListPeers Operation = "sync.list_peers"
	OpSyncTrigger   Operation = "sync.trigger"
)

// Audit operations.
const (
	OpAuditList Operation = "audit.list"
)

// Tool operations.
const (
	OpToolSSHGen         Operation = "tool.ssh_gen"
	OpToolRecoveryPhrase Operation = "tool.recovery_phrase"
)

// Health operations.
const (
	OpSystemHealth Operation = "system.health"
)

// isValidOpcode returns true if the opcode is a known value.
func isValidOpcode(o Opcode) bool {
	switch o {
	case OpcodeQuery, OpcodeMutate, OpcodeResult, OpcodeError:
		return true
	default:
		return false
	}
}

// isValidOperation returns true if the operation string is known.
func isValidOperation(op Operation) bool {
	switch op {
	case OpListEntries, OpGetEntry, OpQueryEntries,
		OpCreateEntry, OpUpdateEntry, OpDeleteEntry,
		OpSearchEntries,
		OpFileListFolder, OpFileCreateFolder, OpFileRenameFolder,
		OpFileDeleteFolder, OpFileMove, OpFileIngest, OpFileDownload,
		OpFileUploadStatus,
		OpWorkspaceList, OpWorkspaceCreate, OpWorkspaceSwitch,
		OpWorkspaceRename, OpWorkspaceDelete,
		OpSyncListPeers, OpSyncTrigger,
		OpAuditList,
		OpToolSSHGen, OpToolRecoveryPhrase,
		OpSystemHealth:
		return true
	default:
		return false
	}
}

// isReadOperation returns true if the operation is read-only.
func isReadOperation(op Operation) bool {
	switch op {
	case OpListEntries, OpGetEntry, OpQueryEntries,
		OpSearchEntries,
		OpFileListFolder, OpFileDownload, OpFileUploadStatus,
		OpWorkspaceList,
		OpSyncListPeers,
		OpAuditList,
		OpToolRecoveryPhrase,
		OpSystemHealth:
		return true
	}
	return false
}

// isWriteOperation returns true if the operation mutates data.
func isWriteOperation(op Operation) bool {
	switch op {
	case OpCreateEntry, OpUpdateEntry, OpDeleteEntry,
		OpFileCreateFolder, OpFileRenameFolder, OpFileDeleteFolder,
		OpFileMove, OpFileIngest,
		OpWorkspaceCreate, OpWorkspaceSwitch, OpWorkspaceRename,
		OpWorkspaceDelete,
		OpSyncTrigger,
		OpToolSSHGen:
		return true
	}
	return false
}

// FrameHeaderSize is the fixed size of the GQL frame header in bytes.
const FrameHeaderSize = 8

// MaxPayloadSize is the maximum allowed payload size (16 MiB).
const MaxPayloadSize = 16 * 1024 * 1024

// MaxNamespaceLen is the maximum allowed namespace string length.
const MaxNamespaceLen = 128

// MaxEntryIDLen is the maximum allowed entry_id string length.
const MaxEntryIDLen = 64

// MaxCategoryLen is the maximum allowed category string length.
const MaxCategoryLen = 32

// MaxFieldKeyLen is the maximum length of a single field key.
const MaxFieldKeyLen = 64

// MaxFieldValueLen is the maximum length of a single field value.
const MaxFieldValueLen = 8192

// MaxFieldsCount is the maximum number of fields per entry.
const MaxFieldsCount = 100

// MaxDataLen is the maximum total data payload size.
const MaxDataLen = 10 * 1024 * 1024
