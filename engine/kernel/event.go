// Package kernel (event.go) defines the Event type and all EventType constants
// used across the Grimlocker daemon. Every inter-module message is an Event.
//
// EventType naming convention: CHANNEL.ACTION (e.g. "CRYPTO.ENCRYPT").
// The channel prefix (everything before ".") is used by the bus to route
// events to the correct Module.Handle implementation.
//
// Adding a new event:
//  1. Add a constant here (e.g. EvFooBar EventType = "FOO.BAR").
//  2. Register a handler in the owning module's buildHandlers() / buildRegistry().
//  3. Document the JSON payload schema in a comment next to the constant.
package kernel

// EventType is the channel address of an event. The prefix before "." is the
// owning module's channel (e.g. "CRYPTO" for all CRYPTO.* events).
type EventType string

const (
	// AUTH channel — owned by security.Module
	EvAuthSetup     EventType = "AUTH.SETUP"
	EvAuthUnlock    EventType = "AUTH.UNLOCK"
	EvAuthResult    EventType = "AUTH.RESULT"
	EvAuthLockdown  EventType = "AUTH.LOCKDOWN"
	EvAuthLogout    EventType = "AUTH.LOGOUT"
	EvAuthStatus    EventType = "AUTH.STATUS"
	EvAuthInitReady EventType = "AUTH.INIT_READY"
	EvAuthKeyReady  EventType = "AUTH.KEY_READY"
	EvAuthReady     EventType = "AUTH.READY"
	EvAuthGetHandle EventType = "AUTH.GET_HANDLE"

	// CRYPTO channel — owned by crypto.Module
	EvCryptoEncrypt EventType = "CRYPTO.ENCRYPT"
	EvCryptoDecrypt EventType = "CRYPTO.DECRYPT"
	EvCryptoDerive  EventType = "CRYPTO.DERIVE_KEY"
	EvCryptoShred   EventType = "CRYPTO.SHRED"
	EvCryptoResult  EventType = "CRYPTO.RESULT"

	// STORAGE channel — owned by storage adapter
	EvStorageWrite          EventType = "STORAGE.WRITE"
	EvStorageRead           EventType = "STORAGE.READ"
	EvStorageDelete         EventType = "STORAGE.DELETE"
	EvStorageList           EventType = "STORAGE.LIST"
	EvStorageResult         EventType = "STORAGE.RESULT"
	EvStorageIngestProgress EventType = "STORAGE.INGEST_PROGRESS"
	EvStorageVFSMount       EventType = "STORAGE.VFS_MOUNT"
	EvStorageReady          EventType = "STORAGE.READY"

	// ENTRY channel — owned by entry handler module
	EvEntryCreate EventType = "ENTRY.CREATE"
	EvEntryRead   EventType = "ENTRY.READ"
	EvEntryUpdate EventType = "ENTRY.UPDATE"
	EvEntryDelete EventType = "ENTRY.DELETE"
	EvEntryIngest EventType = "ENTRY.INGEST"
	EvEntryResult EventType = "ENTRY.RESULT"
	EvEntryQuery  EventType = "ENTRY.QUERY" // client → daemon: {category: "PASSWORD"|"SSH_KEY"|…}

	// TOOL channel — owned by tools module
	EvToolSSHGen EventType = "TOOL.SSH_GEN" // client → daemon: {comment: string}
	EvToolResult EventType = "TOOL.RESULT"  // daemon → client: {public_key, entry_id}

	// SECURITY channel — owned by security.Module
	EvSecMemLock  EventType = "SECURITY.MEM_LOCK"
	EvSecZeroize  EventType = "SECURITY.ZEROIZE"
	EvSecAudit    EventType = "SECURITY.AUDIT"
	EvSecPanic    EventType = "SECURITY.PANIC"
	EvSecLockdown EventType = "SECURITY.LOCKDOWN"

	// SYNC channel — available to SDK plugins + Local Network Sync
	EvSyncBegin    EventType = "SYNC.BEGIN"
	EvSyncComplete EventType = "SYNC.COMPLETE"
	EvSyncDiscover EventType = "SYNC.DISCOVER"     // mDNS peer discovered
	EvSyncPair     EventType = "SYNC.PAIR"         // PIN pairing request/response
	EvSyncPull     EventType = "SYNC.PULL"         // pull entries from peer
	EvSyncPushVer  EventType = "SYNC.PUSH_VERSION" // push version vector to peer
	EvSyncConflict EventType = "SYNC.CONFLICT"     // version conflict detected

	// BIOMETRIC channel — used by hardware sensor plugins
	EvBiometricAuthenticate EventType = "BIOMETRIC.AUTHENTICATE"
	EvBiometricResult       EventType = "BIOMETRIC.RESULT"

	// INTEGRITY channel — used by the binary integrity monitor
	EvIntegrityCheck     EventType = "INTEGRITY.CHECK"
	EvIntegrityViolation EventType = "INTEGRITY.VIOLATION"

	// WORKSPACE channel — multi-tenant vault management
	EvWorkspaceCreate EventType = "WORKSPACE.CREATE"
	EvWorkspaceSwitch EventType = "WORKSPACE.SWITCH"
	EvWorkspaceDelete EventType = "WORKSPACE.DELETE"
	EvWorkspaceResult EventType = "WORKSPACE.RESULT"

	// KERNEL channel — handshake & status reporting
	EvKernelStatus      EventType = "KERNEL.STATUS"
	EvKernelStateReport EventType = "KERNEL.STATE_REPORT"
	EvKernelStateMirror EventType = "KERNEL.STATE_MIRROR" // full vault state push on reconnect

	// RECONNECT channel — UI re-attach protocol (Phase 3)
	EvReconnectResume EventType = "RECONNECT.RESUME" // client requests session resume
	EvReconnectSync   EventType = "RECONNECT.SYNC"   // server pushes full state to reconnected client

	// GQL channel — GrimQueryLanguage binary protocol (Phase 4)
	EvGQLQuery  EventType = "GQL.QUERY"  // client → server: binary-encoded GQLQuery frame
	EvGQLResult EventType = "GQL.RESULT" // server → client: GQLResult (success or error)

	// SYSTEM channel — errors, health, telemetry
	EvSystemError       EventType = "SYSTEM.ERROR"
	EvSystemHealthCheck EventType = "SYSTEM.HEALTH_CHECK"
	EvSystemLog         EventType = "SYSTEM.LOG"
)

// Event is the unit of communication between all modules. Payloads are JSON.
// No module may call another module's functions directly; all inter-module
// communication MUST go through an Event dispatched on the bus.
type Event struct {
	// ID is a UUID v4 used to correlate requests and responses.
	ID string `json:"id"`

	Type EventType `json:"type"`

	// Payload is JSON-encoded data whose schema is defined per EventType.
	Payload []byte `json:"payload,omitempty"`

	// ReplyTo contains the originating Event.ID when this event is a response.
	ReplyTo string `json:"reply_to,omitempty"`

	// Origin is the module ID that dispatched this event.
	Origin string `json:"origin,omitempty"`

	// Timestamp is Unix nanoseconds.
	Timestamp int64 `json:"timestamp"`

	// TTL is decremented on each hop; the bus drops events at 0 to break cycles.
	TTL int `json:"ttl"`
}

// Channel extracts the routing prefix from an EventType (e.g. "CRYPTO" from "CRYPTO.ENCRYPT").
func (et EventType) Channel() string {
	s := string(et)
	for i, c := range s {
		if c == '.' {
			return s[:i]
		}
	}
	return s
}
