// Package engine is the domain core of Grimlocker.
//
// It contains only pure data-logic: cryptography, storage abstractions,
// security primitives, the GQL protocol, the kernel event bus, error types,
// and cryptographic tools. It has ZERO knowledge of:
//
//   - Passwords (received as pre-hashed []byte via the adapter)
//   - OS file I/O (abstracted behind FileSystem interface)
//   - Network protocols (HTTP, WebSocket, IPC)
//   - OS signals, process lifecycle, or Tauri integration
//
// The daemon/ package imports engine/ through these public interfaces.
package engine

import (
	"github.com/grimlocker/grimdb-public/engine/crypto"
	"github.com/grimlocker/grimdb-public/engine/errors"
	"github.com/grimlocker/grimdb-public/engine/gql"
	"github.com/grimlocker/grimdb-public/engine/kernel"
	"github.com/grimlocker/grimdb-public/engine/security"
	"github.com/grimlocker/grimdb-public/engine/storage"
)

// ── Crypto ────────────────────────────────────────────────────────────────────

type (
	CryptoProvider = crypto.Provider
	KDFOptions     = crypto.KDFOptions
	PQCProvider    = crypto.PQCProvider
)

// ── Storage ───────────────────────────────────────────────────────────────────

type (
	BlockStore           = storage.BlockStore
	BlockStoreV2         = storage.BlockStoreV2
	WriteTransaction     = storage.WriteTransaction
	ReadTransaction      = storage.ReadTransaction
	StorageStrategy      = storage.StorageStrategy
)

// ── Security ──────────────────────────────────────────────────────────────────

type (
	SessionContext       = security.SessionContext
	LockdownManager      = security.LockdownManager
	AuditLog             = security.AuditLog
	MVKStore             = security.MVKStore
	MemoryGuard          = security.MemoryGuard
	IntrusionDetector    = security.IntrusionDetector
)

// ── GQL ───────────────────────────────────────────────────────────────────────

type (
	SessionInfo = gql.SessionInfo
	GQLQuery    = gql.GQLQuery
	GQLEntry    = gql.GQLEntry
	GQLResult   = gql.GQLResult
)

// ── Kernel ────────────────────────────────────────────────────────────────────

type (
	Dispatcher    = kernel.Dispatcher
	Module        = kernel.Module
	Event         = kernel.Event
	Handler       = kernel.Handler
	EventType     = kernel.EventType
	ModuleFactory = kernel.ModuleFactory
)

// ── Errors ────────────────────────────────────────────────────────────────────

type (
	GrimlockError    = errors.GrimlockError
	StructuredLogger = errors.StructuredLogger
)
