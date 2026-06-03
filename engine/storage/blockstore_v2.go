package storage

// ─── BlockStoreV2 ─────────────────────────────────────────────────────────────

// BlockStoreV2 extends BlockStore with explicit transaction support.
// Transactions provide atomicity: either all writes in a transaction are
// committed together, or none are (Rollback).
//
// Use BlockStoreV2 when you need to write multiple blocks in a single atomic
// operation (e.g., create entry + attach metadata block).
//
// Existing code that uses BlockStore continues to work unchanged — BlockStoreV2
// is a backwards-compatible extension, not a replacement.
type BlockStoreV2 interface {
	BlockStore

	// BeginWrite starts a write transaction.
	// Only one write transaction may be open at a time per store.
	// The caller must call Commit() or Rollback() to release the transaction.
	BeginWrite() (WriteTransaction, error)

	// BeginRead starts a read-only snapshot transaction.
	// Multiple read transactions may be open concurrently.
	BeginRead() (ReadTransaction, error)
}

// ─── WriteTransaction ─────────────────────────────────────────────────────────

// WriteTransaction batches block writes and atomically commits them to the
// underlying store. The transaction buffers all writes in memory until Commit
// is called, so partial failures do not corrupt the on-disk state.
type WriteTransaction interface {
	// WriteBlock stages a block for writing. The block is not persisted
	// until Commit() is called.
	WriteBlock(b Block) error

	// DeleteBlock stages a block for deletion. The deletion is not applied
	// until Commit() is called.
	DeleteBlock(id string) error

	// Commit atomically applies all staged writes and deletions.
	// Returns an error if any operation fails; the store remains unchanged.
	// The transaction is closed after Commit regardless of success.
	Commit() error

	// Rollback discards all staged writes without modifying the store.
	// Always call Rollback in a defer to handle error paths.
	Rollback()
}

// ─── ReadTransaction ──────────────────────────────────────────────────────────

// ReadTransaction provides a consistent snapshot view of the store.
// Reads within a transaction see the state at the time BeginRead was called.
type ReadTransaction interface {
	// ReadBlock retrieves a block from the snapshot.
	ReadBlock(id string) (Block, error)

	// ListBlocks returns all block metadata from the snapshot.
	ListBlocks() ([]BlockMeta, error)

	// QueryBlocks returns metadata for blocks matching the given category.
	QueryBlocks(category Category) ([]BlockMeta, error)

	// Close releases the snapshot. Always call Close (or use defer).
	Close()
}

// ─── InMemoryWriteTransaction — reference implementation ──────────────────────

// InMemoryWriteTransaction implements WriteTransaction using a buffer.
// The store flushes the buffer on Commit. This is suitable for the current
// single-threaded file-backed store; a future WAL-based store would replace it.
type InMemoryWriteTransaction struct {
	store    BlockStore
	writes   []Block
	deletes  []string
	done     bool
}

// NewInMemoryWriteTransaction creates a buffered write transaction over any BlockStore.
// Modules that want transactions but work with a plain BlockStore can use this
// as a compatibility shim until the store itself implements BlockStoreV2.
func NewInMemoryWriteTransaction(store BlockStore) *InMemoryWriteTransaction {
	return &InMemoryWriteTransaction{store: store}
}

func (t *InMemoryWriteTransaction) WriteBlock(b Block) error {
	if t.done {
		return ErrTransactionClosed
	}
	t.writes = append(t.writes, b)
	return nil
}

func (t *InMemoryWriteTransaction) DeleteBlock(id string) error {
	if t.done {
		return ErrTransactionClosed
	}
	t.deletes = append(t.deletes, id)
	return nil
}

// Commit applies all staged writes then all staged deletes.
// On partial failure the successfully written blocks remain — this is a
// "best-effort atomic" implementation. Use a WAL-backed store for true atomicity.
func (t *InMemoryWriteTransaction) Commit() error {
	if t.done {
		return ErrTransactionClosed
	}
	t.done = true

	for _, b := range t.writes {
		if err := t.store.WriteBlock(b); err != nil {
			return err
		}
	}
	for _, id := range t.deletes {
		if err := t.store.DeleteBlock(id); err != nil {
			return err
		}
	}
	return t.store.Flush()
}

func (t *InMemoryWriteTransaction) Rollback() {
	t.done = true
	t.writes = nil
	t.deletes = nil
}

// ─── Sentinel errors ──────────────────────────────────────────────────────────

// ErrTransactionClosed is returned when a method is called on an already-committed
// or rolled-back transaction.
var ErrTransactionClosed = transactionClosedError{}

type transactionClosedError struct{}

func (transactionClosedError) Error() string {
	return "storage: operation on closed transaction"
}
