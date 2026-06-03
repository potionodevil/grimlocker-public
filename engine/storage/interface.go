package storage

// BlockStore is the interface every storage backend must implement.
// Implementations receive and return opaque Blocks; they never decrypt.
type BlockStore interface {
	WriteBlock(b Block) error
	ReadBlock(id string) (Block, error)
	DeleteBlock(id string) error
	ListBlocks() ([]BlockMeta, error)
	// QueryBlocks returns all BlockMeta whose Category matches the given value.
	// Operates on the in-memory index; vault must be unlocked.
	// Passing an empty string returns all blocks (same as ListBlocks).
	QueryBlocks(category Category) ([]BlockMeta, error)
	// Flush atomically persists the in-memory index.
	Flush() error
	Close() error
}

// StorageStrategy is a pluggable interceptor injected into BlockStore.
// The store calls OnWrite before persisting and OnRead after retrieving.
// OnTrigger is called with a trigger key (e.g. "bait" for honeypot,
// "decoy" for deniable encryption activation).
type StorageStrategy interface {
	Name() string
	OnWrite(b Block) (Block, error)
	OnRead(b Block) (Block, error)
	OnTrigger(key string) error
}

// NopStrategy is a no-op StorageStrategy used when no strategy is active.
type NopStrategy struct{}

func (NopStrategy) Name() string               { return "nop" }
func (NopStrategy) OnWrite(b Block) (Block, error) { return b, nil }
func (NopStrategy) OnRead(b Block) (Block, error)  { return b, nil }
func (NopStrategy) OnTrigger(_ string) error        { return nil }
