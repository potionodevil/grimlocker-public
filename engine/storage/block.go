package storage

// Block is the opaque unit the storage layer reads and writes.
// It contains encrypted bytes that the storage layer NEVER decrypts —
// all decryption happens in the crypto module.
type Block struct {
	ID        string   `json:"id"`
	Nonce     []byte   `json:"nonce"`             // 12 bytes
	HMAC      []byte   `json:"hmac"`              // 32 bytes — stored by storage, verified by caller
	Data      []byte   `json:"data"`              // ciphertext
	Category  Category `json:"category,omitempty"` // entry category — written to index for in-memory filtering
	CreatedAt int64    `json:"created_at"`
	UpdatedAt int64    `json:"updated_at"`
}

// BlockMeta contains only the non-secret metadata about a block.
type BlockMeta struct {
	ID        string   `json:"id"`
	Size      int64    `json:"size"`
	Category  Category `json:"category,omitempty"` // entry category — used for client-side filtering
	CreatedAt int64    `json:"created_at"`
	UpdatedAt int64    `json:"updated_at"`
}
