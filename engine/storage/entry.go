package storage

// Category classifies a vault entry for filterable views.
type Category string

const (
	CategoryPassword    Category = "PASSWORD"
	CategorySSHKey      Category = "SSH_KEY"
	CategoryCertificate Category = "CERTIFICATE"
	CategoryFileVault   Category = "FILE_VAULT"
)
