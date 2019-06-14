package api

import (
	"net/http"
)

// Errors
var (
	ErrAccountNotKeyed    = errAPI.Code("account_not_keyed").StatusError("User has not yet keyed their account", http.StatusBadRequest)
	ErrAccountKeyNotFound = errAPI.Code("account_key_not_found").StatusError("User has not yet keyed their account", http.StatusNotFound)
)

// EncryptedAccountKey represents an account key encrypted with a credential.
type EncryptedAccountKey struct {
	Account             *Account        `json:"account"`
	PublicKey           []byte          `json:"public_key"`
	EncryptedPrivateKey *EncryptedValue `json:"encrypted_private_key"`
	Credential          *Credential     `json:"credential"`
}

// CreateAccountKeyRequest contains the fields to add an account_key encrypted for a credential.
type CreateAccountKeyRequest struct {
	EncryptedPrivateKey *EncryptedValue `json:"encrypted_private_key"`
	PublicKey           []byte          `json:"public_key"`
}

// Validate checks whether the request is valid.
func (req CreateAccountKeyRequest) Validate() error {
	if req.PublicKey == nil {
		return ErrMissingField("public_key")
	}
	if req.EncryptedPrivateKey == nil {
		return ErrMissingField("encrypted_private_key")
	}
	return nil
}
