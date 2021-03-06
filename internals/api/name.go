package api

import (
	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/internals/crypto"
)

// EncryptedNameRequest contains an EncryptedName for an Account.
type EncryptedNameRequest struct {
	AccountID     uuid.UUID            `json:"account_id"`
	EncryptedName crypto.CiphertextRSA `json:"encrypted_name"`
}

// Validate validates the EncryptedNameRequest to be valid.
func (enr *EncryptedNameRequest) Validate() error {
	if enr.AccountID.IsZero() {
		return ErrInvalidAccountID
	}

	return nil
}

// EncryptedNameForNodeRequest contains an EncryptedName for an Account and the corresponding NodeID.
type EncryptedNameForNodeRequest struct {
	EncryptedNameRequest
	NodeID uuid.UUID `json:"node_id"`
}

// Validate validates the EncryptedNameForNodeRequest.
func (nnr EncryptedNameForNodeRequest) Validate() error {
	if nnr.NodeID.IsZero() {
		return ErrInvalidNodeID
	}

	err := nnr.EncryptedNameRequest.Validate()
	if err != nil {
		return err
	}

	return nil
}
