package api

import (
	"github.com/keylockerbv/secrethub/core/uuid"
)

// EncryptedNameRequest contains an EncryptedName for an Account.
type EncryptedNameRequest struct {
	AccountID     *uuid.UUID        `json:"account_id"`
	EncryptedName EncodedCiphertext `json:"encrypted_name"`
}

// Validate validates the EncryptedNameRequest to be valid.
func (enr *EncryptedNameRequest) Validate() error {
	if enr.AccountID == nil {
		return ErrInvalidAccountID
	}

	err := enr.EncryptedName.Validate()
	if err != nil {
		return err
	}

	return nil
}

// EncryptedNameForNodeRequest contains an EncryptedName for an Account and the corresponding NodeID.
type EncryptedNameForNodeRequest struct {
	EncryptedNameRequest
	NodeID *uuid.UUID `json:"node_id"`
}

// Validate validates the EncryptedNameForNodeRequest.
func (nnr EncryptedNameForNodeRequest) Validate() error {
	if nnr.NodeID == nil {
		return ErrInvalidNodeID
	}

	if nnr.AccountID == nil {
		return ErrInvalidAccountID
	}

	err := nnr.EncryptedName.Validate()
	if err != nil {
		return err
	}

	return nil
}
