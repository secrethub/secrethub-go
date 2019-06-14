package api

import (
	"net/http"
	"time"

	"github.com/secrethub/secrethub-go/internals/api/uuid"
)

// Errors
var (
	ErrInvalidFingerprint = errAPI.Code("invalid_fingerprint").StatusError("fingerprint is invalid", http.StatusBadRequest)
	ErrInvalidVerifier    = errAPI.Code("invalid_verifier").StatusError("verifier is invalid", http.StatusBadRequest)
	ErrInvalidAlgorithm   = errAPI.Code("invalid_algorithm").StatusError("algorithm is invalid", http.StatusBadRequest)
)

// Credential is used to authenticate to the API and to encrypt the account key.
type Credential struct {
	AccountID   *uuid.UUID     `json:"account_id"`
	Type        CredentialType `json:"algorithm"`
	CreatedAt   time.Time      `json:"created_at"`
	Fingerprint string         `json:"fingerprint"`
	Name        string         `json:"name"`
	Verifier    []byte         `json:"verifier"`
}

// CredentialType is used to identify the type of algorithm that is used for a credential.
type CredentialType string

// Credential types
const (
	CredentialTypeRSA    CredentialType = "rsa"
	CredentialTypeAWSSTS                = "aws-sts"
)

// Validate validates whether the algorithm type is valid.
func (a CredentialType) Validate() error {
	if a == CredentialTypeRSA || a == CredentialTypeAWSSTS {
		return nil
	}
	return ErrInvalidAlgorithm
}

// CreateCredentialRequest contains the fields to add a credential to an account.
type CreateCredentialRequest struct {
	Type        CredentialType `json:"type"`
	Fingerprint string         `json:"fingerprint"`
	Name        string         `json:"name,omitempty"`
	Verifier    []byte         `json:"verifier"`
	Proof       []byte         `json:"proof"`
}

// Validate validates the request fields.
func (req CreateCredentialRequest) Validate() error {
	if req.Fingerprint == "" {
		return ErrInvalidFingerprint
	}

	if len(req.Verifier) == 0 {
		return ErrInvalidVerifier
	}

	err := req.Type.Validate()
	if err != nil {
		return err
	}
	if req.Type == CredentialTypeAWSSTS && req.Proof == nil {
		return ErrMissingField("proof")
	}

	return nil
}
