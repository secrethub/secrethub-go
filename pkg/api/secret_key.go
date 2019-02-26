package api

import (
	"github.com/keylockerbv/secrethub-go/pkg/api/uuid"
	"github.com/keylockerbv/secrethub-go/pkg/crypto"
	"github.com/keylockerbv/secrethub-go/pkg/errio"
)

// SecretKey represents a secret key that is intended to be used by a specific account.
type SecretKey struct {
	SecretKeyID *uuid.UUID     `json:"secret_key_id"`
	AccountID   *uuid.UUID     `json:"account_id"`
	Key         *crypto.AESKey `json:"key"`
	Status      string         `json:"status"` // TODO SHDEV-702: actually set this in the response
}

// EncryptedSecretKey represents a secret key, encrypted for a specific account.
type EncryptedSecretKey struct {
	SecretKeyID  *uuid.UUID           `json:"secret_key_id"`
	AccountID    *uuid.UUID           `json:"account_id"`
	EncryptedKey crypto.CiphertextRSA `json:"encrypted_key"`
	Status       string               `json:"status"` // TODO SHDEV-702: actually set this in the response
}

// Decrypt decrypts an EncryptedSecretKey into a SecretKey.
func (k *EncryptedSecretKey) Decrypt(accountKey *crypto.RSAKey) (*SecretKey, error) {
	keyBytes, err := accountKey.Unwrap(k.EncryptedKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	return &SecretKey{
		SecretKeyID: k.SecretKeyID,
		AccountID:   k.AccountID,
		Key:         crypto.NewAESKey(keyBytes),
		Status:      k.Status,
	}, nil
}

// CreateSecretKeyRequest contains the request fields for creating a new secret key.
type CreateSecretKeyRequest struct {
	EncryptedFor []EncryptedKeyRequest `json:"encrypted_for"`
}

// Validate validates the request fields.
func (r *CreateSecretKeyRequest) Validate() error {
	if len(r.EncryptedFor) < 1 {
		return ErrNotEncryptedForAccounts
	}

	for _, ef := range r.EncryptedFor {
		err := ef.Validate()
		if err != nil {
			return err
		}
	}

	return nil
}

// EncryptedKeyRequest contains the request fields for re-encrypted for an account.
type EncryptedKeyRequest struct {
	AccountID    *uuid.UUID           `json:"account_id"`
	EncryptedKey crypto.CiphertextRSA `json:"encrypted_key"`
}

// Validate validates the request fields.
func (r *EncryptedKeyRequest) Validate() error {
	if r.AccountID == nil {
		return ErrInvalidAccountID
	}

	return nil
}

// ToAuditSubject converts a SecretKey to an AuditSubject
func (sk *SecretKey) ToAuditSubject() *AuditSubject {
	return &AuditSubject{
		SubjectID: sk.SecretKeyID,
		Type:      AuditSubjectSecretKey,
	}
}
