package api

import (
	"errors"
	"strings"

	"github.com/secrethub/secrethub-go/internals/api/uuid"
)

// KeyType specifies the type of key used for EncryptedData.
type KeyType string

// UnmarshalJSON populates an KeyType by converting an input string to lowercase.
func (ed *KeyType) UnmarshalJSON(b []byte) error {
	*ed = KeyType(strings.ToLower(string(b)))
	return nil
}

// KeyDerivationAlgorithm specifies the key derivation algorithm used for a derived key.
type KeyDerivationAlgorithm string

// UnmarshalJSON populates an KeyDerivationAlgorithm by converting an input string to lowercase.
func (ed *KeyDerivationAlgorithm) UnmarshalJSON(b []byte) error {
	*ed = KeyDerivationAlgorithm(strings.ToLower(string(b)))
	return nil
}

// Options for KeyType
const (
	KeyTypeDerived    KeyType = "derived"
	KeyTypeEncrypted  KeyType = "encrypted"
	KeyTypeLocal      KeyType = "local"
	KeyTypeAccountKey KeyType = "account-key"
	KeyTypeSecretKey  KeyType = "secret-key"
	KeyTypeAWS        KeyType = "aws"
)

// Options for KeyDerivationAlgorithm
const (
	KeyDerivationAlgorithmScrypt KeyDerivationAlgorithm = "scrypt"
)

// EncryptionKey specifies the common fields for all types of encryption keys.
type EncryptionKey struct {
	Type KeyType `json:"type"`
}

// NewEncryptionKeyDerivedScrypt creates a EncryptionKeyDerived with scrypt as key derivation algorithm.
func NewEncryptionKeyDerivedScrypt(length, p, n, r int, salt []byte) *EncryptionKeyDerived {
	return newEncryptionKeyDerived(
		KeyDerivationAlgorithmScrypt,
		length,
		&KeyDerivationParametersScrypt{
			P: Int(p),
			N: Int(n),
			R: Int(r),
		},
		&KeyDerivationMetadataScrypt{
			Salt: salt,
		},
	)
}

func newEncryptionKeyDerived(algorithm KeyDerivationAlgorithm, length int, parameters, metadata interface{}) *EncryptionKeyDerived {
	return &EncryptionKeyDerived{
		EncryptionKey: EncryptionKey{
			Type: KeyTypeDerived,
		},
		Length:     Int(length),
		Algorithm:  algorithm,
		Parameters: parameters,
		Metadata:   metadata,
	}
}

// EncryptionKeyDerived is an encryption key that can be derived from a passphrase.
type EncryptionKeyDerived struct {
	EncryptionKey
	Length     *int                   `json:"length"`
	Algorithm  KeyDerivationAlgorithm `json:"algorithm"`
	Parameters interface{}            `json:"parameters,omitempty"`
	Metadata   interface{}            `json:"metadata,omitempty"`
}

// AlgorithmSupported returns whether the given EncryptionAlgorithm is supported by this type of encrytpion key.
func (EncryptionKeyDerived) AlgorithmSupported(a EncryptionAlgorithm) bool {
	return a == EncryptionAlgorithmAESGCM
}

// Validate whether the EncryptionKeyDerived is valid.
func (EncryptionKeyDerived) Validate() error {
	// TODO: implement
	return nil
}

// NewEncryptionKeyEncrypted creates a EncryptionKeyEncrypted.
func NewEncryptionKeyEncrypted(length int, encryptedKey *EncryptedData) *EncryptionKeyEncrypted {
	return &EncryptionKeyEncrypted{
		EncryptionKey: EncryptionKey{
			Type: KeyTypeEncrypted,
		},
		Length:       Int(length),
		EncryptedKey: encryptedKey,
	}
}

// EncryptionKeyEncrypted is an encryption key that has been encrypted by another key.
type EncryptionKeyEncrypted struct {
	EncryptionKey
	Length       *int           `json:"length"`
	EncryptedKey *EncryptedData `json:"encrypted_key"`
}

// AlgorithmSupported returns whether the given EncryptionAlgorithm is supported by this type of encrytpion key.
func (EncryptionKeyEncrypted) AlgorithmSupported(a EncryptionAlgorithm) bool {
	return a == EncryptionAlgorithmAESGCM || a == EncryptionAlgorithmRSAOEAP
}

// Validate whether the EncryptionKeyEncrypted is valid.
func (k EncryptionKeyEncrypted) Validate() error {
	if k.Length == nil {
		return ErrMissingField("length")
	}
	if IntValue(k.Length) <= 0 {
		return ErrInvalidKeyLength
	}
	return k.EncryptedKey.Validate()
}

// NewEncryptionKeyLocal creates a EncryptionKeyLocal.
func NewEncryptionKeyLocal(length int) *EncryptionKeyLocal {
	return &EncryptionKeyLocal{
		EncryptionKey: EncryptionKey{
			Type: KeyTypeLocal,
		},
		Length: Int(length),
	}
}

// EncryptionKeyLocal is an encryption key that has is stored locally by the user.
type EncryptionKeyLocal struct {
	EncryptionKey
	Length *int `json:"length"`
}

// AlgorithmSupported returns whether the given EncryptionAlgorithm is supported by this type of encrytpion key.
func (EncryptionKeyLocal) AlgorithmSupported(a EncryptionAlgorithm) bool {
	return a == EncryptionAlgorithmAESGCM || a == EncryptionAlgorithmRSAOEAP
}

// Validate whether the EncryptionKeyLocal is valid.
func (k EncryptionKeyLocal) Validate() error {
	if k.Length == nil {
		return ErrMissingField("length")
	}
	if *k.Length <= 0 {
		return ErrInvalidKeyLength
	}
	return nil
}

// NewEncryptionKeyAccountKey creates a EncryptionKeyAccountKey.
func NewEncryptionKeyAccountKey(length int, id uuid.UUID) *EncryptionKeyAccountKey {
	return &EncryptionKeyAccountKey{
		EncryptionKey: EncryptionKey{
			Type: KeyTypeAccountKey,
		},
		Length: Int(length),
		ID:     &id,
	}
}

// EncryptionKeyAccountKey is an encryption key that is the account key of an account.
type EncryptionKeyAccountKey struct {
	EncryptionKey
	Length *int       `json:"length"`
	ID     *uuid.UUID `json:"id"`
}

// AlgorithmSupported returns whether the given EncryptionAlgorithm is supported by this type of encrytpion key.
func (EncryptionKeyAccountKey) AlgorithmSupported(a EncryptionAlgorithm) bool {
	return a == EncryptionAlgorithmRSAOEAP
}

// Validate whether the EncryptionKeyAccountKey is valid.
func (EncryptionKeyAccountKey) Validate() error {
	// TODO: implement
	return nil
}

// NewEncryptionKeySecretKey creates a EncryptionKeySecretKey.
func NewEncryptionKeySecretKey(length int, id uuid.UUID) *EncryptionKeySecretKey {
	return &EncryptionKeySecretKey{
		EncryptionKey: EncryptionKey{
			Type: KeyTypeSecretKey,
		},
		Length: Int(length),
		ID:     &id,
	}
}

// EncryptionKeySecretKey is an encryption key that is a secret key.
type EncryptionKeySecretKey struct {
	EncryptionKey
	Length *int       `json:"length"`
	ID     *uuid.UUID `json:"id"`
}

// AlgorithmSupported returns whether the given EncryptionAlgorithm is supported by this type of encrytpion key.
func (EncryptionKeySecretKey) AlgorithmSupported(a EncryptionAlgorithm) bool {
	return a == EncryptionAlgorithmAESGCM
}

// Validate whether the EncryptionKeySecretKey is valid.
func (EncryptionKeySecretKey) Validate() error {
	// TODO: implement
	return nil
}

// NewEncryptionKeyAWS creates a EncryptionKeyAWS.
func NewEncryptionKeyAWS(id string) *EncryptionKeyAWS {
	return &EncryptionKeyAWS{
		EncryptionKey: EncryptionKey{
			Type: KeyTypeAWS,
		},
		ID: &id,
	}
}

// EncryptionKeyAWS is an encryption key that is stored in AWS KMS.
type EncryptionKeyAWS struct {
	EncryptionKey
	ID *string `json:"id"`
}

// AlgorithmSupported returns whether the given EncryptionAlgorithm is supported by this type of encrytpion key.
func (EncryptionKeyAWS) AlgorithmSupported(a EncryptionAlgorithm) bool {
	return a == EncryptionAlgorithmAWSKMS
}

// Validate whether the EncryptionKeyAWS is valid.
func (k EncryptionKeyAWS) Validate() error {
	if k.ID == nil {
		return ErrMissingField("id")
	}
	return nil
}

// KeyDerivationParametersScrypt are the parameters used by the scrypt key derivation algorithm.
type KeyDerivationParametersScrypt struct {
	P *int `json:"p"`
	N *int `json:"n"`
	R *int `json:"r"`
}

// Validate whether the KeyDerivationParametersScrypt is valid.
func (KeyDerivationParametersScrypt) Validate() error {
	// TODO: implement
	return nil
}

// KeyDerivationMetadataScrypt is the metadata used by the scrypt key derivation algorithm.
type KeyDerivationMetadataScrypt struct {
	Salt []byte `json:"salt"`
}

// Validate whether the KeyDerivationMetadataScrypt is valid.
func (KeyDerivationMetadataScrypt) Validate() error {
	return nil
}

// UnmarshalJSON populates an EncryptionKeyDerived from a JSON representation.
func (ek *EncryptionKeyDerived) UnmarshalJSON(b []byte) error {
	return errors.New("derived key type not yet supported")
}
