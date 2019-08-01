package api

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/secrethub/secrethub-go/internals/api/uuid"
)

// KeyType specifies the type of key used for EncryptedData.
type KeyType string

// UnmarshalJSON populates an KeyType by converting an input string to lowercase.
func (ed *KeyType) UnmarshalJSON(b []byte) error {
	var v string
	err := json.Unmarshal(b, &v)
	if err != nil {
		return err
	}
	*ed = KeyType(strings.ToLower(v))
	return nil
}

// KeyDerivationAlgorithm specifies the key derivation algorithm used for a derived key.
type KeyDerivationAlgorithm string

// UnmarshalJSON populates an KeyDerivationAlgorithm by converting an input string to lowercase.
func (ed *KeyDerivationAlgorithm) UnmarshalJSON(b []byte) error {
	var v string
	err := json.Unmarshal(b, &v)
	if err != nil {
		return err
	}
	*ed = KeyDerivationAlgorithm(strings.ToLower(v))
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
			P: p,
			N: n,
			R: r,
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

// SupportsAlgorithm returns true when the encryption key supports the given algorithm.
func (EncryptionKeyDerived) SupportsAlgorithm(a EncryptionAlgorithm) bool {
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

// SupportsAlgorithm returns true when the encryption key supports the given algorithm.
func (EncryptionKeyEncrypted) SupportsAlgorithm(a EncryptionAlgorithm) bool {
	return a == EncryptionAlgorithmAESGCM || a == EncryptionAlgorithmRSAOEAP
}

// Validate checks whether all the fields of the response are valid.
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
		Length: length,
	}
}

// EncryptionKeyLocal is an encryption key that has is stored locally by the user.
type EncryptionKeyLocal struct {
	EncryptionKey
	Length int `json:"length"`
}

// SupportsAlgorithm returns true when the encryption key supports the given algorithm.
func (EncryptionKeyLocal) SupportsAlgorithm(a EncryptionAlgorithm) bool {
	return a == EncryptionAlgorithmAESGCM || a == EncryptionAlgorithmRSAOEAP
}

// Validate whether the EncryptionKeyLocal is valid.
func (k EncryptionKeyLocal) Validate() error {
	if k.Length == 0 {
		return ErrMissingField("length")
	}
	if k.Length <= 0 {
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
		Length: length,
		ID:     id,
	}
}

// EncryptionKeyAccountKey is an account's master key that is used to encrypt data and/or keys specifically for an account.
type EncryptionKeyAccountKey struct {
	EncryptionKey
	Length int       `json:"length"`
	ID     uuid.UUID `json:"id"`
}

// SupportsAlgorithm returns true when the encryption key supports the given algorithm.
func (EncryptionKeyAccountKey) SupportsAlgorithm(a EncryptionAlgorithm) bool {
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
		Length: length,
		ID:     id,
	}
}

// EncryptionKeySecretKey is a key that is used to encrypt secrets
type EncryptionKeySecretKey struct {
	EncryptionKey
	Length int       `json:"length"`
	ID     uuid.UUID `json:"id"`
}

// SupportsAlgorithm returns true when the encryption key supports the given algorithm.
func (EncryptionKeySecretKey) SupportsAlgorithm(a EncryptionAlgorithm) bool {
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
		ID: id,
	}
}

// EncryptionKeyAWS is a key that is stored in the AWS KMS service and which can be used for encryption by calling the AWS KMS API.
type EncryptionKeyAWS struct {
	EncryptionKey
	ID string `json:"id"`
}

// SupportsAlgorithm returns true when the encryption key supports the given algorithm.
func (EncryptionKeyAWS) SupportsAlgorithm(a EncryptionAlgorithm) bool {
	return a == EncryptionAlgorithmAWSKMS
}

// Validate whether the EncryptionKeyAWS is valid.
func (k EncryptionKeyAWS) Validate() error {
	if k.ID == "" {
		return ErrMissingField("id")
	}
	return nil
}

// KeyDerivationParametersScrypt are the parameters used by the scrypt key derivation algorithm.
type KeyDerivationParametersScrypt struct {
	P int `json:"p"`
	N int `json:"n"`
	R int `json:"r"`
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
