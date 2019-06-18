package api

import (
	"errors"

	"github.com/secrethub/secrethub-go/internals/api/uuid"
)

type KeyType string
type KeyDerivationAlgorithm string

const (
	KeyTypeDerived    KeyType = "derived"
	KeyTypeEncrypted  KeyType = "encrypted"
	KeyTypeAccountKey KeyType = "account-key"
	KeyTypeSecretKey  KeyType = "secret-key"
	KeyTypeAWS        KeyType = "aws"

	KeyDerivationAlgorithmScrypt KeyDerivationAlgorithm = "scrypt"
)

type EncryptionKey struct {
	Type KeyType `json:"type"`
}

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
		Parameters: parameters,
		Metadata:   metadata,
	}
}

type EncryptionKeyDerived struct {
	EncryptionKey
	Length     *int                   `json:"length"`
	Algorithm  KeyDerivationAlgorithm `json:"algorithm"`
	Parameters interface{}            `json:"parameters,omitempty"`
	Metadata   interface{}            `json:"metadata,omitempty"`
}

func (EncryptionKeyDerived) AlgorithmSupported(a EncryptionAlgorithm) bool {
	return a == EncryptionAlgorithmAESGCM
}
func (EncryptionKeyDerived) Validate() error {
	// TODO: implement
	return nil
}

func NewEncryptionKeyEncrypted(length int, encryptedKey *EncryptedData) *EncryptionKeyEncrypted {
	return &EncryptionKeyEncrypted{
		EncryptionKey: EncryptionKey{
			Type: KeyTypeEncrypted,
		},
		Length:       Int(length),
		EncryptedKey: encryptedKey,
	}
}

type EncryptionKeyEncrypted struct {
	EncryptionKey
	Length       *int           `json:"length"`
	EncryptedKey *EncryptedData `json:"encrypted_key"`
}

func (EncryptionKeyEncrypted) AlgorithmSupported(a EncryptionAlgorithm) bool {
	return a == EncryptionAlgorithmAESGCM || a == EncryptionAlgorithmRSAOEAP
}
func (k EncryptionKeyEncrypted) Validate() error {
	if k.Type != KeyTypeEncrypted {
		return errWrongKeyType
	}
	if k.Length == nil {
		return ErrMissingField("length")
	}
	if *k.Length <= 0 {
		return ErrInvalidKeyLength
	}
	return k.EncryptedKey.Validate()
}

func NewEncryptionKeyAccountKey(length int, id uuid.UUID) *EncryptionKeyAccountKey {
	return &EncryptionKeyAccountKey{
		EncryptionKey: EncryptionKey{
			Type: KeyTypeAccountKey,
		},
		Length: Int(length),
		ID:     &id,
	}
}

type EncryptionKeyAccountKey struct {
	EncryptionKey
	Length *int       `json:"length"`
	ID     *uuid.UUID `json:"id"`
}

func (EncryptionKeyAccountKey) AlgorithmSupported(a EncryptionAlgorithm) bool {
	return a == EncryptionAlgorithmRSAOEAP
}
func (EncryptionKeyAccountKey) Validate() error {
	// TODO: implement
	return nil
}

func NewEncryptionKeySecretKey(length int, id uuid.UUID) *EncryptionKeySecretKey {
	return &EncryptionKeySecretKey{
		EncryptionKey: EncryptionKey{
			Type: KeyTypeSecretKey,
		},
		Length: Int(length),
		ID:     &id,
	}
}

type EncryptionKeySecretKey struct {
	EncryptionKey
	Length *int       `json:"length"`
	ID     *uuid.UUID `json:"id"`
}

func (EncryptionKeySecretKey) AlgorithmSupported(a EncryptionAlgorithm) bool {
	return a == EncryptionAlgorithmAESGCM
}
func (EncryptionKeySecretKey) Validate() error {
	// TODO: implement
	return nil
}

func NewEncryptionKeyAWS(id string) *EncryptionKeyAWS {
	return &EncryptionKeyAWS{
		EncryptionKey: EncryptionKey{
			Type: KeyTypeAWS,
		},
		ID: &id,
	}
}

type EncryptionKeyAWS struct {
	EncryptionKey
	ID *string `json:"id"`
}

func (EncryptionKeyAWS) AlgorithmSupported(a EncryptionAlgorithm) bool {
	return a == EncryptionAlgorithmAWSKMS
}
func (k EncryptionKeyAWS) Validate() error {
	if k.Type != KeyTypeAWS {
		return errWrongKeyType
	}
	if k.ID == nil {
		return ErrMissingField("id")
	}
	return nil
}

type KeyDerivationParametersScrypt struct {
	P *int `json:"p"`
	N *int `json:"n"`
	R *int `json:"r"`
}

func (KeyDerivationParametersScrypt) Validate() error {
	return nil
}

type KeyDerivationMetadataScrypt struct {
	Salt []byte `json:"salt"`
}

func (KeyDerivationMetadataScrypt) Validate() error {
	return nil
}

func (ek *EncryptionKeyDerived) UnmarshalJSON(b []byte) error {
	return errors.New("derived key type not yet supported")
}
