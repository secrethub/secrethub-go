package api

import (
	"encoding/json"

	"github.com/secrethub/secrethub-go/internals/crypto"
)

// Errors
var (
	ErrInvalidEncryptionType = errAPI.Code("invalid_encryption_type").Error("invalid encryption method provided for key")
)

// EncryptionType specifies the encryption method used for an EncryptedValue.
type EncryptionType string

// Supported values for EncryptionType.
const (
	EncryptionTypeRSAAES  EncryptionType = "rsa-oaep-aes-gcm"
	EncryptionTypeAWSKKMS EncryptionType = "aws-kms"
)

// EncryptedValue contains a value that is encrypted with a method described by EncryptionType.
// If the encryption method requires metadata, this is contained in Metadata.
type EncryptedValue struct {
	EncryptionType *EncryptionType `json:"encryption_type"`
	Ciphertext     []byte          `json:"ciphertext"`
	Metadata       interface{}     `json:"metadata"`
}

// EncryptionMetadataRSAAES contains all metadata for combined encryption with RSA-OAEP and AES-GCM.
type EncryptionMetadataRSAAES struct {
	RSAKeySize      *int   `json:"rsa_key_size"`
	AESKeySize      *int   `json:"aes_key_size"`
	EncryptedAESKey []byte `json:"aes_key"`
	AESNonce        []byte `json:"aes_nonce"`
}

// EncryptionMetadataAWSKMS contains all metadata for AWS KMS encryption.
type EncryptionMetadataAWSKMS struct {
}

// UnmarshalJSON populates an EncryptedValue from a JSON representation.
func (ek *EncryptedValue) UnmarshalJSON(b []byte) error {
	encodedMetadata := json.RawMessage{}
	ek.Metadata = &encodedMetadata
	err := json.Unmarshal(b, &ek)
	if err != nil {
		return err
	}

	if ek.EncryptionType == nil {
		return ErrInvalidEncryptionType
	}

	switch *ek.EncryptionType {
	case EncryptionTypeRSAAES:
		ek.Metadata = &EncryptionMetadataRSAAES{}
	case EncryptionTypeAWSKKMS:
		ek.Metadata = &EncryptionMetadataAWSKMS{}
	default:
		return ErrInvalidEncryptionType
	}

	err = json.Unmarshal(encodedMetadata, ek.Metadata)
	if err != nil {
		return err
	}
	return nil
}

// ToCiphertextRSAAES converts a EncryptedValue to crypto.CiphertextRSAAES, if the EncryptedValue has the correct type.
func (ek *EncryptedValue) ToCiphertextRSAAES() (*crypto.CiphertextRSAAES, error) {
	metadata, ok := ek.Metadata.(*EncryptionMetadataRSAAES)
	if !ok {
		return nil, crypto.ErrInvalidMetadata
	}
	return &crypto.CiphertextRSAAES{
		AES: crypto.CiphertextAES{
			Data:  ek.Ciphertext,
			Nonce: metadata.AESNonce,
		},
		RSA: crypto.CiphertextRSA{
			Data: metadata.EncryptedAESKey,
		},
	}, nil
}

// NewEncryptedValueFromCiphertextRSAAES creates a new EncryptedValue from a crypto.CiphertextRSAAES.
func NewEncryptedValueFromCiphertextRSAAES(ciphertext crypto.CiphertextRSAAES) *EncryptedValue {
	encryptionType := EncryptionTypeRSAAES

	return &EncryptedValue{
		EncryptionType: &encryptionType,
		Ciphertext:     ciphertext.AES.Data,
		Metadata: &EncryptionMetadataRSAAES{
			RSAKeySize:      Int(crypto.RSAKeyLength),
			AESKeySize:      Int(crypto.SymmetricKeyLength * 8),
			AESNonce:        ciphertext.AES.Nonce,
			EncryptedAESKey: ciphertext.RSA.Data,
		},
	}
}
