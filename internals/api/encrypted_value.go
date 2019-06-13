package api

import (
	"encoding/json"

	"github.com/secrethub/secrethub-go/internals/crypto"
)

var (
	ErrInvalidEncryptionType = errAPI.Code("invalid_encryption_type").Error("invalid encryption method provided for key")
)

type EncryptionType string

const (
	EncryptionTypeRSAAES  EncryptionType = "rsa-oaep-aes-gcm"
	EncryptionTypeAWSKKMS                = "aws-kms"
)

type EncryptedValue struct {
	EncryptionType *EncryptionType `json:"encryption_type"`
	Ciphertext     []byte          `json:"ciphertext"`
	Metadata       interface{}     `json:"metadata"`
}

type EncryptionMetadataRSAAES struct {
	RSAKeySize      *int   `json:"rsa_key_size"`
	AESKeySize      *int   `json:"aes_key_size"`
	EncryptedAESKey []byte `json:"aes_key"`
	AESNonce        []byte `json:"aes_nonce"`
}

type EncryptionMetadataAWSKMS struct {
}

func (ek EncryptedValue) UnmarshalJSON(b []byte) error {
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

func (ek EncryptedValue) ToCiphertextRSAAES() (*crypto.CiphertextRSAAES, error) {
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
