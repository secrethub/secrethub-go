package api

import (
	"encoding/json"
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
	// Declare a private type to avoid recursion into this function.
	type encryptedValue EncryptedValue

	var rawMessage json.RawMessage
	dec := encryptedValue{
		Metadata: &rawMessage,
	}
	err := json.Unmarshal(b, &dec)
	if err != nil {
		return err
	}

	if dec.EncryptionType == nil {
		return ErrInvalidEncryptionType
	}

	switch *dec.EncryptionType {
	case EncryptionTypeRSAAES:
		dec.Metadata = &EncryptionMetadataRSAAES{}
	case EncryptionTypeAWSKKMS:
		dec.Metadata = &EncryptionMetadataAWSKMS{}
	default:
		return ErrInvalidEncryptionType
	}

	err = json.Unmarshal(rawMessage, dec.Metadata)
	if err != nil {
		return err
	}
	*ek = EncryptedValue(dec)
	return nil
}
