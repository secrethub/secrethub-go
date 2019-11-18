package api

import (
	"encoding/json"
	"strings"
)

// Errors
var (
	ErrInvalidEncryptionAlgorithm    = errAPI.Code("invalid_encryption_algorithm").Error("invalid encryption algorithm provided")
	ErrInvalidKeyType                = errAPI.Code("invalid_key_type").Error("invalid key type")
	ErrKeyAlgorithmMismatch          = errAPI.Code("key_algorithm_mismatch").Error("mismatch between algorithm and key type")
	ErrInvalidKeyLength              = errAPI.Code("invalid_key_length").Error("key length value is invalid")
	ErrInvalidKeyDerivationAlgorithm = errAPI.Code("invalid_key_derivation_algorithm").Error("invalid key derivation algorithm")
)

// EncryptionAlgorithm specifies the encryption algorithm used for EncryptedData.
type EncryptionAlgorithm string

// UnmarshalJSON populates an EncryptionAlgorithm by converting an input string to lowercase.
func (ed *EncryptionAlgorithm) UnmarshalJSON(b []byte) error {
	var v string
	err := json.Unmarshal(b, &v)
	if err != nil {
		return err
	}
	*ed = EncryptionAlgorithm(strings.ToLower(v))
	return nil
}

// HashingAlgorithm specifies the hashing algorithm used for any encryption algorithm using hasing.
type HashingAlgorithm string

// UnmarshalJSON populates an HashingAlgorithm by converting an input string to lowercase.
func (ed *HashingAlgorithm) UnmarshalJSON(b []byte) error {
	var v string
	err := json.Unmarshal(b, &v)
	if err != nil {
		return err
	}
	*ed = HashingAlgorithm(strings.ToLower(v))
	return nil
}

// Supported values for EncryptionAlgorithm.
const (
	EncryptionAlgorithmAESGCM  EncryptionAlgorithm = "aes-gcm"
	EncryptionAlgorithmRSAOEAP EncryptionAlgorithm = "rsa-oaep"
	EncryptionAlgorithmAWSKMS  EncryptionAlgorithm = "aws-kms"

	HashingAlgorithmSHA256 HashingAlgorithm = "sha-256"
)

// EncryptedData contains data that is encrypted with an algorithm described by Algorithm.
// If the encryption method requires metadata, this is contained in Metadata.
type EncryptedData struct {
	Algorithm  EncryptionAlgorithm `json:"algorithm"`
	Key        interface{}         `json:"key"`
	Parameters interface{}         `json:"parameters,omitempty"`
	Metadata   interface{}         `json:"metadata,omitempty"`
	Ciphertext []byte              `json:"ciphertext"`
}

// NewEncryptedDataAESGCM creates a new EncryptedData with the AES-GCM algorithm.
func NewEncryptedDataAESGCM(ciphertext, nonce []byte, nonceLength int, key interface{}) *EncryptedData {
	return &EncryptedData{
		Algorithm: EncryptionAlgorithmAESGCM,
		Key:       key,
		Metadata: &EncryptionMetadataAESGCM{
			Nonce: nonce,
		},
		Parameters: &EncryptionParametersAESGCM{
			NonceLength: nonceLength,
		},
		Ciphertext: ciphertext,
	}
}

// NewEncryptedDataRSAOAEP creates a new EncryptedData with the RSA-OAEP algorithm.
func NewEncryptedDataRSAOAEP(ciphertext []byte, hashingAlgorithm HashingAlgorithm, key interface{}) *EncryptedData {
	return &EncryptedData{
		Algorithm: EncryptionAlgorithmRSAOEAP,
		Key:       key,
		Metadata:  nil,
		Parameters: &EncryptionParametersRSAOAEP{
			HashingAlgorithm: hashingAlgorithm,
		},
		Ciphertext: ciphertext,
	}
}

// NewEncryptedDataAWSKMS creates a new EncryptedData with the AWS-KMS algorithm.
func NewEncryptedDataAWSKMS(ciphertext []byte, key *EncryptionKeyAWS) *EncryptedData {
	return &EncryptedData{
		Algorithm:  EncryptionAlgorithmAWSKMS,
		Key:        key,
		Metadata:   nil,
		Parameters: nil,
		Ciphertext: ciphertext,
	}
}

// UnmarshalJSON populates an EncryptedData from a JSON representation.
func (ed *EncryptedData) UnmarshalJSON(b []byte) error {
	// Declare a private type to avoid recursion into this function.
	type encryptedData EncryptedData

	var rawKey, rawParameters, rawMetadata json.RawMessage
	dec := encryptedData{
		Key:        &rawKey,
		Parameters: &rawParameters,
		Metadata:   &rawMetadata,
	}
	err := json.Unmarshal(b, &dec)
	if err != nil {
		return err
	}
	if rawKey == nil {
		return ErrInvalidKeyType
	}
	var keyType struct {
		Type KeyType `json:"type"`
	}
	err = json.Unmarshal(rawKey, &keyType)
	if err != nil {
		return err
	}

	switch keyType.Type {
	case KeyTypeDerived:
		dec.Key = &EncryptionKeyDerived{}
	case KeyTypeEncrypted:
		dec.Key = &EncryptionKeyEncrypted{}
	case KeyTypeLocal:
		dec.Key = &EncryptionKeyLocal{}
	case KeyTypeBootstrapCode:
		dec.Key = &EncryptionKeyBootstrapCode{}
	case KeyTypeAccountKey:
		dec.Key = &EncryptionKeyAccountKey{}
	case KeyTypeSecretKey:
		dec.Key = &EncryptionKeySecretKey{}
	case KeyTypeAWS:
		dec.Key = &EncryptionKeyAWS{}
	default:
		return ErrInvalidKeyType
	}
	err = json.Unmarshal(rawKey, dec.Key)
	if err != nil {
		return err
	}

	switch dec.Algorithm {
	case EncryptionAlgorithmRSAOEAP:
		dec.Metadata = nil
		dec.Parameters = &EncryptionParametersRSAOAEP{}
	case EncryptionAlgorithmAESGCM:
		dec.Metadata = &EncryptionMetadataAESGCM{}
		dec.Parameters = &EncryptionParametersAESGCM{}
	case EncryptionAlgorithmAWSKMS:
		dec.Metadata = nil
		dec.Parameters = nil
	default:
		return ErrInvalidEncryptionAlgorithm
	}

	if rawMetadata != nil && dec.Metadata != nil {
		err = json.Unmarshal(rawMetadata, dec.Metadata)
		if err != nil {
			return err
		}
	}
	if rawParameters != nil && dec.Parameters != nil {
		err = json.Unmarshal(rawParameters, dec.Parameters)
		if err != nil {
			return err
		}
	}
	*ed = EncryptedData(dec)
	return nil
}

type keyValidator interface {
	validator
	SupportsAlgorithm(EncryptionAlgorithm) bool
}

// Validate whether the EncryptedData is valid.
func (ed *EncryptedData) Validate() error {
	if ed.Algorithm != EncryptionAlgorithmAESGCM &&
		ed.Algorithm != EncryptionAlgorithmRSAOEAP &&
		ed.Algorithm != EncryptionAlgorithmAWSKMS {
		return ErrInvalidEncryptionAlgorithm
	}

	if ed.Key == nil {
		return ErrMissingField("key")
	}
	if ed.Ciphertext == nil {
		return ErrMissingField("ciphertext")
	}

	key := ed.Key.(keyValidator)
	if err := key.Validate(); err != nil {
		return err
	}
	if !key.SupportsAlgorithm(ed.Algorithm) {
		return ErrKeyAlgorithmMismatch
	}

	parameters, ok := ed.Parameters.(validator)
	if ok {
		if err := parameters.Validate(); err != nil {
			return err
		}
	}

	metadata, ok := ed.Metadata.(validator)
	if ok {
		if err := metadata.Validate(); err != nil {
			return err
		}
	}
	return nil
}
