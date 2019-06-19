package api

import (
	"encoding/json"
	"errors"
)

// Errors
var (
	ErrInvalidEncryptionAlgorithm = errAPI.Code("invalid_encryption_algorithm").Error("invalid encryption algorithm provided")
	ErrInvalidKeyType             = errAPI.Code("invalid_key_type").Error("invalid key type")
	ErrKeyAlgorithmMismatch       = errAPI.Code("key_algorithm_mismatch").Error("mismatch between algorithm and key type")
	ErrInvalidKeyLength           = errAPI.Code("invalid_key_length").Error("key length value is invalid")
	errWrongKeyType               = errors.New("key type field set to wrong value, refer to the documentation to construct a legal struct")
	errInvalidEncryptedData       = errors.New("invalid EncryptedData struct was constructed, refer to the documentation to construct a legal struct")
)

// EncryptionAlgorithm specifies the encryption algorithm used for EncryptedData.
type EncryptionAlgorithm string
type HashingAlgorithm string

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

func NewEncryptedDataAESGCM(ciphertext, nonce []byte, nonceLength int, key interface{}) *EncryptedData {
	return &EncryptedData{
		Algorithm: EncryptionAlgorithmAESGCM,
		Key:       key,
		Metadata: &EncryptionMetadataAESGCM{
			Nonce: nonce,
		},
		Parameters: &EncryptionParametersAESGCM{
			NonceLength: &nonceLength,
		},
		Ciphertext: ciphertext,
	}
}

func NewEncryptedDataRSAOAEP(ciphertext []byte, hashingAlgorithm HashingAlgorithm, key interface{}) *EncryptedData {
	return &EncryptedData{
		Algorithm: EncryptionAlgorithmRSAOEAP,
		Key:       key,
		Metadata:  &EncryptionMetadataRSAOEAP{},
		Parameters: &EncryptionParametersRSAOAEP{
			HashingAlgorithm: hashingAlgorithm,
		},
		Ciphertext: ciphertext,
	}
}

func NewEncryptedDataAWSKMS(ciphertext []byte, key *EncryptionKeyAWS) *EncryptedData {
	return &EncryptedData{
		Algorithm:  EncryptionAlgorithmAWSKMS,
		Key:        key,
		Metadata:   &EncryptionMetadataAWSKMS{},
		Parameters: &EncryptionParametersAWSKMS{},
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
		dec.Metadata = &EncryptionMetadataRSAOEAP{}
		dec.Parameters = &EncryptionParametersRSAOAEP{}
	case EncryptionAlgorithmAESGCM:
		dec.Metadata = &EncryptionMetadataAESGCM{}
		dec.Parameters = &EncryptionParametersAESGCM{}
	case EncryptionAlgorithmAWSKMS:
		dec.Metadata = &EncryptionMetadataAWSKMS{}
		dec.Parameters = &EncryptionParametersAWSKMS{}
	default:
		return ErrInvalidEncryptionAlgorithm
	}

	if rawMetadata != nil {
		err = json.Unmarshal(rawMetadata, dec.Metadata)
		if err != nil {
			return err
		}
	}
	if rawParameters != nil {
		err = json.Unmarshal(rawParameters, dec.Parameters)
		if err != nil {
			return err
		}
	}
	*ed = EncryptedData(dec)
	return nil
}

type validator interface {
	Validate() error
}

type keyValidator interface {
	validator
	AlgorithmSupported(EncryptionAlgorithm) bool
}

func (ed *EncryptedData) Validate() error {
	if ed.Algorithm != EncryptionAlgorithmAESGCM &&
		ed.Algorithm != EncryptionAlgorithmRSAOEAP &&
		ed.Algorithm != EncryptionAlgorithmAWSKMS {
		return ErrInvalidEncryptionAlgorithm
	}

	if ed.Key == nil {
		return ErrMissingField("key")
	}
	if ed.Parameters == nil {
		return ErrMissingField("parameters")
	}
	if ed.Metadata == nil {
		return ErrMissingField("parameters")
	}
	if ed.Ciphertext == nil {
		return ErrMissingField("ciphertext")
	}

	key, ok := ed.Key.(keyValidator)
	if !ok {
		// TODO: or do we just want to panic here? This should never fail when the code is used correctly.
		return errInvalidEncryptedData
	}
	if err := key.Validate(); err != nil {
		return err
	}
	if !key.AlgorithmSupported(ed.Algorithm) {
		return ErrKeyAlgorithmMismatch
	}

	parameters, ok := ed.Parameters.(validator)
	if !ok {
		// TODO: or do we just want to panic here? This should never fail when the code is used correctly.
		return errInvalidEncryptedData
	}
	if err := parameters.Validate(); err != nil {
		return err
	}

	metadata, ok := ed.Metadata.(validator)
	if !ok {
		// TODO: or do we just want to panic here? This should never fail when the code is used correctly.
		return errInvalidEncryptedData
	}
	if err := metadata.Validate(); err != nil {
		return err
	}
	return nil
}
