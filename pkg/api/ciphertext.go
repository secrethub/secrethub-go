package api

import (
	"fmt"
	"regexp"

	"github.com/keylockerbv/secrethub-go/pkg/crypto"
	"github.com/keylockerbv/secrethub-go/pkg/errio"

	"encoding/base64"
	"sort"
)

// Errors
var (
	ErrUnknownAlgorithm  = errAPI.Code("unknown_algorithm").Error("algorithm of the encoded ciphertext is invalid")
	ErrInvalidCiphertext = errAPI.Code("invalid_ciphertext").Error("cannot encode invalid ciphertext")
)

// EncodedCiphertext contains a string in the format <algorithm>$<base64-encoded-encrypted-data>$<metadata>.
type EncodedCiphertext string

// EncryptionAlgorithm represents the algorithm an EncodedCiphertext is encrypted with.
type EncryptionAlgorithm string

// EncryptionAlgorithm definitions
const (
	AlgorithmRSAAES EncryptionAlgorithm = "RSA-OAEP+AES-GCM"
	AlgorithmRSA    EncryptionAlgorithm = "RSA-OAEP"
	AlgorithmAES    EncryptionAlgorithm = "AES-GCM"
)

// EncodedCiphertextMetadata represents the metadata of an EncodedCiphertext.
// Has the form of <name>=<value>,<name>=<value>.
// E.g. nonce=abcd,length=1024
type EncodedCiphertextMetadata string

// NewEncodedCiphertext creates a new EncodedCiphertext from an EncryptionAlgorithm and a []byte with a key.
func NewEncodedCiphertext(algorithm EncryptionAlgorithm, keyData []byte, metadataList map[string]string) EncodedCiphertext {
	encodedKey := base64.StdEncoding.EncodeToString(keyData)

	metadata := NewEncodedCiphertextMetadata(metadataList)

	return EncodedCiphertext(fmt.Sprintf("%s$%s$%s", algorithm, encodedKey, metadata))
}

// EncodeCiphertext creates a new EncodedCiphertext based on an existing Ciphertext.
func EncodeCiphertext(ciphertext crypto.Ciphertext) (EncodedCiphertext, error) {

	var encoded EncodedCiphertext

	if ciphertext == nil {
		return "", ErrInvalidCiphertext
	}

	switch c := ciphertext.(type) {
	case *crypto.CiphertextRSAAES:

		if c.CiphertextAES == nil || c.CiphertextRSA == nil {
			return "", ErrInvalidCiphertext
		}

		encoded = NewEncodedCiphertext(
			AlgorithmRSAAES,
			c.CiphertextAES.Data,
			map[string]string{
				"nonce": base64.StdEncoding.EncodeToString(c.CiphertextAES.Nonce),
				"key":   base64.StdEncoding.EncodeToString(c.CiphertextRSA.Data),
			},
		)
	case *crypto.CiphertextRSA:
		encoded = NewEncodedCiphertext(
			AlgorithmRSA,
			c.Data,
			nil,
		)
	case *crypto.CiphertextAES:
		encoded = NewEncodedCiphertext(
			AlgorithmAES,
			c.Data,
			map[string]string{
				"nonce": base64.StdEncoding.EncodeToString(c.Nonce),
			},
		)
	default:
		return "", ErrUnknownAlgorithm
	}

	err := encoded.Validate()
	if err != nil {
		return "", err
	}

	return encoded, nil
}

// Validate verifies the EncodedCiphertext has a valid format.
func (ec EncodedCiphertext) Validate() error {
	if !encodedCiphertextPattern.MatchString(string(ec)) {
		return ErrInvalidCiphertext
	}

	return nil
}

// parseRegex finds all matches of the encryptedKeyPattern regex on the EncodedCiphertext.
func (ec EncodedCiphertext) parseRegex() ([]string, error) {
	matches := encodedCiphertextPattern.FindStringSubmatch(string(ec))
	if len(matches) < 4 {
		return nil, ErrInvalidCiphertext
	}
	return matches, nil
}

// GetAlgorithm returns the algorithm part of the EncodedCiphertext.
func (ec EncodedCiphertext) GetAlgorithm() (EncryptionAlgorithm, error) {
	matches, err := ec.parseRegex()
	if err != nil {
		return "", errio.Error(err)
	}
	return EncryptionAlgorithm(matches[1]), nil
}

// GetData returns the encrypted data part of the EncodedCiphertext.
func (ec EncodedCiphertext) GetData() ([]byte, error) {
	matches, err := ec.parseRegex()
	if err != nil {
		return nil, errio.Error(err)
	}
	return base64.StdEncoding.DecodeString(matches[2])
}

// GetMetadata returns the metadata part of the EncodedCiphertext.
func (ec EncodedCiphertext) GetMetadata() (EncodedCiphertextMetadata, error) {
	matches, err := ec.parseRegex()
	if err != nil {
		return "", errio.Error(err)
	}
	return EncodedCiphertextMetadata(matches[3]), nil
}

// Decode converts an EncodedCiphertext into an instance of Ciphertext (CiphertextRSAAES, CiphertextRSA or CiphertextAES).
func (ec EncodedCiphertext) Decode() (crypto.Ciphertext, error) {

	algorithm, err := ec.GetAlgorithm()
	if err != nil {
		return nil, errio.Error(err)
	}

	encryptedData, err := ec.GetData()
	if err != nil {
		return nil, errio.Error(err)
	}

	metadata, err := ec.GetMetadata()
	if err != nil {
		return nil, errio.Error(err)
	}

	switch algorithm {
	case AlgorithmRSAAES:

		aesNonce, err := metadata.GetDecodedValue("nonce")
		if err != nil {
			return nil, errio.Error(err)
		}

		aesKey, err := metadata.GetDecodedValue("key")
		if err != nil {
			return nil, errio.Error(err)
		}

		return &crypto.CiphertextRSAAES{
			CiphertextAES: &crypto.CiphertextAES{
				Data:  encryptedData,
				Nonce: aesNonce,
			},
			CiphertextRSA: &crypto.CiphertextRSA{
				Data: aesKey,
			},
		}, nil

	case AlgorithmRSA:

		return &crypto.CiphertextRSA{
			Data: encryptedData,
		}, nil

	case AlgorithmAES:

		aesNonce, err := metadata.GetDecodedValue("nonce")
		if err != nil {
			return nil, errio.Error(err)
		}

		return &crypto.CiphertextAES{
			Data:  encryptedData,
			Nonce: aesNonce,
		}, nil

	default:
		return nil, ErrUnknownAlgorithm
	}

}

// NewEncodedCiphertextMetadata creates a new EncodedCiphertextMetadata from a map of metadata.
// Input of {"param": "foo", "second": "bar"} outputs "param=foo,second=bar".
func NewEncodedCiphertextMetadata(metadataList map[string]string) EncodedCiphertextMetadata {
	metadata := ""

	// Sort all the keys of the metadataList so that metadata is always in alphabetical order.
	var keys []string
	for k := range metadataList {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		separator := ""
		if len(metadata) > 0 {
			separator = ","
		}
		metadata = fmt.Sprintf("%s%s%s=%s", metadata, separator, k, metadataList[k])
	}

	return EncodedCiphertextMetadata(metadata)
}

// GetValue returns a value from metadata.
// E.g. when the metadata is "first=foo,second=bar", then GetValue("second") => "bar".
func (m EncodedCiphertextMetadata) GetValue(name string) (string, error) {
	pattern := fmt.Sprintf(encodedCiphertextMetadataPattern, name)
	regexp, err := regexp.Compile(pattern)

	if err != nil {
		return "", ErrInvalidMetadata
	}

	matches := regexp.FindStringSubmatch(string(m))

	if len(matches) < 2 {
		return "", ErrInvalidMetadata
	}

	return matches[1], nil
}

// GetDecodedValue gets the value as if GetValue and also decodes it from base64.
func (m EncodedCiphertextMetadata) GetDecodedValue(name string) ([]byte, error) {
	dataStr, err := m.GetValue(name)
	if err != nil {
		return nil, ErrInvalidMetadata
	}

	return base64.StdEncoding.DecodeString(dataStr)
}
