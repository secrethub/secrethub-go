package crypto

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"

	"github.com/keylockerbv/secrethub-go/pkg/errio"
)

// Errors
var (
	ErrWrongKeyType      = errCrypto.Code("wrong_key_type").Error("received wrong key type")
	ErrInvalidCiphertext = errCrypto.Code("invalid_ciphertext").Error("ciphertext contains invalid data")
	ErrUnknownAlgorithm  = errCrypto.Code("unknown_algorithm").Error("algorithm of the encoded ciphertext is invalid")
	ErrWrongAlgorithm    = errCrypto.Code("wrong_algorithm").Error("unexpected algorithm of the encoded ciphertext")
	ErrInvalidMetadata   = errCrypto.Code("invalid_metadata").Error("metadata of encrypted key is invalid")
)

var (
	// encodedCiphertextPattern matches "<algorithm name>$<base64 encoded string>$<parameter name>=<parameter value>,<parameter name>=<parameter value>...".
	encodedCiphertextPattern = regexp.MustCompile(`^([a-zA-Z0-9\-+]+)\$([A-Za-z0-9+/]+(?:={0,2})?)\$((?:[a-zA-Z]+=[a-zA-Z0-9+/]+(?:={0,2})?(?:$|,))*)$`)

	// encodedCiphertextMetadataPattern matches "<parameter name>=<parameter value>".
	// Can be used to find the value of a parameter, as this is captured.
	// Usage:
	// 	pattern := fmt.Sprintf(encodedCiphertextMetadataPattern, "<parameter name>")
	// 	regexp, err := regexp.Compile(pattern)
	// 	matches := regexp.FindStringSubmatch(string(m))
	//  parameterValue = matches[1]
	encodedCiphertextMetadataPattern = `(?:^|,)%s=([a-zA-Z0-9\+/]+(?:={0,2}?))(?:$|,)`
)

// Key represents a key that can be used to decrypt data.
type Key interface{}

// Ciphertext is an interface for to decrypt encrypted data.
type Ciphertext interface{}

// EncodedCiphertext contains a string in the format <algorithm>$<base64-encoded-encrypted-data>$<metadata>.
type EncodedCiphertext string

// EncodedCiphertextAES contains a string in the format AES-GCM$<base64-encoded-encrypted-data>$<metadata>.
type EncodedCiphertextAES EncodedCiphertext

// EncodedCiphertextRSA contains a string in the format RSA-OAEP$<base64-encoded-encrypted-data>$<metadata>.
type EncodedCiphertextRSA EncodedCiphertext

// EncodedCiphertextRSAAES contains a string in the format RSA-OAEP+AES-GCM$<base64-encoded-encrypted-data>$<metadata>.
type EncodedCiphertextRSAAES EncodedCiphertext

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

func (ec EncodedCiphertextRSA) decode() (*ciphertextRSA, error) {
	algorithm, err := EncodedCiphertext(ec).GetAlgorithm()
	if err != nil {
		return nil, errio.Error(err)
	}

	if algorithm != AlgorithmRSA {
		return nil, ErrWrongAlgorithm
	}

	encryptedData, err := EncodedCiphertext(ec).GetData()
	if err != nil {
		return nil, errio.Error(err)
	}

	return &ciphertextRSA{
		Data: encryptedData,
	}, nil
}

func (ec EncodedCiphertextRSAAES) decode() (*ciphertextRSAAES, error) {
	algorithm, err := EncodedCiphertext(ec).GetAlgorithm()
	if err != nil {
		return nil, errio.Error(err)
	}

	if algorithm != AlgorithmRSA {
		return nil, ErrWrongAlgorithm
	}

	encryptedData, err := EncodedCiphertext(ec).GetData()
	if err != nil {
		return nil, errio.Error(err)
	}

	metadata, err := EncodedCiphertext(ec).GetMetadata()
	if err != nil {
		return nil, errio.Error(err)
	}

	aesNonce, err := metadata.GetDecodedValue("nonce")
	if err != nil {
		return nil, errio.Error(err)
	}

	aesKey, err := metadata.GetDecodedValue("key")
	if err != nil {
		return nil, errio.Error(err)
	}

	return &ciphertextRSAAES{
		ciphertextAES: &ciphertextAES{
			Data:  encryptedData,
			Nonce: aesNonce,
		},
		ciphertextRSA: &ciphertextRSA{
			Data: aesKey,
		},
	}, nil
}

func (ec EncodedCiphertextAES) decode() (*ciphertextAES, error) {
	algorithm, err := EncodedCiphertext(ec).GetAlgorithm()
	if err != nil {
		return nil, errio.Error(err)
	}

	if algorithm != AlgorithmAES {
		return nil, ErrWrongAlgorithm
	}

	encryptedData, err := EncodedCiphertext(ec).GetData()
	if err != nil {
		return nil, errio.Error(err)
	}

	metadata, err := EncodedCiphertext(ec).GetMetadata()
	if err != nil {
		return nil, errio.Error(err)
	}

	aesNonce, err := metadata.GetDecodedValue("nonce")
	if err != nil {
		return nil, errio.Error(err)
	}

	return &ciphertextAES{
		Data:  encryptedData,
		Nonce: aesNonce,
	}, nil
}

// Validate validates the encoded ciphertext.
func (ec EncodedCiphertextRSA) Validate() error {
	err := EncodedCiphertext(ec).Validate()
	if err != nil {
		return err
	}

	algorithm, err := EncodedCiphertext(ec).GetAlgorithm()
	if err != nil {
		return err
	}

	if algorithm != AlgorithmRSA {
		return ErrWrongAlgorithm
	}

	return nil
}

// Validate validates the encoded ciphertext.
func (ec EncodedCiphertextAES) Validate() error {
	err := EncodedCiphertext(ec).Validate()
	if err != nil {
		return err
	}

	algorithm, err := EncodedCiphertext(ec).GetAlgorithm()
	if err != nil {
		return err
	}

	if algorithm != AlgorithmAES {
		return ErrWrongAlgorithm
	}

	return nil
}

// Validate validates the encoded ciphertext.
func (ec EncodedCiphertextRSAAES) Validate() error {
	err := EncodedCiphertext(ec).Validate()
	if err != nil {
		return err
	}

	algorithm, err := EncodedCiphertext(ec).GetAlgorithm()
	if err != nil {
		return err
	}

	if algorithm != AlgorithmRSAAES {
		return ErrWrongAlgorithm
	}

	return nil
}
