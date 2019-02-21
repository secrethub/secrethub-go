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
	ErrInvalidCiphertext = errCrypto.Code("invalid_ciphertext").Error("ciphertext contains invalid data")
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

// encodedCiphertext contains a string in the format <algorithm>$<base64-encoded-encrypted-data>$<metadata>.
type encodedCiphertext string

// EncodedCiphertextAES contains a string in the format AES-GCM$<base64-encoded-encrypted-data>$<metadata>.
type EncodedCiphertextAES encodedCiphertext

// EncodedCiphertextRSA contains a string in the format RSA-OAEP$<base64-encoded-encrypted-data>$<metadata>.
type EncodedCiphertextRSA encodedCiphertext

// EncodedCiphertextRSAAES contains a string in the format RSA-OAEP+AES-GCM$<base64-encoded-encrypted-data>$<metadata>.
type EncodedCiphertextRSAAES encodedCiphertext

// EncryptionAlgorithm represents the algorithm an EncodedCiphertext is encrypted with.
type EncryptionAlgorithm string

// EncryptionAlgorithm definitions
const (
	AlgorithmRSAAES EncryptionAlgorithm = "RSA-OAEP+AES-GCM"
	AlgorithmRSA    EncryptionAlgorithm = "RSA-OAEP"
	AlgorithmAES    EncryptionAlgorithm = "AES-GCM"
)

// encodedCiphertextMetadata represents the metadata of an EncodedCiphertext.
// Has the form of <name>=<value>,<name>=<value>.
// E.g. nonce=abcd,length=1024
type encodedCiphertextMetadata string

// newEncodedCiphertext creates a new EncodedCiphertext from an EncryptionAlgorithm and a []byte with a key.
func newEncodedCiphertext(algorithm EncryptionAlgorithm, keyData []byte, metadataList map[string]string) encodedCiphertext {
	encodedKey := base64.StdEncoding.EncodeToString(keyData)

	metadata := newEncodedCiphertextMetadata(metadataList)

	return encodedCiphertext(fmt.Sprintf("%s$%s$%s", algorithm, encodedKey, metadata))
}

// Validate verifies the EncodedCiphertext has a valid format.
func (ec encodedCiphertext) Validate() error {
	if !encodedCiphertextPattern.MatchString(string(ec)) {
		return ErrInvalidCiphertext
	}

	return nil
}

// parseRegex finds all matches of the encryptedKeyPattern regex on the EncodedCiphertext.
func (ec encodedCiphertext) parseRegex() ([]string, error) {
	matches := encodedCiphertextPattern.FindStringSubmatch(string(ec))
	if len(matches) < 4 {
		return nil, ErrInvalidCiphertext
	}
	return matches, nil
}

// GetAlgorithm returns the algorithm part of the EncodedCiphertext.
func (ec encodedCiphertext) GetAlgorithm() (EncryptionAlgorithm, error) {
	matches, err := ec.parseRegex()
	if err != nil {
		return "", errio.Error(err)
	}
	return EncryptionAlgorithm(matches[1]), nil
}

// GetData returns the encrypted data part of the EncodedCiphertext.
func (ec encodedCiphertext) GetData() ([]byte, error) {
	matches, err := ec.parseRegex()
	if err != nil {
		return nil, errio.Error(err)
	}
	return base64.StdEncoding.DecodeString(matches[2])
}

// GetMetadata returns the metadata part of the EncodedCiphertext.
func (ec encodedCiphertext) GetMetadata() (encodedCiphertextMetadata, error) {
	matches, err := ec.parseRegex()
	if err != nil {
		return "", errio.Error(err)
	}
	return encodedCiphertextMetadata(matches[3]), nil
}

// newEncodedCiphertextMetadata creates a new encodedCiphertextMetadata from a map of metadata.
// Input of {"param": "foo", "second": "bar"} outputs "param=foo,second=bar".
func newEncodedCiphertextMetadata(metadataList map[string]string) encodedCiphertextMetadata {
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

	return encodedCiphertextMetadata(metadata)
}

// GetValue returns a value from metadata.
// E.g. when the metadata is "first=foo,second=bar", then GetValue("second") => "bar".
func (m encodedCiphertextMetadata) GetValue(name string) (string, error) {
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
func (m encodedCiphertextMetadata) GetDecodedValue(name string) ([]byte, error) {
	dataStr, err := m.GetValue(name)
	if err != nil {
		return nil, ErrInvalidMetadata
	}

	return base64.StdEncoding.DecodeString(dataStr)
}

func (ec EncodedCiphertextRSA) decode() (*ciphertextRSA, error) {
	algorithm, err := encodedCiphertext(ec).GetAlgorithm()
	if err != nil {
		return nil, errio.Error(err)
	}

	if algorithm != AlgorithmRSA {
		return nil, ErrWrongAlgorithm
	}

	encryptedData, err := encodedCiphertext(ec).GetData()
	if err != nil {
		return nil, errio.Error(err)
	}

	return &ciphertextRSA{
		Data: encryptedData,
	}, nil
}

func (ec EncodedCiphertextRSAAES) decode() (*ciphertextRSAAES, error) {
	algorithm, err := encodedCiphertext(ec).GetAlgorithm()
	if err != nil {
		return nil, errio.Error(err)
	}

	if algorithm != AlgorithmRSA {
		return nil, ErrWrongAlgorithm
	}

	encryptedData, err := encodedCiphertext(ec).GetData()
	if err != nil {
		return nil, errio.Error(err)
	}

	metadata, err := encodedCiphertext(ec).GetMetadata()
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
	algorithm, err := encodedCiphertext(ec).GetAlgorithm()
	if err != nil {
		return nil, errio.Error(err)
	}

	if algorithm != AlgorithmAES {
		return nil, ErrWrongAlgorithm
	}

	encryptedData, err := encodedCiphertext(ec).GetData()
	if err != nil {
		return nil, errio.Error(err)
	}

	metadata, err := encodedCiphertext(ec).GetMetadata()
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
	err := encodedCiphertext(ec).Validate()
	if err != nil {
		return err
	}

	algorithm, err := encodedCiphertext(ec).GetAlgorithm()
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
	err := encodedCiphertext(ec).Validate()
	if err != nil {
		return err
	}

	algorithm, err := encodedCiphertext(ec).GetAlgorithm()
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
	err := encodedCiphertext(ec).Validate()
	if err != nil {
		return err
	}

	algorithm, err := encodedCiphertext(ec).GetAlgorithm()
	if err != nil {
		return err
	}

	if algorithm != AlgorithmRSAAES {
		return ErrWrongAlgorithm
	}

	return nil
}
