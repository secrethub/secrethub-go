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

// encryptionAlgorithm represents the algorithm an EncodedCiphertext is encrypted with.
type encryptionAlgorithm string

// encryptionAlgorithm definitions
const (
	algorithmRSAAES encryptionAlgorithm = "RSA-OAEP+AES-GCM"
	algorithmRSA    encryptionAlgorithm = "RSA-OAEP"
	algorithmAES    encryptionAlgorithm = "AES-GCM"
)

// encodedCiphertextMetadata represents the metadata of an EncodedCiphertext.
// Has the form of <name>=<value>,<name>=<value>.
// E.g. nonce=abcd,length=1024
type encodedCiphertextMetadata string

// validate verifies the EncodedCiphertext has a valid format.
func (ec encodedCiphertext) validate() error {
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

// algorithm returns the algorithm part of the EncodedCiphertext.
func (ec encodedCiphertext) algorithm() (encryptionAlgorithm, error) {
	matches, err := ec.parseRegex()
	if err != nil {
		return "", errio.Error(err)
	}
	return encryptionAlgorithm(matches[1]), nil
}

// data returns the encrypted data part of the EncodedCiphertext.
func (ec encodedCiphertext) data() ([]byte, error) {
	matches, err := ec.parseRegex()
	if err != nil {
		return nil, errio.Error(err)
	}
	return base64.StdEncoding.DecodeString(matches[2])
}

// metadata returns the metadata part of the EncodedCiphertext.
func (ec encodedCiphertext) metadata() (encodedCiphertextMetadata, error) {
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

// getValue returns a value from metadata.
// E.g. when the metadata is "first=foo,second=bar", then getValue("second") => "bar".
func (m encodedCiphertextMetadata) getValue(name string) (string, error) {
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

// getDecodedValue gets the value as if getValue and also decodes it from base64.
func (m encodedCiphertextMetadata) getDecodedValue(name string) ([]byte, error) {
	dataStr, err := m.getValue(name)
	if err != nil {
		return nil, ErrInvalidMetadata
	}

	return base64.StdEncoding.DecodeString(dataStr)
}
