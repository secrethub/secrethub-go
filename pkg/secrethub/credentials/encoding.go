package credentials

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/internals/errio"
)

// Errors
var (
	errCredentials                       = errio.Namespace("credentials")
	ErrInvalidCredential                 = errCredentials.Code("invalid_credential")
	ErrInvalidNumberOfCredentialSegments = errCredentials.Code("invalid_number_of_credential_segments").ErrorPref("credential contains an invalid number of segments: %d")
	ErrEmptyCredentialHeader             = errCredentials.Code("invalid_empty_credential_header").Error("credential header cannot be empty")
	ErrEmptyCredentialPassphrase         = errCredentials.Code("invalid_empty_credential_passphrase").Error("credential passphrase cannot be empty for encrypted credentials")
	ErrInvalidCredentialHeaderField      = errCredentials.Code("invalid_credential_header_field").ErrorPref("invalid header field: %s")
	ErrCannotDecodeCredentialHeader      = errCredentials.Code("invalid_credential_header").ErrorPref("cannot decode credential header: %v")
	ErrUnsupportedCredentialType         = errCredentials.Code("unsupported_credential_type").ErrorPref("unsupported credential type: %s")
	ErrCannotDecodeCredentialPayload     = errCredentials.Code("invalid_credential_header").ErrorPref("cannot decode credential payload: %v")
	ErrCannotDecodeEncryptedCredential   = errCredentials.Code("cannot_decode_encrypted_credential").Error("cannot decode an encrypted credential without a key")
	ErrCannotDecryptCredential           = errCredentials.Code("cannot_decrypt_credential").Error("passphrase is incorrect")
	ErrNeedPassphrase                    = errCredentials.Code("credential_passphrase_required").Error("credential is password-protected")
	ErrMalformedCredential               = errCredentials.Code("malformed_credential").ErrorPref("credential is malformed: %v")
	ErrInvalidKey                        = errCredentials.Code("invalid_key").Error("the given key is not valid for the encryption algorithm")
)

var (
	// DefaultDecoders defines the default list of supported decoders.
	DefaultDecoders = []Decoder{rsaPrivateKeyDecoder{}}
	// defaultParser defines the default parser for credentials.
	defaultParser = newParser(DefaultDecoders)
	// defaultEncoding defines the default encoding used for encoding credential segments.
	defaultEncoding = base64.URLEncoding.WithPadding(base64.NoPadding)
)

// EncodableCredential used to be an interface that contained functions to encrypt, decrypt and authenticate.
// We'll migrate away from using it and use smaller interfaces instead.
// See Verifier, Decrypter and Encrypter for the smaller interfaces.
type EncodableCredential interface {
	// Encode the credential to a format that can be decoded by its Decoder.
	Encode() []byte
	// Decoder returns a Decoder that can decode an exported key back into a Credential.
	Decoder() Decoder
}

// encodedCredential is an intermediary format for encoding and decoding credentials.
type encodedCredential struct {
	// Raw is the raw credential string.
	// Populated when you Parse a credential.
	Raw []byte
	// Header is the decoded first part of the credential string.
	Header map[string]interface{}
	// RawHeader is the first part of the credential string, encoded as json.
	RawHeader []byte
	// Payload is the second part of the credential string.
	Payload []byte
	// EncryptionAlgorithm contains the name of the encryption algorithm if the payload is encrypted.
	EncryptionAlgorithm string
	// Decoder is used to decode the payload into a Credential.
	// Populated when you Parse a credential string.
	Decoder Decoder
}

// Decode decodes an unencrypted credential string into a Credential.
func (c encodedCredential) Decode() (*RSACredential, error) {
	if c.IsEncrypted() {
		return nil, ErrCannotDecodeEncryptedCredential
	}

	return c.Decoder.Decode(c.Payload)
}

// DecodeEncrypted decodes and decrypts an encrypted credential string
// using the given key.
func (c encodedCredential) DecodeEncrypted(key PassBasedKey) (*RSACredential, error) {
	if key.Name() != c.EncryptionAlgorithm {
		return nil, ErrInvalidKey
	}

	payload, err := key.Decrypt(c.Payload, c.RawHeader)
	if err != nil {
		return nil, errio.Error(err)
	}

	return c.Decoder.Decode(payload)
}

// IsEncrypted returns true when the credential is encrypted.
func (c encodedCredential) IsEncrypted() bool {
	return c.EncryptionAlgorithm != ""
}

// EncodeCredential encodes a Credential as a one line string that can be transferred.
func EncodeCredential(credential EncodableCredential) ([]byte, error) {
	cred := newEncodedCredential(credential)

	return encodeCredentialParts(cred.Header, cred.Payload)
}

// EncodeEncryptedCredential encrypts and encodes a Credential as a one line string token that can be transferred.
func EncodeEncryptedCredential(credential EncodableCredential, key PassBasedKey) ([]byte, error) {
	cred := newEncodedCredential(credential)

	// Set the `enc` header so it can be used to decrypt later.
	cred.Header["enc"] = key.Name()

	payload, additionalheaders, err := key.Encrypt(cred.Payload)
	if err != nil {
		return nil, errio.Error(err)
	}

	for key, value := range additionalheaders {
		cred.Header[key] = value
	}

	return encodeCredentialParts(cred.Header, payload)
}

// newEncodedCredential creates exports and encodes a credential in the payload.
func newEncodedCredential(credential EncodableCredential) *encodedCredential {
	decoder := credential.Decoder()

	return &encodedCredential{
		Header: map[string]interface{}{
			"type": decoder.Name(),
		},
		Payload: credential.Encode(),
		Decoder: decoder,
	}
}

// encodeCredentialParts encodes an header and payload in `header.payload` format.
func encodeCredentialParts(header map[string]interface{}, payload []byte) ([]byte, error) {
	if len(header) == 0 {
		return nil, ErrEmptyCredentialHeader
	}

	parts := make([]string, 2)
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return nil, ErrInvalidCredential.Errorf("cannot encode header as json: %s", err)
	}

	parts[0] = defaultEncoding.EncodeToString(headerBytes)
	parts[1] = defaultEncoding.EncodeToString(payload)
	return []byte(strings.Join(parts, ".")), nil
}

// parser parses a credential string with support
// for different credential decoders.
type parser struct {
	supportedDecoders map[string]Decoder
}

// newParser returns a new credential parser
func newParser(decoders []Decoder) parser {
	supportedDecoders := map[string]Decoder{}
	for _, decoder := range decoders {
		supportedDecoders[decoder.Name()] = decoder
	}

	return parser{
		supportedDecoders: supportedDecoders,
	}
}

// parse parses a credential string.
func (p parser) parse(raw []byte) (*encodedCredential, error) {
	parts := bytes.Split(raw, []byte("."))
	if len(parts) != 2 {
		return nil, ErrInvalidNumberOfCredentialSegments(len(parts))
	}

	cred := &encodedCredential{
		Raw:       raw,
		Header:    make(map[string]interface{}),
		RawHeader: make([]byte, defaultEncoding.DecodedLen(len(parts[0]))),
		Payload:   make([]byte, defaultEncoding.DecodedLen(len(parts[1]))),
	}

	// Decode the header
	n, err := defaultEncoding.Decode(cred.RawHeader, parts[0])
	if err != nil {
		return nil, ErrCannotDecodeCredentialHeader(err)
	}
	cred.RawHeader = cred.RawHeader[:n]

	err = json.Unmarshal(cred.RawHeader, &cred.Header)
	if err != nil {
		return nil, ErrCannotDecodeCredentialHeader(fmt.Sprintf("cannot unmarshal json: %v", err))
	}

	payloadType, ok := cred.Header["type"].(string)
	if !ok {
		return nil, ErrInvalidCredentialHeaderField("type")
	}

	// Decode the payload
	cred.Decoder, ok = p.supportedDecoders[payloadType]
	if !ok {
		return nil, ErrUnsupportedCredentialType(payloadType)
	}

	n, err = defaultEncoding.Decode(cred.Payload, parts[1])
	if err != nil {
		return nil, ErrCannotDecodeCredentialPayload(err)
	}
	cred.Payload = cred.Payload[:n]

	encryptionAlgorithm, ok := cred.Header["enc"].(string)
	if ok {
		cred.EncryptionAlgorithm = encryptionAlgorithm
	}

	return cred, nil
}

// rsaPrivateKeyDecoder implements the Decoder interface for an RSA private key.
type rsaPrivateKeyDecoder struct{}

// Decode converts a encodedCredential's payload into an RSA ClientKey.
func (d rsaPrivateKeyDecoder) Decode(payload []byte) (*RSACredential, error) {
	key, err := x509.ParsePKCS1PrivateKey(payload)
	if err != nil {
		return nil, ErrMalformedCredential(err)
	}

	return &RSACredential{
		RSAPrivateKey: crypto.NewRSAPrivateKey(key),
	}, nil
}

// Name returns the encoding name.
func (d rsaPrivateKeyDecoder) Name() string {
	return "rsa"
}

// Decoder converts a payload into a Credential.
type Decoder interface {
	// Decode decodes a payload into a Credential.
	Decode(payload []byte) (*RSACredential, error)
	// Name returns the name of the encoding.
	Name() string
}
