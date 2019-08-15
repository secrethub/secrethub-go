package credentials

import (
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
	ErrInvalidKey                        = errCredentials.Code("invalid_key").Error("the given key is not valid for the encryption algorithm")
)

var (
	// DefaultCredentialParser defines the default parser for credentials.
	DefaultCredentialParser = NewCredentialParser(DefaultCredentialDecoders)
	// DefaultCredentialDecoders defines the default list of supported decoders.
	DefaultCredentialDecoders = []CredentialDecoder{RSAPrivateKeyDecoder{}}
	// DefaultCredentialEncoding defines the default encoding used for encoding credential segments.
	DefaultCredentialEncoding = base64.URLEncoding.WithPadding(base64.NoPadding)
)

// Credential used to be an interface that contained functions to encrypt, decrypt and authenticate.
// We'll migrate away from using it and use smaller interfaces instead.
// See Verifier, Decrypter and Encrypter for the smaller interfaces.
type EncodableCredential interface {
	// Export exports the credential in a format that can be decoded by its Decoder.
	Export() []byte
	// Decoder returns a decoder that can decode an exported key back into a Credential.
	Decoder() CredentialDecoder
}

// NewCredential is a shorthand function to decode a credential string and optionally
// decrypt it with a passphrase. When an encrypted credential is given, the passphrase
// cannot be empty.
//
// Note that when you want to customize the process of parsing and decoding/decrypting
// a credential (e.g. to prompt only for a passphrase when the credential is encrypted),
// it is recommended you use a CredentialParser instead (e.g. DefaultCredentialParser).
func UnpackRSACredential(credential string, passphrase string) (*RSACredential, error) {
	encoded, err := DefaultCredentialParser.Parse(credential)
	if err != nil {
		return nil, errio.Error(err)
	}

	if encoded.IsEncrypted() {
		if passphrase == "" {
			return nil, ErrEmptyCredentialPassphrase
		}

		key, err := NewPassBasedKey([]byte(passphrase))
		if err != nil {
			return nil, err
		}

		credential, err := encoded.DecodeEncrypted(key)
		if crypto.IsWrongKey(err) {
			return nil, ErrCannotDecryptCredential
		}
		return credential, err
	}

	return encoded.Decode()
}

// EncodedCredential is an intermediary format for encoding and decoding credentials.
type EncodedCredential struct {
	// Raw is the raw credential string.
	// Populated when you Parse a credential.
	Raw string
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
	Decoder CredentialDecoder
}

// Decode decodes an unencrypted credential string into a Credential.
func (c EncodedCredential) Decode() (*RSACredential, error) {
	if c.IsEncrypted() {
		return nil, ErrCannotDecodeEncryptedCredential
	}

	return c.Decoder.Decode(c.Payload)
}

// DecodeEncrypted decodes and decrypts an encrypted credential string
// using the given key.
func (c EncodedCredential) DecodeEncrypted(key PassBasedKey) (*RSACredential, error) {
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
func (c EncodedCredential) IsEncrypted() bool {
	return c.EncryptionAlgorithm != ""
}

// EncodeCredential encodes a Credential as a one line string that can be transferred.
func EncodeCredential(credential EncodableCredential) (string, error) {
	cred := newEncodedCredential(credential)

	return encodeCredentialPartsToString(cred.Header, cred.Payload)
}

// EncodeEncryptedCredential encrypts and encodes a Credential as a one line string token that can be transferred.
func EncodeEncryptedCredential(credential EncodableCredential, key PassBasedKey) (string, error) {
	cred := newEncodedCredential(credential)

	// Set the `enc` header so it can be used to decrypt later.
	cred.Header["enc"] = key.Name()

	payload, additionalheaders, err := key.Encrypt(cred.Payload)
	if err != nil {
		return "", errio.Error(err)
	}

	for key, value := range additionalheaders {
		cred.Header[key] = value
	}

	return encodeCredentialPartsToString(cred.Header, payload)
}

// newEncodedCredential creates exports and encodes a credential in the payload.
func newEncodedCredential(credential EncodableCredential) *EncodedCredential {
	decoder := credential.Decoder()

	return &EncodedCredential{
		Header: map[string]interface{}{
			"type": decoder.Name(),
		},
		Payload: credential.Export(),
		Decoder: decoder,
	}
}

// encodeCredentialPartsToString encodes an header and payload in a format string: header.payload
func encodeCredentialPartsToString(header map[string]interface{}, payload []byte) (string, error) {
	if len(header) == 0 {
		return "", ErrEmptyCredentialHeader
	}

	parts := make([]string, 2)
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", ErrInvalidCredential.Errorf("cannot encode header as json: %s", err)
	}

	parts[0] = DefaultCredentialEncoding.EncodeToString(headerBytes)
	parts[1] = DefaultCredentialEncoding.EncodeToString(payload)
	return strings.Join(parts, "."), nil
}

// Parser parses a credential string with support
// for different credential decoders.
type Parser struct {
	SupportedDecoders map[string]CredentialDecoder
}

// NewCredentialParser returns a new credential parser
func NewCredentialParser(decoders []CredentialDecoder) Parser {
	supportedDecoders := map[string]CredentialDecoder{}
	for _, decoder := range decoders {
		supportedDecoders[decoder.Name()] = decoder
	}

	return Parser{
		SupportedDecoders: supportedDecoders,
	}
}

// Parse parses a credential string.
func (p Parser) Parse(raw string) (*EncodedCredential, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return nil, ErrInvalidNumberOfCredentialSegments(len(parts))
	}

	cred := &EncodedCredential{
		Raw:    raw,
		Header: make(map[string]interface{}),
	}

	// Decode the header
	var err error
	cred.RawHeader, err = DefaultCredentialEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrCannotDecodeCredentialHeader(err)
	}

	err = json.Unmarshal(cred.RawHeader, &cred.Header)
	if err != nil {
		return nil, ErrCannotDecodeCredentialHeader(fmt.Sprintf("cannot unmarshal json: %v", err))
	}

	payloadType, ok := cred.Header["type"].(string)
	if !ok {
		return nil, ErrInvalidCredentialHeaderField("type")
	}

	// Decode the payload
	cred.Decoder, ok = p.SupportedDecoders[payloadType]
	if !ok {
		return nil, ErrUnsupportedCredentialType(payloadType)
	}

	cred.Payload, err = DefaultCredentialEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrCannotDecodeCredentialPayload(err)
	}

	encryptionAlgorithm, ok := cred.Header["enc"].(string)
	if ok {
		cred.EncryptionAlgorithm = encryptionAlgorithm
	}

	return cred, nil
}

// RSAPrivateKeyDecoder implements the CredentialDecoder interface for an RSA private key.
type RSAPrivateKeyDecoder struct{}

// Decode converts a EncodedCredential's payload into an RSA ClientKey.
func (d RSAPrivateKeyDecoder) Decode(payload []byte) (*RSACredential, error) {
	key, err := x509.ParsePKCS1PrivateKey(payload)
	if err != nil {
		return nil, err
	}

	return &RSACredential{
		RSAPrivateKey: crypto.NewRSAPrivateKey(key),
	}, nil
}

// Name returns the encoding name.
func (d RSAPrivateKeyDecoder) Name() string {
	return "rsa"
}

// CredentialDecoder converts a payload into a Credential.
type CredentialDecoder interface {
	// Decode decodes a payload into a Credential.
	Decode(payload []byte) (*RSACredential, error)
	// Name returns the name of the encoding.
	Name() string
}
