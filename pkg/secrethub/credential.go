package secrethub

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/secrethub/secrethub-go/internals/api"

	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/internals/errio"
)

// Errors
var (
	ErrInvalidCredential                 = errClient.Code("invalid_credential")
	ErrInvalidNumberOfCredentialSegments = errClient.Code("invalid_number_of_credential_segments").ErrorPref("credential contains an invalid number of segments: %d")
	ErrEmptyCredentialHeader             = errClient.Code("invalid_empty_credential_header").Error("credential header cannot be empty")
	ErrEmptyCredentialPassphrase         = errClient.Code("invalid_empty_credential_passphrase").Error("credential passphrase cannot be empty for encrypted credentials")
	ErrInvalidCredentialHeaderField      = errClient.Code("invalid_credential_header_field").ErrorPref("invalid header field: %s")
	ErrCannotDecodeCredentialHeader      = errClient.Code("invalid_credential_header").ErrorPref("cannot decode credential header: %v")
	ErrUnsupportedCredentialType         = errClient.Code("unsupported_credential_type").ErrorPref("unsupported credential type: %s")
	ErrCannotDecodeCredentialPayload     = errClient.Code("invalid_credential_header").ErrorPref("cannot decode credential payload: %v")
	ErrCannotDecodeEncryptedCredential   = errClient.Code("cannot_decode_encrypted_credential").Error("cannot decode an encrypted credential without a key")
	ErrCannotDecryptCredential           = errClient.Code("cannot_decrypt_credential").Error("passphrase is incorrect")
	ErrInvalidKey                        = errClient.Code("invalid_key").Error("the given key is not valid for the encryption algorithm")
)

var (
	// DefaultCredentialParser defines the default parser for credentials.
	DefaultCredentialParser = NewCredentialParser(DefaultCredentialDecoders)
	// DefaultCredentialDecoders defines the default list of supported decoders.
	DefaultCredentialDecoders = []CredentialDecoder{RSAPrivateKeyDecoder{}}
	// DefaultCredentialEncoding defines the default encoding used for encoding credential segments.
	DefaultCredentialEncoding = base64.URLEncoding.WithPadding(base64.NoPadding)
)

// Verifier exports verification bytes that can be used to verify signed data is processed by the owner of a signer.
type Verifier interface {
	// Fingerprint returns an identifier by which the server can identify the credential, e.g. a username of a fingerprint.
	Fingerprint() (string, error)
	// Verifier returns the data to be stored server side to verify an http request authenticated with this credential.
	Verifier() ([]byte, error)
	// Type returns what type of credential this is.
	Type() api.CredentialType
}

// Credential used to be an interface that contained functions to encrypt, decrypt and authenticate.
// We'll migrate away from using it and use smaller interfaces instead.
// See Verifier, Decrypter and Encrypter for the smaller interfaces.
type Credential interface {
	Verifier
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
func NewCredential(credential string, passphrase string) (Credential, error) {
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

// CredentialDecoder converts a payload into a Credential.
type CredentialDecoder interface {
	// Decode decodes a payload into a Credential.
	Decode(payload []byte) (Credential, error)
	// Name returns the name of the encoding.
	Name() string
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
func (c EncodedCredential) Decode() (Credential, error) {
	if c.IsEncrypted() {
		return nil, ErrCannotDecodeEncryptedCredential
	}

	return c.Decoder.Decode(c.Payload)
}

// DecodeEncrypted decodes and decrypts an encrypted credential string
// using the given key.
func (c EncodedCredential) DecodeEncrypted(key PassBasedKey) (Credential, error) {
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
func EncodeCredential(credential Credential) (string, error) {
	cred := newEncodedCredential(credential)

	return encodeCredentialPartsToString(cred.Header, cred.Payload)
}

// EncodeEncryptedCredential encrypts and encodes a Credential as a one line string token that can be transferred.
func EncodeEncryptedCredential(credential Credential, key PassBasedKey) (string, error) {
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
func newEncodedCredential(credential Credential) *EncodedCredential {
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

// RSACredential implements a Credential for an RSA key.
type RSACredential struct {
	crypto.RSAPrivateKey
}

// GenerateCredential generates a new credential to be used to
// authenticate the account and to decrypt the account key.
func GenerateCredential() (Credential, error) {
	return generateRSACredential(crypto.RSAKeyLength)
}

func generateRSACredential(keyLength int) (RSACredential, error) {
	key, err := crypto.GenerateRSAPrivateKey(keyLength)
	if err != nil {
		return RSACredential{}, errio.Error(err)
	}

	return RSACredential{
		RSAPrivateKey: key,
	}, nil
}

// Fingerprint returns the key identifier by which the server can identify the credential.
func (c RSACredential) Fingerprint() (string, error) {
	return c.RSAPrivateKey.Public().Fingerprint()
}

// ID returns a string by which the credential can be identified.
func (c RSACredential) ID() (string, error) {
	return c.Fingerprint()
}

// Sign provides proof the given bytes are processed by the owner of the credential.
func (c RSACredential) Sign(data []byte) ([]byte, error) {
	return c.RSAPrivateKey.Sign(data)
}

// SignMethod returns a string by which the signing method can be identified.
func (c RSACredential) SignMethod() string {
	return "PKCS1v15"
}

// Verifier returns the public key to be stored server side to verify an http request authenticated with this credential.
func (c RSACredential) Verifier() ([]byte, error) {
	return c.RSAPrivateKey.Public().Export()
}

// Decoder returns the decoder for the rsa private key.
func (c RSACredential) Decoder() CredentialDecoder {
	return RSAPrivateKeyDecoder{}
}

// Wrap encrypts data, typically an account key.
func (c RSACredential) Wrap(plaintext []byte) (*api.EncryptedData, error) {
	ciphertext, err := c.RSAPrivateKey.Public().Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	key := api.NewEncryptionKeyEncrypted(
		crypto.SymmetricKeyLength*8,
		api.NewEncryptedDataRSAOAEP(
			ciphertext.RSA.Data,
			api.HashingAlgorithmSHA256,
			api.NewEncryptionKeyLocal(crypto.RSAKeyLength),
		),
	)
	return api.NewEncryptedDataAESGCM(
		ciphertext.AES.Data,
		ciphertext.AES.Nonce,
		len(ciphertext.AES.Nonce)*8,
		key,
	), nil
}

// Unwrap decrypts data, typically an account key.
func (c RSACredential) Unwrap(ciphertext *api.EncryptedData) ([]byte, error) {
	if ciphertext.Algorithm != api.EncryptionAlgorithmAESGCM {
		return nil, api.ErrInvalidCiphertext
	}
	key, ok := ciphertext.Key.(*api.EncryptionKeyEncrypted)
	if !ok {
		return nil, api.ErrInvalidCiphertext
	}
	encryptedKey := key.EncryptedKey
	if encryptedKey.Algorithm != api.EncryptionAlgorithmRSAOEAP {
		return nil, api.ErrInvalidCiphertext
	}
	metadata, ok := ciphertext.Metadata.(*api.EncryptionMetadataAESGCM)
	if !ok {
		return nil, api.ErrInvalidCiphertext
	}
	return c.RSAPrivateKey.Decrypt(crypto.CiphertextRSAAES{
		AES: crypto.CiphertextAES{
			Data:  ciphertext.Ciphertext,
			Nonce: metadata.Nonce,
		},
		RSA: crypto.CiphertextRSA{
			Data: encryptedKey.Ciphertext,
		},
	})
}

// Type returns what type of credential this is.
func (c RSACredential) Type() api.CredentialType {
	return api.CredentialTypeRSA
}

// RSAPrivateKeyDecoder implements the CredentialDecoder interface for an RSA private key.
type RSAPrivateKeyDecoder struct{}

// Decode converts a EncodedCredential's payload into an RSA ClientKey.
func (d RSAPrivateKeyDecoder) Decode(payload []byte) (Credential, error) {
	key, err := x509.ParsePKCS1PrivateKey(payload)
	if err != nil {
		return nil, err
	}

	return RSACredential{
		RSAPrivateKey: crypto.NewRSAPrivateKey(key),
	}, nil
}

// Name returns the encoding name.
func (d RSAPrivateKeyDecoder) Name() string {
	return "rsa"
}

// PassBasedKey can encrypt a Credential into token values.
type PassBasedKey interface {
	// Name returns the name of the key derivation algorithm.
	Name() string
	// Encrypt encrypts a given payload with the passphrase derived key and returns encrypted bytes and header with encryption parameter values.
	Encrypt(payload []byte) ([]byte, map[string]interface{}, error)
	// Decrypt decrypts a payload with the key and accepts the raw JSON header to read values from.
	Decrypt(payload []byte, header []byte) ([]byte, error)
}

// passbasedKeyHeader is a helper type to help encoding
// and decoding header values for the Scrypt encryption.
type passbasedKeyHeader struct {
	KeyLen int    `json:"klen"`
	Salt   []byte `json:"salt"`
	N      int    `json:"n"`
	R      int    `json:"r"`
	P      int    `json:"p"`
	Nonce  []byte `json:"nonce"`
}

// passBasedKey wraps an scrypt derived key and implements
// the PassBasedKey interface.
type passBasedKey struct {
	key        *crypto.ScryptKey
	passphrase []byte
}

// NewPassBasedKey generates a new key from a passphrase.
func NewPassBasedKey(passphrase []byte) (PassBasedKey, error) {
	key, err := crypto.GenerateScryptKey(passphrase)
	if err != nil {
		return nil, errio.Error(err)
	}

	return passBasedKey{
		key:        key,
		passphrase: passphrase,
	}, nil
}

// Encrypt implements the PassBasedKey interface and encrypts a payload,
// returning the encrypted payload and header values.
func (p passBasedKey) Encrypt(payload []byte) ([]byte, map[string]interface{}, error) {
	ciphertext, err := p.key.Encrypt(payload, crypto.SaltOperationLocalCredentialEncryption)
	if err != nil {
		return nil, nil, errio.Error(err)
	}

	header := passbasedKeyHeader{
		KeyLen: p.key.KeyLen,
		Salt:   p.key.Salt,
		N:      p.key.N,
		R:      p.key.R,
		P:      p.key.P,
		Nonce:  ciphertext.Nonce,
	}
	raw, err := json.Marshal(header)
	if err != nil {
		return nil, nil, errio.Error(err)
	}

	headerMap := make(map[string]interface{})
	err = json.Unmarshal(raw, &headerMap)
	if err != nil {
		return nil, nil, errio.Error(err)
	}

	return ciphertext.Data, headerMap, nil
}

// Name implements the PassBasedKey interface.
func (p passBasedKey) Name() string {
	return "scrypt"
}

// Decrypt decrypts an encrypted payload and reads values from the header when necessary.
func (p passBasedKey) Decrypt(payload []byte, rawHeader []byte) ([]byte, error) {
	header := passbasedKeyHeader{}
	err := json.Unmarshal(rawHeader, &header)
	if err != nil {
		return nil, errio.Error(err)
	}

	key, err := crypto.DeriveScryptKey(p.passphrase, header.Salt, header.N, header.R, header.P, header.KeyLen)
	if err != nil {
		return nil, errio.Error(err)
	}

	return key.Decrypt(
		crypto.CiphertextAES{
			Data:  payload,
			Nonce: header.Nonce,
		},
		crypto.SaltOperationLocalCredentialEncryption,
	)
}
