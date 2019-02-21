package secrethub

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/keylockerbv/secrethub-go/pkg/api"

	"github.com/keylockerbv/secrethub-go/pkg/auth"
	"github.com/keylockerbv/secrethub-go/pkg/crypto"
	"github.com/keylockerbv/secrethub-go/pkg/errio"
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
	ErrInvalidKey                        = errClient.Code("invalid_key").Error("the given key is not valid for the encryption algorithm")
)

var (
	// DefaultCredentialDecoders defines the default list of supported decoders.
	DefaultCredentialDecoders = []CredentialDecoder{RSAPrivateKeyDecoder{}}
	// DefaultCredentialEncoding defines the default encoding used for encoding credential segments.
	DefaultCredentialEncoding = base64.URLEncoding.WithPadding(base64.NoPadding)
)

// Credential can be used to encrypt and decrypt data and to authenticate http requests.
type Credential interface {
	auth.Credential
	// Fingerprint returns an identifier by which the server can identify the credential, e.g. a username of a fingerprint.
	Fingerprint() (string, error)
	// Verifier returns the data to be stored server side to verify an http request authenticated with this credential.
	Verifier() ([]byte, error)
	// Wrap encrypts data, typically an account key.
	Wrap(plaintext []byte) (crypto.EncodedCiphertextRSAAES, error)
	// Unwrap decrypts data, typically an account key.
	Unwrap(ciphertext crypto.EncodedCiphertextRSAAES) ([]byte, error)
	// Export exports the credential in a format that can be decoded by its Decoder.
	Export() []byte
	// Decoder returns a decoder that can decode an exported key back into a Credential.
	Decoder() CredentialDecoder
	// Type returns what type of credential this is.
	Type() api.CredentialType
}

// NewCredential is a shorthand function to decode a credential string and optionally
// decrypt it with a passphrase. When an encrypted credential is given, the passphrase
// cannot be empty.
func NewCredential(credential string, passphrase string) (Credential, error) {
	parser := NewCredentialParser(DefaultCredentialDecoders)

	encoded, err := parser.Parse(credential)
	if err != nil {
		return nil, errio.Error(err)
	}

	if encoded.IsEncrypted() {
		if passphrase == "" {
			return nil, ErrEmptyCredentialPassphrase
		}

		return encoded.DecodeArmored(NewPassphraseUnarmorer([]byte(passphrase)))
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
	// Armor contains the name of the armoring algorithm if the payload is encrypted.
	Armor string
	// Decoder is used to decode the payload into a Credential.
	// Populated when you Parse a credential string.
	Decoder CredentialDecoder
}

// Decode decodes an unarmored credential string into a Credential.
func (c EncodedCredential) Decode() (Credential, error) {
	if c.IsEncrypted() {
		return nil, ErrCannotDecodeEncryptedCredential
	}

	return c.Decoder.Decode(c.Payload)
}

// DecodeArmored decodes an armored credential string into a Credential
// using the given Unarmorer.
func (c EncodedCredential) DecodeArmored(unarmorer Unarmorer) (Credential, error) {
	if unarmorer.Name() != c.Armor {
		return nil, ErrInvalidKey
	}

	payload, err := unarmorer.Unarmor(c.Payload, c.RawHeader)
	if err != nil {
		return nil, errio.Error(err)
	}

	return c.Decoder.Decode(payload)
}

// IsEncrypted returns true when the credential is encrypted.
func (c EncodedCredential) IsEncrypted() bool {
	return c.Armor != ""
}

// EncodeCredential encodes a Credential as a one line string that can be transferred.
func EncodeCredential(credential Credential) (string, error) {
	cred := newEncodedCredential(credential)

	return encodeCredentialPartsToString(cred.Header, cred.Payload)
}

// EncodeArmoredCredential armors and encodes a Credential as a one line string token that can be transferred.
func EncodeArmoredCredential(credential Credential, armorer Armorer) (string, error) {
	cred := newEncodedCredential(credential)

	// Set the `enc` header so it can be used to decrypt later.
	cred.Header["enc"] = armorer.Name()

	payload, additionalheaders, err := armorer.Armor(cred.Payload)
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

	armor, ok := cred.Header["enc"].(string)
	if ok {
		cred.Armor = armor
	}

	return cred, nil
}

// RSACredential implements a Credential for an RSA key.
type RSACredential struct {
	*crypto.RSAKey
}

// GenerateCredential generates a new credential to be used to
// authenticate the account and to decrypt the account key.
func GenerateCredential() (Credential, error) {
	return generateRSACredential(crypto.ExternalKeyLength)
}

func generateRSACredential(keyLength int) (RSACredential, error) {
	key, err := crypto.GenerateRSAKey(keyLength)
	if err != nil {
		return RSACredential{}, errio.Error(err)
	}

	return RSACredential{
		RSAKey: key,
	}, nil
}

// AddAuthentication adds authentication to an http request.
func (c RSACredential) AddAuthentication(r *http.Request) error {
	return auth.NewCredentialSignature(c.RSAKey).AddAuthentication(r)
}

// Fingerprint returns the key identifier by which the server can identify the credential.
func (c RSACredential) Fingerprint() (string, error) {
	return c.RSAKey.Fingerprint()
}

// Verifier returns the public key to be stored server side to verify an http request authenticated with this credential.
func (c RSACredential) Verifier() ([]byte, error) {
	return c.RSAKey.ExportPublicKey()
}

// Decoder returns the decoder for the rsa private key.
func (c RSACredential) Decoder() CredentialDecoder {
	return RSAPrivateKeyDecoder{}
}

// Wrap encrypts data, typically an account key.
func (c RSACredential) Wrap(plaintext []byte) (crypto.EncodedCiphertextRSAAES, error) {
	return crypto.EncryptRSAAES(plaintext, c.RSAKey.RSAPublicKey)
}

// Unwrap decrypts data, typically an account key.
func (c RSACredential) Unwrap(encodedCiphertext crypto.EncodedCiphertextRSAAES) ([]byte, error) {
	ciphertext, err := encodedCiphertext.Decode()
	if err != nil {
		return nil, err
	}

	return ciphertext.Decrypt(c.RSAKey)
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
		RSAKey: crypto.NewRSAKey(key),
	}, nil
}

// Name returns the encoding name.
func (d RSAPrivateKeyDecoder) Name() string {
	return "rsa"
}

// Armorer can armor a Credential into token values.
type Armorer interface {
	// Name returns the name of the algorithm.
	Name() string
	// Armor encrypts a payload with and returns a header.
	Armor(payload []byte) ([]byte, map[string]interface{}, error)
}

// Unarmorer can unarmor token values into a Credential.
type Unarmorer interface {
	// Name returns the name of the algorithm.
	Name() string
	// Unarmor decrypts a payload with the key and accepts the raw JSON header to read values from.
	Unarmor(payload []byte, header []byte) ([]byte, error)
}

// armoredCredentialHeader is a helper type to help encoding
// and decoding header values for the Scrypt armoring.
type armoredCredentialHeader struct {
	KeyLen int    `json:"klen"`
	Salt   []byte `json:"salt"`
	N      int    `json:"n"`
	R      int    `json:"r"`
	P      int    `json:"p"`
	Nonce  []byte `json:"nonce"`
}

// passphraseArmorer wraps an scrypt derived key and implements
// the Armorer interface.
type passphraseArmorer struct {
	key *crypto.ScryptKey
}

// NewPassphraseArmorer generates a new armorer from a passphrase.
func NewPassphraseArmorer(passphrase []byte) (Armorer, error) {
	key, err := crypto.GenerateScryptKey(passphrase)
	if err != nil {
		return nil, errio.Error(err)
	}

	return passphraseArmorer{
		key: key,
	}, nil
}

// Armor implements the Armorer interface and encrypts a payload,
// returning the encrypted payload and header values.
func (p passphraseArmorer) Armor(payload []byte) ([]byte, map[string]interface{}, error) {
	ciphertextAES, err := p.key.Encrypt(payload, crypto.SaltOperationLocalCredentialEncryption)
	if err != nil {
		return nil, nil, errio.Error(err)
	}

	header := armoredCredentialHeader{
		KeyLen: p.key.KeyLen,
		Salt:   p.key.Salt,
		N:      p.key.N,
		R:      p.key.R,
		P:      p.key.P,
		Nonce:  ciphertextAES.Nonce,
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

	return ciphertextAES.Data, headerMap, nil
}

// Name implements the Armorer interface.
func (p passphraseArmorer) Name() string {
	return "scrypt"
}

// passphraseUnarmorer implements the Unarmorer interface for the scrypt algorithm.
type passphraseUnarmorer []byte

// NewPassphraseUnarmorer returns an unarmorer for the given passphrase.
func NewPassphraseUnarmorer(passphrase []byte) Unarmorer {
	return passphraseUnarmorer(passphrase)
}

// Unarmor decrypts an encrypted payload and reads values from the header when necessary.
func (p passphraseUnarmorer) Unarmor(payload []byte, rawHeader []byte) ([]byte, error) {
	header := armoredCredentialHeader{}
	err := json.Unmarshal(rawHeader, &header)
	if err != nil {
		return nil, errio.Error(err)
	}

	key, err := crypto.DeriveScryptKey(p, header.Salt, header.N, header.R, header.P, header.KeyLen)
	if err != nil {
		return nil, errio.Error(err)
	}

	return key.Decrypt(payload, header.Nonce, crypto.SaltOperationLocalCredentialEncryption)
}

// Name returns the unarmoring algorithm.
func (p passphraseUnarmorer) Name() string {
	return "scrypt"
}
