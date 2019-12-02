package credentials

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

var (
	bootstrapCodeRegexp = regexp.MustCompile("[^a-zA-Z0-9]+")
)

// Enforce implementation of interfaces by structs.
var _ Creator = (*BackupCodeCreator)(nil)
var _ Provider = (*bootstrapCodeProvider)(nil)
var _ auth.Signer = (*bootstrapCode)(nil)

// BackupCodeCreator creates a new credential based on a backup code.
type BackupCodeCreator struct {
	bootstrapCode *bootstrapCode
}

// CreateBackupCode returns a Creator that creates a backup code credential.
func CreateBackupCode() *BackupCodeCreator {
	return &BackupCodeCreator{}
}

// ParseBootstrapCode parses a string and checks whether it is a valid bootstrap code.
// If it is valid, the bytes of the code are returned.
func ParseBootstrapCode(code string) ([]byte, error) {
	code = filterBootstrapCode(code)
	decoded, err := hex.DecodeString(code)
	if err != nil {
		return nil, errors.New("illegal characters in code")
	}
	if len(decoded) != crypto.SymmetricKeyLength {
		return nil, errors.New("wrong length")
	}
	return decoded, nil
}

// Create generates a new code and stores it in the BackupCodeCreator.
func (b *BackupCodeCreator) Create() error {
	key, err := crypto.GenerateSymmetricKey()
	if err != nil {
		return err
	}
	b.bootstrapCode = newBootstrapCode(key.Export(), api.CredentialTypeBackupCode)
	return nil
}

// Code returns the string representation of the backup code.
// Can only be called after the credential has been created.
func (b *BackupCodeCreator) Code() (string, error) {
	if b.bootstrapCode == nil {
		return "", errors.New("backup code has not yet been generated")
	}
	code := strings.ToUpper(hex.EncodeToString(b.bootstrapCode.encryptionKey.Export()))
	delimitedCode := strings.Join(splitStringByWidth(code, 8), "-")
	return delimitedCode, nil
}

// Verifier returns a Verifier that can be used for creating a new credential from this backup code.
func (b *BackupCodeCreator) Verifier() Verifier {
	return b.bootstrapCode
}

// Encrypter returns a Encrypter that can be used to encrypt data with this backup code.
func (b *BackupCodeCreator) Encrypter() Encrypter {
	return b.bootstrapCode
}

// Metadata returns the metadata for a backup code.
func (b *BackupCodeCreator) Metadata() map[string]string {
	return nil
}

// bootstrapCodeProvider is a Provider that can be used to authenticate and decrypt with a bootstrap code.
type bootstrapCodeProvider struct {
	code string
	t    api.CredentialType
}

// UseBackupCode returns a Provider for authentication and decryption with the given backup code.
func UseBackupCode(code string) Provider {
	return &bootstrapCodeProvider{
		code: code,
		t:    api.CredentialTypeBackupCode,
	}
}

// Provide returns the auth.Authenticator and Decrypter corresponding to a bootstrap code.
func (b *bootstrapCodeProvider) Provide(_ *http.Client) (auth.Authenticator, Decrypter, error) {
	bytes, err := ParseBootstrapCode(b.code)
	if err != nil {
		return nil, nil, fmt.Errorf("malformed code: %w", err)
	}
	bootstrapCode := newBootstrapCode(bytes, b.t)
	return auth.NewHTTPSigner(bootstrapCode), bootstrapCode, nil
}

// bootstrapCode is a type that represents both backup and enroll codes.
type bootstrapCode struct {
	t             api.CredentialType
	encryptionKey *crypto.SymmetricKey
	signKey       *crypto.SymmetricKey
}

// newBootstrapCode returns a new bootstrapCode for the given AES key and credential type.
func newBootstrapCode(key []byte, t api.CredentialType) *bootstrapCode {
	encryptionKey := crypto.NewSymmetricKey(key)
	signKey := crypto.NewSymmetricKey(crypto.SHA256(key))
	return &bootstrapCode{
		t:             t,
		encryptionKey: encryptionKey,
		signKey:       signKey,
	}
}

func (b *bootstrapCode) Export() ([]byte, string, error) {
	verifierBytes := []byte(base64.StdEncoding.EncodeToString(b.signKey.Export()))
	fingerprint := api.GetFingerprint(b.t, verifierBytes)
	return verifierBytes, fingerprint, nil
}

func (b *bootstrapCode) Type() api.CredentialType {
	return b.t
}

func (b *bootstrapCode) AddProof(req *api.CreateCredentialRequest) error {
	return nil
}

func (b *bootstrapCode) ID() (string, error) {
	_, fingerprint, err := b.Export()
	if err != nil {
		return "", err
	}
	return fingerprint, nil
}

func (b *bootstrapCode) Sign(in []byte) ([]byte, error) {
	return b.signKey.HMAC(in)
}

func (b *bootstrapCode) SignMethod() string {
	return "BootstrapCode-HMAC"
}

func (b *bootstrapCode) Wrap(plaintext []byte) (*api.EncryptedData, error) {
	enc, err := b.encryptionKey.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	return api.NewEncryptedDataAESGCM(enc.Data, enc.Nonce, len(enc.Nonce)*8, api.NewEncryptionKeyBootstrapCode(256)), nil
}

func (b *bootstrapCode) Unwrap(ciphertext *api.EncryptedData) ([]byte, error) {
	ciphertextAESGCM, err := ciphertext.AESGCM()
	if err != nil {
		return nil, err
	}
	decrypted, err := b.encryptionKey.Decrypt(crypto.CiphertextAES{
		Data:  ciphertextAESGCM.Ciphertext,
		Nonce: ciphertextAESGCM.Metadata.Nonce,
	})
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

func filterBootstrapCode(code string) string {
	return bootstrapCodeRegexp.ReplaceAllString(code, "")
}

func splitStringByWidth(in string, width int) []string {
	var out []string
	tmp := ""
	for i, r := range in {
		tmp += string(r)

		if (i+1)%width == 0 {
			out = append(out, tmp)
			tmp = ""
		}
	}
	return out
}
