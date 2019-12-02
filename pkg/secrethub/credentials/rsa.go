package credentials

import (
	"net/http"

	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/internals/errio"
	httpclient "github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

// RSACredential implements a Credential for an RSA key.
type RSACredential struct {
	crypto.RSAPrivateKey
}

// GenerateRSACredential generates a new credential that has uses RSA key with keyLength bits for
// encryption and authentication.
func GenerateRSACredential(keyLength int) (*RSACredential, error) {
	key, err := crypto.GenerateRSAPrivateKey(keyLength)
	if err != nil {
		return nil, errio.Error(err)
	}

	return &RSACredential{
		RSAPrivateKey: key,
	}, nil
}

// Fingerprint returns the key identifier by which the server can identify the credential.
func (c RSACredential) Export() ([]byte, string, error) {
	verifier, err := c.RSAPrivateKey.Public().Encode()
	if err != nil {
		return nil, "", err
	}
	fingerprint := api.GetFingerprint(c.Type(), verifier)
	return verifier, fingerprint, nil
}

// ID returns a string by which the credential can be identified.
func (c RSACredential) ID() (string, error) {
	_, fingerprint, err := c.Export()
	return fingerprint, err
}

// Sign provides proof the given bytes are processed by the owner of the credential.
func (c RSACredential) Sign(data []byte) ([]byte, error) {
	return c.RSAPrivateKey.Sign(data)
}

// SignMethod returns a string by which the signing method can be identified.
func (c RSACredential) SignMethod() string {
	return "PKCS1v15"
}

// Decoder returns the Decoder for the rsa private key.
func (c RSACredential) Decoder() Decoder {
	return rsaPrivateKeyDecoder{}
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
	return api.CredentialTypeKey
}

// AddProof add the proof for possession of this credential to a CreateCredentialRequest .
func (c RSACredential) AddProof(_ *api.CreateCredentialRequest) error {
	// Currently not implemented for RSA credentials
	return nil
}

// Authenticate implements the auth.Authenticator interface.
func (c RSACredential) Authenticate(r *http.Request) error {
	return auth.NewHTTPSigner(c).Authenticate(r)
}

// Provide implements the credentials.Provider interface.
func (c RSACredential) Provide(_ *httpclient.Client) (auth.Authenticator, Decrypter, error) {
	return c, c, nil
}
