package credentials

import (
	"errors"

	awssdk "github.com/aws/aws-sdk-go/aws"

	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/internals/aws"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials/sessions"
	"github.com/secrethub/secrethub-go/pkg/secrethub/http"
)

// Verifier exports verification bytes that can be used to verify signed data is processed by the owner of a signer.
type Verifier interface {
	// Verifier returns the data to be stored server side to verify an http request authenticated with this credential.
	Verifier() ([]byte, error)
	// Type returns what type of credential this is.
	Type() api.CredentialType
	// AddProof adds the proof of this credential's possession to a CreateCredentialRequest.
	AddProof(req *api.CreateCredentialRequest) error
}

// Decrypter decrypts data, typically an account key.
type Decrypter interface {
	// Unwrap decrypts data, typically an account key.
	Unwrap(ciphertext *api.EncryptedData) ([]byte, error)
}

// Encrypter encrypts data, typically an account key.
type Encrypter interface {
	// Wrap encrypts data, typically an account key.
	Wrap(plaintext []byte) (*api.EncryptedData, error)
}

type staticCredentialAuthProvider struct {
	credential auth.Signer
}

func (s staticCredentialAuthProvider) Provide(_ *http.Client) (auth.Authenticator, error) {
	return auth.NewHTTPSigner(s.credential), nil
}

type Provider func() (http.AuthProvider, Decrypter, error)

func AWS(awsCfg ...*awssdk.Config) Provider {
	return func() (http.AuthProvider, Decrypter, error) {
		decrypter, err := aws.NewKMSDecrypter(awsCfg...)
		if err != nil {
			return nil, nil, err
		}
		authProvider := sessions.NewAuthProvider(sessions.NewAWSSessionCreator(awsCfg...))
		return authProvider, decrypter, nil
	}
}

// Usage:
//		credentials.RSA(credentials.Raw("<a credential>"))
//		credentials.RSA(credentials.File("~/.secrethub/credential"), credentials.Raw("passphrase"))
func RSA(credentialReader BytesReader, passReader ...BytesReader) Provider {
	return func() (http.AuthProvider, Decrypter, error) {
		// This function can be cleaned up a lot. It is mainly for demonstrating the overall idea.

		bytes, err := credentialReader.Data()
		if err != nil {
			return nil, nil, err
		}
		encoded, err := DefaultCredentialParser.Parse(string(bytes))
		if err != nil {
			return nil, nil, err
		}
		if encoded.IsEncrypted() {
			if len(passReader) == 0 || passReader[0] == nil {
				return nil, nil, errors.New("need passphrase")
			}
			passphrase, err := passReader[0].Data()
			if err != nil {
				return nil, nil, err
			}
			key, err := NewPassBasedKey(passphrase)
			if err != nil {
				return nil, nil, err
			}

			credential, err := encoded.DecodeEncrypted(key)
			if crypto.IsWrongKey(err) {
				return nil, nil, ErrCannotDecryptCredential
			} else if err != nil {
				return nil, nil, err
			}
			return staticCredentialAuthProvider{credential: credential}, credential, nil
		}
		credential, err := encoded.Decode()
		if err != nil {
			return nil, nil, err
		}

		return staticCredentialAuthProvider{credential: credential}, credential, nil
	}
}
