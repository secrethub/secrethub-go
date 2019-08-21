package credentials

import (
	"errors"
	"io"
	"io/ioutil"

	awssdk "github.com/aws/aws-sdk-go/aws"

	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/internals/aws"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials/sessions"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
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

type Provider func(*http.Client) (auth.Authenticator, Decrypter, error)

func UseAWS(awsCfg ...*awssdk.Config) Provider {
	return func(httpClient *http.Client) (auth.Authenticator, Decrypter, error) {
		decrypter, err := aws.NewKMSDecrypter(awsCfg...)
		if err != nil {
			return nil, nil, err
		}
		authProvider := sessions.NewSessionRefresher(httpClient, sessions.NewAWSSessionCreator(awsCfg...))
		return authProvider, decrypter, nil
	}
}

// Usage:
//		credentials.UseKey(credentials.FromBytes("<a credential>"))
//		credentials.UseKey(credentials.FromFile("~/.secrethub/credential"), credentials.FromString("passphrase"))
func UseKey(credentialReader io.Reader, passReader io.Reader) Provider {
	return func(_ *http.Client) (auth.Authenticator, Decrypter, error) {
		// This function can be cleaned up a lot. It is mainly for demonstrating the overall idea.
		if credentialReader == nil {
			credentialReader = fromDefault()
		}

		bytes, err := ioutil.ReadAll(credentialReader)
		if err != nil {
			return nil, nil, err
		}
		encoded, err := DefaultParser.parse(string(bytes))
		if err != nil {
			return nil, nil, err
		}
		if encoded.IsEncrypted() {
			if passReader == nil {
				return nil, nil, errors.New("need passphrase")
			}
			passphrase, err := ioutil.ReadAll(passReader)
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
			return auth.NewHTTPSigner(credential), credential, nil
		}
		credential, err := encoded.Decode()
		if err != nil {
			return nil, nil, err
		}

		return auth.NewHTTPSigner(credential), credential, nil
	}
}
