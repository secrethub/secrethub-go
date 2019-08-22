package credentials

import (
	"errors"
	"io"
	"io/ioutil"

	awssdk "github.com/aws/aws-sdk-go/aws"

	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/internals/aws"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials/sessions"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

type UsableCredential interface {
	Decrypter
	auth.Authenticator
}

type usableCredential struct {
	Decrypter
	auth.Authenticator
}

// Provider provides a credential that can be used for authentication and decryption when called.
type Provider interface {
	Provide(*http.Client) (UsableCredential, error)
}

// UseAWS returns a Provider that can be used to use an assumed AWS role as a credential for SecretHub.
// The provided awsCfg is used to configure the AWS client.
// If used on AWS (e.g. from an EC2-instance), this extra configuration is not required and the correct configuration
// should be auto-detected by the AWS client.
//
// Usage:
//		credentials.UseAWS()
//		credentials.UseAWS(&aws.Config{Region: aws.String("eu-west-1")})
func UseAWS(awsCfg ...*awssdk.Config) Provider {
	return providerFunc(func(httpClient *http.Client) (UsableCredential, error) {
		decrypter, err := aws.NewKMSDecrypter(awsCfg...)
		if err != nil {
			return nil, err
		}
		authProvider := sessions.NewSessionRefresher(httpClient, sessions.NewAWSSessionCreator(awsCfg...))
		return usableCredential{decrypter, authProvider}, nil
	})
}

// UseKey returns a Provider that reads a key credential from credentialReader.
// If the key credential is encrypted, a passphrase is read from passReader and used for decryption,
// The passReader argument can be set to nil if the credential is not encrypted.
// If credentialReader argument is set to nil, the following default locations are searched for a credential:
//   1. The SECRETHUB_CREDENTIAL environment variable.
//   2. The credential file placed in the directory given by the SECRETHUB_CONFIG_DIR environment variable.
//   3. The credential file found in <user's home directory>/.secrethub/credential.
//
// Usage:
//		credentials.UseKey(credentials.FromString("<a credential>"), nil)
//		credentials.UseKey(credentials.FromFile("/path/to/credential"), credentials.FromString("passphrase"))
func UseKey(credentialReader io.Reader, passReader io.Reader) Provider {
	return providerFunc(func(_ *http.Client) (UsableCredential, error) {
		// This function can be cleaned up a lot. It is mainly for demonstrating the overall idea.
		if credentialReader == nil {
			credentialReader = credentialFromDefault()
		}

		bytes, err := ioutil.ReadAll(credentialReader)
		if err != nil {
			return nil, err
		}
		encoded, err := defaultParser.parse(string(bytes))
		if err != nil {
			return nil, err
		}
		if encoded.IsEncrypted() {
			if passReader == nil {
				return nil, errors.New("need passphrase")
			}
			passphrase, err := ioutil.ReadAll(passReader)
			if err != nil {
				return nil, err
			}
			key, err := NewPassBasedKey(passphrase)
			if err != nil {
				return nil, err
			}

			credential, err := encoded.DecodeEncrypted(key)
			if crypto.IsWrongKey(err) {
				return nil, ErrCannotDecryptCredential
			} else if err != nil {
				return nil, err
			}
			return struct {
				Decrypter
				auth.Authenticator
			}{credential, auth.NewHTTPSigner(credential)}, nil
		}
		credential, err := encoded.Decode()
		if err != nil {
			return nil, err
		}

		return credential, nil
	})
}

// providerFunc is a helper type to let any func(*http.Client) (UsableCredential, error) implement the Provider interface.
type providerFunc func(*http.Client) (UsableCredential, error)

// Provide lets providerFunc implement the Provider interface.
func (f providerFunc) Provide(httpClient *http.Client) (UsableCredential, error) {
	return f(httpClient)
}
