package credentials

import (
	awssdk "github.com/aws/aws-sdk-go/aws"

	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/internals/aws"
	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials/sessions"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

// Provider provides a credential that can be used for authentication and decryption when called.
type Provider interface {
	Provide(*http.Client) (auth.Authenticator, Decrypter, error)
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
	return providerFunc(func(httpClient *http.Client) (auth.Authenticator, Decrypter, error) {
		decrypter, err := aws.NewKMSDecrypter(awsCfg...)
		if err != nil {
			return nil, nil, err
		}
		authenticator := sessions.NewSessionRefresher(httpClient, sessions.NewAWSSessionCreator(awsCfg...))
		return authenticator, decrypter, nil
	})
}

// UseKey returns a Provider that reads a key credential from credentialReader.
// If the key credential is encrypted, a passphrase must be set by calling Passphrase on the returned KeyProvider,
//
// Usage:
//		credentials.UseKey(credentials.FromString("<a credential>"))
//		credentials.UseKey(credentials.FromFile("/path/to/credential")).Passphrase(credentials.FromString("passphrase"))
func UseKey(credentialReader Reader) KeyProvider {
	return KeyProvider{
		credentialReader: credentialReader,
	}
}

type KeyProvider struct {
	credentialReader Reader
	passphraseReader Reader
}

func (k KeyProvider) Passphrase(passphraseReader Reader) Provider {
	k.passphraseReader = passphraseReader
	return k
}

func (k KeyProvider) Provide(httpClient *http.Client) (auth.Authenticator, Decrypter, error) {
	key, err := ImportKey(k.credentialReader, k.passphraseReader)
	if err != nil {
		return nil, nil, err
	}
	return key.Provide(httpClient)
}

// providerFunc is a helper type to let any func(*http.Client) (UsableCredential, error) implement the Provider interface.
type providerFunc func(*http.Client) (auth.Authenticator, Decrypter, error)

// Provide lets providerFunc implement the Provider interface.
func (f providerFunc) Provide(httpClient *http.Client) (auth.Authenticator, Decrypter, error) {
	return f(httpClient)
}
