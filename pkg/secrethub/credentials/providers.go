package credentials

import (
	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

// Provider provides a credential that can be used for authentication and decryption when called.
type Provider interface {
	Provide(*http.Client) (auth.Authenticator, Decrypter, error)
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

// KeyProvider is a Provider that reads a key from a Reader.
// If the key is encrypted with a passphrase, Passphrase() should be called on the KeyProvider to set the Reader that
// provides the passphrase that can be used to decrypt the key.
type KeyProvider struct {
	credentialReader Reader
	passphraseReader Reader
}

// Passphrase returns a new Provider that uses the passphraseReader to read a passphrase if the read key is encrypted.
func (k KeyProvider) Passphrase(passphraseReader Reader) Provider {
	k.passphraseReader = passphraseReader
	return k
}

// Provide implements the Provider interface for a KeyProvider.
func (k KeyProvider) Provide(httpClient *http.Client) (auth.Authenticator, Decrypter, error) {
	key, err := ImportKey(k.credentialReader, k.passphraseReader)
	if err != nil {
		if source, ok := k.credentialReader.(CredentialSource); ok {
			return nil, nil, ErrLoadingCredential{
				Location: source.Source(),
				Err:      err,
			}
		}
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

// CredentialSource should be implemented by credential readers to allow returning credential reading errors
// that include the credentials source (e.g. path to credential file, environment variable etc.).
type CredentialSource interface {
	Source() string
}
