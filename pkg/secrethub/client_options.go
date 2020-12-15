package secrethub

import (
	"net/http"
	"net/url"
	"time"

	"github.com/secrethub/secrethub-go/pkg/secrethub/configdir"
	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials"
	httpclient "github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

// Errors
var (
	ErrInvalidServerURL = errClient.Code("invalid_server_url").ErrorPref("%s")
)

// ClientOption is an option that can be set on a secrethub.Client.
type ClientOption func(*Client) error

// WithTimeout overrides the default request timeout of the HTTP client.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) error {
		c.httpClient.Options(httpclient.WithTimeout(timeout))
		return nil
	}
}

// WithServerURL overrides the default server endpoint URL used by the HTTP client.
func WithServerURL(serverURL string) ClientOption {
	return func(c *Client) error {
		parsedURL, err := url.Parse(serverURL)
		if err != nil {
			return ErrInvalidServerURL(err)
		}

		c.httpClient.Options(httpclient.WithServerURL(*parsedURL))
		return nil
	}
}

// WithTransport replaces the DefaultTransport used by the HTTP client with the provided RoundTripper.
func WithTransport(transport http.RoundTripper) ClientOption {
	return func(c *Client) error {
		c.httpClient.Options(httpclient.WithTransport(transport))
		return nil
	}
}

// WithAppInfo sets the AppInfo to be used for identifying the application that is using the SecretHub Client.
func WithAppInfo(appInfo *AppInfo) ClientOption {
	return func(c *Client) error {
		if err := appInfo.ValidateName(); err != nil {
			return err
		}
		c.appInfo = append(c.appInfo, appInfo)
		return nil
	}
}

// WithConfigDir sets the configuration directory to use (among others) for sourcing the credential file from.
func WithConfigDir(configDir configdir.Dir) ClientOption {
	return func(c *Client) error {
		c.ConfigDir = &configDir
		return nil
	}
}

// WithCredentials sets the credential to be used for authenticating to the API and decrypting the account key.
func WithCredentials(provider credentials.Provider) ClientOption {
	return func(c *Client) error {
		authenticator, decrypter, err := provider.Provide(c.httpClient)
		if err != nil {
			return err
		}
		c.decrypter = decrypter
		c.httpClient.Options(httpclient.WithAuthenticator(authenticator))
		return nil
	}
}

// WithDefaultPassphraseReader sets a default passphrase reader that is used for decrypting an encrypted key credential
// if no credential is set explicitly.
func WithDefaultPassphraseReader(reader credentials.Reader) ClientOption {
	return func(c *Client) error {
		c.defaultPassphraseReader = reader
		return nil
	}
}
