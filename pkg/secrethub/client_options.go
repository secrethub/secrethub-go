package secrethub

import (
	"net/http"
	"time"

	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials"
	httpclient "github.com/secrethub/secrethub-go/pkg/secrethub/http"
)

type ClientOption func(*Client) error

func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) error {
		c.httpClient.Options(httpclient.WithTimeout(timeout))
		return nil
	}
}

func WithServerURL(url string) ClientOption {
	return func(c *Client) error {
		c.httpClient.Options(httpclient.WithServerURL(url))
		return nil
	}
}

func WithTransport(transport http.RoundTripper) ClientOption {
	return func(c *Client) error {
		c.httpClient.Options(httpclient.WithTransport(transport))
		return nil
	}
}

func WithCredentials(provider credentials.Provider) ClientOption {
	return func(c *Client) error {
		authProvider, decrypter, err := provider(c.httpClient)
		if err != nil {
			return err
		}
		c.decrypter = decrypter
		c.httpClient.Options(httpclient.WithAuthenticator(authProvider))
		return nil
	}
}
