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

func WithRemote(url string) ClientOption {
	return func(c *Client) error {
		c.httpClient.Options(httpclient.WithRemote(url))
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
		authProvider, decrypter, err := provider()
		if err != nil {
			return err
		}
		c.decrypter = decrypter
		c.httpClient.Options(httpclient.WithAuthProvider(authProvider))
		return nil
	}
}
