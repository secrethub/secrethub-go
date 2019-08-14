package secrethub

import (
	"net/http"
	"time"

	"github.com/secrethub/secrethub-go/internals/auth"
)

type ClientOption func(*Client) error

func Timeout(timeout time.Duration) ClientOption {
	return func(c *Client) error {
		c.httpClient.client.Timeout = timeout
		return nil
	}
}

func Remote(url string) ClientOption {
	return func(c *Client) error {
		c.httpClient.base = url
		return nil
	}
}

func Transport(roundTripper http.RoundTripper) ClientOption {
	return func(c *Client) error {
		c.httpClient.client.Transport = roundTripper
		return nil
	}
}

type CredentialProvider func(*Client) (auth.Authenticator, Decrypter, error)

func Credentials(provider CredentialProvider) ClientOption {
	return func(c *Client) error {
		authenticator, decrypter, err := provider(c)
		if err != nil {
			return err
		}
		c.decrypter = decrypter
		c.httpClient.authenticator = authenticator
		return nil
	}
}
