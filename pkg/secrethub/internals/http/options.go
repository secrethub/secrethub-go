package http

import (
	"net/http"
	"time"

	"github.com/secrethub/secrethub-go/internals/auth"
)

type Option func(*Client)

func WithServerURL(url string) Option {
	return func(client *Client) {
		client.base = url
	}
}

func WithTransport(transport http.RoundTripper) Option {
	return func(client *Client) {
		client.client.Transport = transport
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(client *Client) {
		client.client.Timeout = timeout
	}
}

func WithAuthenticator(authenticator auth.Authenticator) Option {
	return func(client *Client) {
		client.authenticator = authenticator
	}
}
