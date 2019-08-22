package http

import (
	"net/http"
	"time"

	"github.com/secrethub/secrethub-go/internals/auth"
)

type ClientOption func(*Client)

func WithServerURL(url string) ClientOption {
	return func(client *Client) {
		client.base = url
	}
}

func WithTransport(transport http.RoundTripper) ClientOption {
	return func(client *Client) {
		client.client.Transport = transport
	}
}

func WithTimeout(timeout time.Duration) ClientOption {
	return func(client *Client) {
		client.client.Timeout = timeout
	}
}

func WithAuthenticator(authenticator auth.Authenticator) ClientOption {
	return func(client *Client) {
		client.authenticator = authenticator
	}
}
