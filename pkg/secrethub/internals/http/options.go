package http

import (
	"net/http"
	"time"

	"github.com/secrethub/secrethub-go/internals/auth"
)

// ClientOption is an option that can be set on an http.Client.
type ClientOption func(*Client)

// WithServerURL overrides the default server endpoint URL used by the HTTP client.
func WithServerURL(url string) ClientOption {
	return func(client *Client) {
		client.base = getBaseURL(url)
	}
}

// WithTransport replaces the DefaultTransport used by the HTTP client with the provided RoundTripper.
func WithTransport(transport http.RoundTripper) ClientOption {
	return func(client *Client) {
		client.client.Transport = transport
	}
}

// WithTimeout overrides the default request timeout of the HTTP client.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(client *Client) {
		client.client.Timeout = timeout
	}
}

// WithUserAgent overrides the default user-agent supplied by HTTP client in requests.
func WithUserAgent(userAgent string) ClientOption {
	return func(client *Client) {
		client.userAgent = userAgent
	}
}

// WithAuthenticator sets the authenticator used to authenticate requests made by the HTTP client.
func WithAuthenticator(authenticator auth.Authenticator) ClientOption {
	return func(client *Client) {
		client.authenticator = authenticator
	}
}
