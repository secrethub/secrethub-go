package http

import (
	"net/http"
	"time"
)

type Option func(*Client)

func WithRemote(remote string) Option {
	return func(client *Client) {
		client.base = remote
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

func WithAuthProvider(provider AuthProvider) Option {
	return func(client *Client) {
		client.authProvider = provider
	}
}
