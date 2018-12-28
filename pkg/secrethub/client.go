package secrethub

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/crypto"
	"github.com/keylockerbv/secrethub-go/pkg/errio"
)

var (
	errClient = errio.Namespace("client")
)

// Client is a client for the SecretHub HTTP API.
type client struct {
	httpClient *httpClient

	// credential is the key used by a client to decrypt the account key and authenticate the requests.
	// It is passed to the httpClient to provide authentication.
	credential Credential

	// account is the api.Account for this SecretHub account.
	// Do not use this field directly, but use client.getMyAccount() instead.
	account *api.Account

	// accountKey is the intermediate key for this SecretHub account.
	// Do not use this field directly, but use client.getAccountKey() instead.
	accountKey *crypto.RSAKey

	// repoindexKeys are the keys used to generate blind names in the repo.
	// These are cached
	repoIndexKeys map[api.RepoPath]*crypto.AESKey
}

// newClient configures a new client, overriding defaults with options when given.
func newClient(credential Credential, opts *ClientOptions) (*client, error) {
	httpClient := newHTTPClient(credential, opts)

	return &client{
		httpClient:    httpClient,
		credential:    credential,
		repoIndexKeys: make(map[api.RepoPath]*crypto.AESKey),
	}, nil
}
