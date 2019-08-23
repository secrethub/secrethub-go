package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/internals/errio"
	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

// ClientAdapter is an interface that can be used to consume the SecretHub client and is implemented by secrethub.Client.
type ClientAdapter interface {
	AccessRules() AccessRuleService
	Accounts() AccountService
	Dirs() DirService
	Me() MeService
	Orgs() OrgService
	Repos() RepoService
	Secrets() SecretService
	Services() ServiceService
	Users() UserService
}

var (
	errClient = errio.Namespace("client")
)

// Client is a client for the SecretHub HTTP API.
type Client struct {
	httpClient *http.Client

	decrypter credentials.Decrypter

	// account is the api.Account for this SecretHub account.
	// Do not use this field directly, but use client.getMyAccount() instead.
	account *api.Account

	// accountKey is the intermediate key for this SecretHub account.
	// Do not use this field directly, but use client.getAccountKey() instead.
	accountKey *crypto.RSAPrivateKey

	// repoindexKeys are the keys used to generate blind names in the repo.
	// These are cached
	repoIndexKeys map[api.RepoPath]*crypto.SymmetricKey
}

// NewClient creates a new SecretHub client. Provided options are applied to the client.
//
// If no WithCredentials() option is provided, the client tries to find a key credential at the following locations (in order):
//   1. The SECRETHUB_CREDENTIAL environment variable.
//   2. The credential file placed in the directory given by the SECRETHUB_CONFIG_DIR environment variable.
//   3. The credential file found in <user's home directory>/.secrethub/credential.
// If no key credential could be found, a Client is returned that can only be used for unauthenticated routes.
func NewClient(with ...ClientOption) (*Client, error) {
	client := &Client{
		httpClient:    http.NewClient(),
		repoIndexKeys: make(map[api.RepoPath]*crypto.SymmetricKey),
	}
	for _, option := range with {
		err := option(client)
		if err != nil {
			return nil, err
		}
	}

	// Try to use default key credentials if none provided explicitly
	if client.decrypter == nil {
		err := WithCredentials(credentials.UseKey(nil, nil))(client)
		// nolint: staticcheck
		if err != nil {
			// TODO: log that default credential was not loaded.
			// Do go on because we want to allow an unauthenticated client.
		}
	}

	return client, nil
}

// Must is a helper function to ensure the Client is valid and there was no
// error when calling a NewClient function.
//
// This helper is intended to be used in initialization to load the
// Session and configuration at startup. For example:
//
//     var client = secrethub.Must(secrethub.NewClient())
func Must(c *Client, err error) *Client {
	if err != nil {
		panic(err)
	}
	return c
}

// AccessRules returns an AccessRuleService.
func (c *Client) AccessRules() AccessRuleService {
	return newAccessRuleService(c)
}

// Accounts returns an AccountService.
func (c *Client) Accounts() AccountService {
	return newAccountService(c)
}

// Dirs returns an DirService.
func (c *Client) Dirs() DirService {
	return newDirService(c)
}

// Me returns a MeService.
func (c *Client) Me() MeService {
	return newMeService(c)
}

// Orgs returns an OrgService.
func (c *Client) Orgs() OrgService {
	return newOrgService(c)
}

// Repos returns an RepoService.
func (c *Client) Repos() RepoService {
	return newRepoService(c)
}

// Secrets returns an SecretService.
func (c *Client) Secrets() SecretService {
	return newSecretService(c)
}

// Services returns an ServiceService.
func (c *Client) Services() ServiceService {
	return newServiceService(c)
}

// Users returns an UserService.
func (c *Client) Users() UserService {
	return newUserService(c)
}
