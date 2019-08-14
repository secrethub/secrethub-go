package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/internals/errio"
)

// Client is the SecretHub client.
type ClientAdapter interface {
	AccessRules() AccessRuleService
	Accounts() AccountService
	Sessions() SessionService
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
	httpClient *httpClient

	decrypter Decrypter

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

// NewClient creates a new SecretHub client.
// It overrides the default configuration with the options when given.
func NewClient(with ...ClientOption) (*Client, error) {
	client := &Client{
		httpClient:    newHTTPClient(),
		repoIndexKeys: make(map[api.RepoPath]*crypto.SymmetricKey),
	}
	for _, option := range with {
		err := option(client)
		if err != nil {
			return nil, err
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

// Decrypter decrypts data, typically an account key.
type Decrypter interface {
	// Unwrap decrypts data, typically an account key.
	Unwrap(ciphertext *api.EncryptedData) ([]byte, error)
}

// Encrypter encrypts data, typically an account key.
type Encrypter interface {
	// Wrap encrypts data, typically an account key.
	Wrap(plaintext []byte) (*api.EncryptedData, error)
}

// AccessRules returns an AccessRuleService.
func (c *Client) AccessRules() AccessRuleService {
	return newAccessRuleService(c)
}

// Accounts returns an AccountService.
func (c *Client) Accounts() AccountService {
	return newAccountService(c)
}

// Auth returns a SessionService.
func (c *Client) Sessions() SessionService {
	return newSessionService(c)
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
