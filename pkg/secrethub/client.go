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

func Must(c ClientAdapter, err error) ClientAdapter {
	if err != nil {
		panic(err)
	}
	return c
}

// NewClient creates a new SecretHub client.
// It overrides the default configuration with the options when given.
func NewClient(options ...ClientOption) (ClientAdapter, error) {
	return newClient()
}

// AccessRules returns an AccessRuleService.
func (c *client) AccessRules() AccessRuleService {
	return newAccessRuleService(c)
}

// Accounts returns an AccountService.
func (c *client) Accounts() AccountService {
	return newAccountService(c)
}

// Auth returns an SessionService.
func (c *client) Sessions() SessionService {
	return newSessionService(c)
}

// Dirs returns an DirService.
func (c *client) Dirs() DirService {
	return newDirService(c)
}

// Me returns a MeService.
func (c *client) Me() MeService {
	return newMeService(c)
}

// Orgs returns an OrgService.
func (c *client) Orgs() OrgService {
	return newOrgService(c)
}

// Repos returns an RepoService.
func (c *client) Repos() RepoService {
	return newRepoService(c)
}

// Secrets returns an SecretService.
func (c *client) Secrets() SecretService {
	return newSecretService(c)
}

// Services returns an ServiceService.
func (c *client) Services() ServiceService {
	return newServiceService(c)
}

// Users returns an UserService.
func (c *client) Users() UserService {
	return newUserService(c)
}

var (
	errClient = errio.Namespace("client")
)

// Client is a client for the SecretHub HTTP API.
type client struct {
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

func must(c *client, err error) *client {
	if err != nil {
		panic(err)
	}
	return c
}

// newClient configures a new client, overriding defaults with options when given.
func newClient(options ...ClientOption) (*client, error) {
	client := &client{
		httpClient:    newHTTPClient(),
		repoIndexKeys: make(map[api.RepoPath]*crypto.SymmetricKey),
	}
	for _, option := range options {
		err := option(client)
		if err != nil {
			return nil, err
		}
	}
	return client, nil
}
