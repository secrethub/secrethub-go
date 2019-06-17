package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/internals/errio"
)

// Client is the SecretHub client.
type Client interface {
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

// Decrypter decrypts data, typically an account key.
type Decrypter interface {
	// Unwrap decrypts data, typically an account key.
	Unwrap(ciphertext crypto.CiphertextRSAAES) ([]byte, error)
}

// Encrypter encrypts data, typically an account key.
type Encrypter interface {
	// Wrap encrypts data, typically an account key.
	Wrap(plaintext []byte) (crypto.CiphertextRSAAES, error)
}

type clientAdapter struct {
	client client
}

// NewClient creates a new SecretHub client.
// It overrides the default configuration with the options when given.
func NewClient(decrypter Decrypter, authenticator auth.Authenticator, opts *ClientOptions) Client {
	return &clientAdapter{
		client: newClient(decrypter, authenticator, opts),
	}
}

// AccessRules returns an AccessRuleService.
func (c clientAdapter) AccessRules() AccessRuleService {
	return newAccessRuleService(c.client)
}

// Accounts returns an AccountService.
func (c clientAdapter) Accounts() AccountService {
	return newAccountService(c.client)
}

// Dirs returns an DirService.
func (c clientAdapter) Dirs() DirService {
	return newDirService(c.client)
}

// Me returns a MeService.
func (c clientAdapter) Me() MeService {
	return newMeService(c.client)
}

// Orgs returns an OrgService.
func (c clientAdapter) Orgs() OrgService {
	return newOrgService(c.client)
}

// Repos returns an RepoService.
func (c clientAdapter) Repos() RepoService {
	return newRepoService(c.client)
}

// Secrets returns an SecretService.
func (c clientAdapter) Secrets() SecretService {
	return newSecretService(c.client)
}

// Services returns an ServiceService.
func (c clientAdapter) Services() ServiceService {
	return newServiceService(c.client)
}

// Users returns an UserService.
func (c clientAdapter) Users() UserService {
	return newUserService(c.client)
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

// newClient configures a new client, overriding defaults with options when given.
func newClient(decrypter Decrypter, authenticator auth.Authenticator, opts *ClientOptions) client {
	httpClient := newHTTPClient(authenticator, opts)

	return client{
		httpClient:    httpClient,
		decrypter:     decrypter,
		repoIndexKeys: make(map[api.RepoPath]*crypto.SymmetricKey),
	}
}
