package secrethub

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/crypto"
	"github.com/keylockerbv/secrethub-go/pkg/errio"
)

// AccountService handles operations on SecretHub accounts.
type AccountService interface {
	// Get retrieves an account by name.
	Get(name string) (*api.Account, error)
	// Keys returns an account key service.
	Keys() AccountKeyService
}

func newAccountService(client client) AccountService {
	return &accountService{
		client: client,
	}
}

type accountService struct {
	client client
}

// Get retrieves an account by name.
func (s accountService) Get(name string) (*api.Account, error) {
	accountName, err := api.NewAccountName(name)
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.httpClient.GetAccount(accountName)
}

// Keys returns an account key service.
func (s accountService) Keys() AccountKeyService {
	return newAccountKeyService(s.client)
}

// createAccountKey creates a new intermediate key wrapped in the supplied credential.
// The public key of the intermediate key is returned.
// The intermediate key is returned in an CreateAccountKeyRequest ready to be sent to the API.
// If an error has occured, it will be returned and the other result should be considered invalid.
func (c *client) createAccountKeyRequest(credential Credential, accountKey crypto.RSAKey) (*api.CreateAccountKeyRequest, error) {
	publicAccountKey, err := accountKey.Public().Export()
	if err != nil {
		return nil, errio.Error(err)
	}

	privateAccountKey, err := accountKey.ExportPrivateKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	wrappedAccountKey, err := credential.Wrap(privateAccountKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	return &api.CreateAccountKeyRequest{
		PublicKey:           publicAccountKey,
		EncryptedPrivateKey: wrappedAccountKey,
	}, nil
}

func (c *client) createCredentialRequest(credential Credential) (*api.CreateCredentialRequest, error) {
	fingerprint, err := credential.Fingerprint()
	if err != nil {
		return nil, errio.Error(err)
	}

	verifier, err := credential.Verifier()
	if err != nil {
		return nil, errio.Error(err)
	}

	return &api.CreateCredentialRequest{
		Fingerprint: fingerprint,
		Verifier:    verifier,
		Type:        credential.Type(),
	}, nil
}

// getAccountKey attempts to get the account key from the cache,
// getting it from the API if not found in the cache.
func (c *client) getAccountKey() (*crypto.RSAKey, error) {
	if c.accountKey == nil {
		err := c.fetchAccountDetails()
		if err != nil {
			return nil, errio.Error(err)
		}
	}

	return c.accountKey, nil
}

// getMyAccount returns the account of the client itself.
func (c *client) getMyAccount() (*api.Account, error) {
	// retrieve the account from cache
	if c.account != nil {
		return c.account, nil
	}

	err := c.fetchAccountDetails()
	if err != nil {
		return nil, errio.Error(err)
	}

	return c.account, nil
}

// fetchAccountDetails is a helper function that fetches the account and account key from the API.
// These are cached in the client.
// This function should only be called from client.getAccountKey or client.getMyAccount
// Don't use this unless you know what you're doing. Use client.getAccountKey instead.
func (c *client) fetchAccountDetails() error {
	resp, err := c.httpClient.GetAccountKey()
	if err != nil {
		return errio.Error(err)
	}

	data, err := c.credential.Unwrap(resp.EncryptedPrivateKey)
	if err != nil {
		return errio.Error(err)
	}

	accountKey, err := crypto.ImportRSAPrivateKey(data)
	if err != nil {
		return errio.Error(err)
	}

	// Cache the account and account key
	c.account = resp.Account
	c.accountKey = &accountKey

	return nil
}
