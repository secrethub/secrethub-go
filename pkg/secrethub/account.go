package secrethub

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/crypto"
	"github.com/keylockerbv/secrethub/core/errio"
)

// AccountService handles operations on SecretHub accounts.
type AccountService interface {
	// Get retrieves an account.
	Get(name api.AccountName) (*api.Account, error)
	// Keys returns an account key service.
	Keys() AccountKeyService
}

type accountService struct {
	client *Client
}

// Get retrieves an account.
func (s accountService) Get(name api.AccountName) (*api.Account, error) {
	return s.client.GetAccount(name)
}

// Keys returns an account key service.
func (s accountService) Keys() AccountKeyService {
	return newAccountKeyService(s.client)
}

// createAccountKey creates a new intermediate key wrapped in the supplied credential.
// The public key of the intermediate key is returned.
// The intermediate key is returned in an CreateAccountKeyRequest ready to be sent to the API.
// If an error has occured, it will be returned and the other result should be considered invalid.
func (c *Client) createAccountKeyRequest(credential Credential, accountKey *crypto.RSAKey) (*api.CreateAccountKeyRequest, error) {
	publicAccountKey, err := accountKey.ExportPublicKey()
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

	encodedWrappedAccountKey, err := api.EncodeCiphertext(wrappedAccountKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	return &api.CreateAccountKeyRequest{
		PublicKey:           publicAccountKey,
		EncryptedPrivateKey: encodedWrappedAccountKey,
	}, nil
}

func (c *Client) createCredentialRequest(credential Credential) (*api.CreateCredentialRequest, error) {
	authID, err := credential.AuthID()
	if err != nil {
		return nil, errio.Error(err)
	}

	authData, err := credential.AuthData()
	if err != nil {
		return nil, errio.Error(err)
	}

	return &api.CreateCredentialRequest{
		Fingerprint: authID,
		Verifier:    authData,
		Type:        credential.Type(),
	}, nil
}

// GetAccount returns the account retrieved by name.
func (c *Client) GetAccount(name api.AccountName) (*api.Account, error) {
	account, err := c.httpClient.GetAccount(name)
	return account, errio.Error(err)
}

// getAccountKey attempts to get the account key from the cache,
// getting it from the API if not found in the cache.
func (c *Client) getAccountKey() (*crypto.RSAKey, error) {
	if c.accountKey == nil {
		err := c.fetchAccountDetails()
		if err != nil {
			return nil, errio.Error(err)
		}
	}

	return c.accountKey, nil
}

// getMyAccount returns the account of the client itself.
func (c *Client) getMyAccount() (*api.Account, error) {
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
// This function should only be called from Client.getAccountKey or Client.getMyAccount
// Don't use this unless you know what you're doing. Use Client.getAccountKey instead.
func (c *Client) fetchAccountDetails() error {
	resp, err := c.httpClient.GetAccountKey()
	if err != nil {
		return errio.Error(err)
	}

	ciphertext, err := resp.EncryptedPrivateKey.Decode()
	if err != nil {
		return errio.Error(err)
	}

	data, err := c.credential.Unwrap(ciphertext)
	if err != nil {
		return errio.Error(err)
	}

	accountKey, err := crypto.ImportRSAPrivateKey(data)
	if err != nil {
		return errio.Error(err)
	}

	// Cache the account and account key
	c.account = resp.Account
	c.accountKey = accountKey

	return nil
}
