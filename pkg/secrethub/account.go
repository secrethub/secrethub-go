package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/internals/errio"
	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials"
)

// Errors
var (
	ErrNoDecryptionKey    = errClient.Code("no_decryption_key").Error("client is not initialized with a method to decrypt the account key")
	ErrIncorrectAccountID = errClient.Code("incorrect_account_id").Error("the incorrect account ID was provided. To delete the currently authenticated account please provide its ID.")
)

// AccountService handles operations on SecretHub accounts.
type AccountService interface {
	// Me retrieves the authenticated account of the client.
	Me() (*api.Account, error)
	// Delete deletes the authenticated account of the client if it's ID is provided as a parameter.
	// Do not use this method. Account deletes should only be performed from the CLI.
	Delete(accountID uuid.UUID) error
	// Get retrieves an account by name.
	Get(name string) (*api.Account, error)
	// Keys returns an account key service.
	Keys() AccountKeyService
}

func newAccountService(client *Client) AccountService {
	return &accountService{
		client: client,
	}
}

type accountService struct {
	client *Client
}

// Me retrieves the authenticated account of the client.
func (s accountService) Me() (*api.Account, error) {
	return s.client.getMyAccount()
}

// Delete deletes the authenticated account of the client if it's ID is provided as a parameter.
// Do not use this method. Account deletes should only be performed from the CLI.
func (s accountService) Delete(accountID uuid.UUID) error {
	account, err := s.client.getMyAccount()
	if err != nil {
		return err
	}
	if accountID != account.AccountID {
		return ErrIncorrectAccountID
	}
	return s.client.httpClient.DeleteMyAccount()
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
// If an error has occurred, it will be returned and the other result should be considered invalid.
func (c *Client) createAccountKeyRequest(encrypter credentials.Encrypter, accountKey crypto.RSAPrivateKey) (*api.CreateAccountKeyRequest, error) {
	publicAccountKey, err := accountKey.Public().Encode()
	if err != nil {
		return nil, errio.Error(err)
	}

	privateAccountKey, err := accountKey.ExportPEM()
	if err != nil {
		return nil, errio.Error(err)
	}

	wrappedAccountKey, err := encrypter.Wrap(privateAccountKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	return &api.CreateAccountKeyRequest{
		PublicKey:           publicAccountKey,
		EncryptedPrivateKey: wrappedAccountKey,
	}, nil
}

func (c *Client) createCredentialRequest(encrypter credentials.Encrypter, accountKey crypto.RSAPrivateKey, verifier credentials.Verifier, metadata map[string]string) (*api.CreateCredentialRequest, error) {
	bytes, fingerprint, err := verifier.Export()
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKeyReq, err := c.createAccountKeyRequest(encrypter, accountKey)
	if err != nil {
		return nil, err
	}

	req := api.CreateCredentialRequest{
		Fingerprint: fingerprint,
		Verifier:    bytes,
		Type:        verifier.Type(),
		Metadata:    metadata,
		AccountKey:  accountKeyReq,
	}
	err = verifier.AddProof(&req)
	if err != nil {
		return nil, errio.Error(err)
	}
	return &req, nil
}

// getAccountKey attempts to get the account key from the cache,
// getting it from the API if not found in the cache.
func (c *Client) getAccountKey() (*crypto.RSAPrivateKey, error) {
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
// This function should only be called from client.getAccountKey or client.getMyAccount
// Don't use this unless you know what you're doing. Use client.getAccountKey instead.
func (c *Client) fetchAccountDetails() error {
	if c.decrypter == nil {
		return ErrNoDecryptionKey
	}

	resp, err := c.httpClient.GetAccountKey()
	if err != nil {
		return errio.Error(err)
	}

	data, err := c.decrypter.Unwrap(resp.EncryptedPrivateKey)
	if err != nil {
		return errio.Error(err)
	}

	accountKey, err := crypto.ImportRSAPrivateKeyPEM(data)
	if err != nil {
		return errio.Error(err)
	}

	// Cache the account and account key
	c.account = resp.Account
	c.accountKey = &accountKey

	return nil
}
