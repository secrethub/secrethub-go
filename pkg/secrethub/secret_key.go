package secrethub

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub/core/errio"
	"github.com/keylockerbv/secrethub/crypto"
)

// GetSecretKey gets the current key for a given secret.
func (c *Client) GetSecretKey(secretPath api.SecretPath) (*api.SecretKey, error) {
	blindName, err := c.convertPathToBlindName(secretPath)
	if err != nil {
		return nil, errio.Error(err)
	}

	encKey, err := c.httpClient.GetCurrentSecretKey(blindName)
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKey, err := c.getAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	return encKey.Decrypt(accountKey)
}

// CreateSecretKey creates a new secret key for a given secret.
func (c *Client) CreateSecretKey(secretPath api.SecretPath) (*api.SecretKey, error) {
	secretKey, err := crypto.GenerateAESKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	parentPath, err := secretPath.GetParentPath()
	if err != nil {
		return nil, errio.Error(err)
	}

	// Get all accounts that have permission to read the secret.
	accounts, err := c.ListDirAccounts(parentPath)
	if err != nil {
		return nil, errio.Error(err)
	}

	encryptedFor := make([]api.EncryptedKeyRequest, len(accounts))
	for i, account := range accounts {
		publicKey, err := crypto.ImportRSAPublicKey(account.PublicKey)
		if err != nil {
			return nil, errio.Error(err)
		}

		encryptedSecretKey, err := crypto.EncryptRSA(secretKey.Export(), publicKey)
		if err != nil {
			return nil, errio.Error(err)
		}

		encodedSecretKey, err := api.EncodeCiphertext(encryptedSecretKey)
		if err != nil {
			return nil, errio.Error(err)
		}

		encryptedFor[i] = api.EncryptedKeyRequest{
			AccountID:    account.AccountID,
			EncryptedKey: encodedSecretKey,
		}
	}

	in := &api.CreateSecretKeyRequest{
		EncryptedFor: encryptedFor,
	}

	blindName, err := c.convertPathToBlindName(secretPath)
	if err != nil {
		return nil, errio.Error(err)
	}

	resp, err := c.httpClient.CreateSecretKey(blindName, in)
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKey, err := c.getAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	return resp.Decrypt(accountKey)
}
