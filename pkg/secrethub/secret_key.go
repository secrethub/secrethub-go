package secrethub

import (
	"fmt"

	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/internals/errio"
)

// getSecretKey gets the current key for a given secret.
func (c *Client) getSecretKey(secretPath api.SecretPath) (*api.SecretKey, error) {
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

// createSecretKey creates a new secret key for a given secret.
func (c *Client) createSecretKey(secretPath api.SecretPath) (*api.SecretKey, error) {
	secretKey, err := crypto.GenerateSymmetricKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	parentPath, err := secretPath.GetParentPath()
	if err != nil {
		return nil, errio.Error(err)
	}

	blindName, err := c.convertPathToBlindName(secretPath)
	if err != nil {
		return nil, errio.Error(err)
	}

	encryptedKeysMap := make(map[uuid.UUID]api.EncryptedKeyRequest)

	tries := 0
	for {
		// Get all accounts that have permission to read the secret.
		accounts, err := c.listDirAccounts(parentPath)
		if err != nil {
			return nil, errio.Error(err)
		}

		for _, account := range accounts {
			_, ok := encryptedKeysMap[account.AccountID]
			if !ok {
				publicKey, err := crypto.ImportRSAPublicKey(account.PublicKey)
				if err != nil {
					return nil, errio.Error(err)
				}

				encryptedSecretKey, err := publicKey.Wrap(secretKey.Export())
				if err != nil {
					return nil, errio.Error(err)
				}

				encryptedKeysMap[account.AccountID] = api.EncryptedKeyRequest{
					AccountID:    account.AccountID,
					EncryptedKey: encryptedSecretKey,
				}
			}
		}

		encryptedFor := make([]api.EncryptedKeyRequest, len(encryptedKeysMap))
		i := 0
		for _, encryptedKey := range encryptedKeysMap {
			encryptedFor[i] = encryptedKey
			i++
		}

		in := &api.CreateSecretKeyRequest{
			EncryptedFor: encryptedFor,
		}

		resp, err := c.httpClient.CreateSecretKey(blindName, in)
		if err == nil {
			accountKey, err := c.getAccountKey()
			if err != nil {
				return nil, err
			}

			return resp.Decrypt(accountKey)
		}
		if err != api.ErrNotEncryptedForAccounts {
			return nil, err
		}
		if tries >= missingMemberRetries {
			return nil, fmt.Errorf("cannot create secret key: access rules giving access to the secret (key) are simultaneously being created; you may try again")
		}
		tries++
	}
}
