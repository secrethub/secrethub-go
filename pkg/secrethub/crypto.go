package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/internals/crypto"
)

func (c *Client) encryptDirFor(dir *api.Dir, account *api.Account) (api.EncryptedNameForNodeRequest, error) {
	return encryptNameForNodeAccount(dir.DirID, dir.Name, account)
}

// encryptSecretFor encrypts the secret for every account.
// The SecretKeys are retrieved from the API.
// The keys are decrypted, then for every account this key is encrypted.
func (c *Client) encryptSecretFor(secret *api.Secret, account *api.Account) (api.SecretAccessRequest, error) {
	secretKeys, err := c.httpClient.ListSecretKeys(secret.BlindName)
	if err != nil {
		return api.SecretAccessRequest{}, err
	}

	myKey, err := c.getAccountKey()
	if err != nil {
		return api.SecretAccessRequest{}, err
	}

	decryptedKeys := make([]*api.SecretKey, len(secretKeys))
	for i, key := range secretKeys {
		decryptedKeys[i], err = key.Decrypt(myKey)
		if err != nil {
			return api.SecretAccessRequest{}, err
		}
	}

	publicKey, err := crypto.ImportRSAPublicKey(account.PublicKey)
	if err != nil {
		return api.SecretAccessRequest{}, err
	}

	encryptedSecretName, err := publicKey.Wrap([]byte(secret.Name))
	if err != nil {
		return api.SecretAccessRequest{}, err
	}

	encryptedName := api.EncryptedNameForNodeRequest{
		EncryptedNameRequest: api.EncryptedNameRequest{
			AccountID:     account.AccountID,
			EncryptedName: encryptedSecretName,
		},
		NodeID: secret.SecretID,
	}

	encryptedKeys := make([]api.SecretKeyMemberRequest, len(decryptedKeys))
	for keyIndex, decryptedKey := range decryptedKeys {
		encryptedKey, err := publicKey.Wrap(decryptedKey.Key.Export())
		if err != nil {
			return api.SecretAccessRequest{}, err
		}

		encryptedKeys[keyIndex] = api.SecretKeyMemberRequest{
			AccountID:    account.AccountID,
			SecretKeyID:  decryptedKey.SecretKeyID,
			EncryptedKey: encryptedKey,
		}
	}

	return api.SecretAccessRequest{
		Name: encryptedName,
		Keys: encryptedKeys,
	}, nil
}

// encryptNameForNodeAccount encrypts the name for the account and returns a EncryptedNameForNodeRequest.
func encryptNameForNodeAccount(nodeID uuid.UUID, name string, account *api.Account) (api.EncryptedNameForNodeRequest, error) {
	encryptedName, err := encryptNameForAccount(name, account)
	if err != nil {
		return api.EncryptedNameForNodeRequest{}, err
	}

	return api.EncryptedNameForNodeRequest{
		EncryptedNameRequest: api.EncryptedNameRequest{
			AccountID:     encryptedName.AccountID,
			EncryptedName: encryptedName.EncryptedName,
		},
		NodeID: nodeID,
	}, nil
}

// encryptNameForAccounts encrypts the name for every account and returns a list of EncryptedNameRequests.
func encryptNameForAccounts(name string, accounts ...*api.Account) ([]api.EncryptedNameRequest, error) {
	encryptedNames := make([]api.EncryptedNameRequest, len(accounts))
	for i, account := range accounts {
		var err error
		encryptedNames[i], err = encryptNameForAccount(name, account)
		if err != nil {
			return nil, err
		}
	}

	return encryptedNames, nil
}

func encryptNameForAccount(name string, account *api.Account) (api.EncryptedNameRequest, error) {
	publicKey, err := crypto.ImportRSAPublicKey(account.PublicKey)
	if err != nil {
		return api.EncryptedNameRequest{}, err
	}

	ciphertext, err := publicKey.Wrap([]byte(name))
	if err != nil {
		return api.EncryptedNameRequest{}, err
	}

	return api.EncryptedNameRequest{
		AccountID:     account.AccountID,
		EncryptedName: ciphertext,
	}, nil
}

// encryptKeyForAccount encrypts the key for the account and returns an EncryptedKeyRequest.
func encryptKeyForAccount(key *crypto.SymmetricKey, account *api.Account) (api.EncryptedKeyRequest, error) {
	publicKey, err := crypto.ImportRSAPublicKey(account.PublicKey)
	if err != nil {
		return api.EncryptedKeyRequest{}, err
	}

	encryptedSecretKey, err := publicKey.Wrap(key.Export())
	if err != nil {
		return api.EncryptedKeyRequest{}, err
	}

	return api.EncryptedKeyRequest{
		AccountID:    account.AccountID,
		EncryptedKey: encryptedSecretKey,
	}, nil
}
