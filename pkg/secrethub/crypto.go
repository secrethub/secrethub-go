package secrethub

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/api/uuid"
	"github.com/keylockerbv/secrethub-go/pkg/crypto"
	"github.com/keylockerbv/secrethub/core/errio"
)

func (c *Client) encryptDirFor(dir *api.Dir, accounts ...*api.Account) ([]api.EncryptedNameForNodeRequest, error) {
	currentDir, err := encryptNameForNodeAccounts(dir.DirID, dir.Name, accounts...)
	return currentDir, errio.Error(err)
}

// encryptSecretFor encrypts the secret for every account.
// The SecretKeys are retrieved from the API.
// The keys are decrypted, then for every account this key is encrypted.
func (c *Client) encryptSecretFor(secret *api.Secret, accounts ...*api.Account) ([]api.SecretAccessRequest, error) {
	results := make([]api.SecretAccessRequest, len(accounts))

	secretKeys, err := c.httpClient.ListSecretKeys(secret.BlindName)
	if err != nil {
		return nil, errio.Error(err)
	}

	myKey, err := c.getAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	decryptedKeys := make([]*api.SecretKey, len(secretKeys))
	for i, key := range secretKeys {
		decryptedKeys[i], err = key.Decrypt(myKey)
		if err != nil {
			return nil, errio.Error(err)
		}
	}

	for i, account := range accounts {
		publicKey, err := crypto.ImportRSAPublicKey(account.PublicKey)
		if err != nil {
			return nil, errio.Error(err)
		}

		encryptedSecretName, err := crypto.EncryptRSA([]byte(secret.Name), publicKey)
		if err != nil {
			return nil, errio.Error(err)
		}

		encodedSecretName, err := api.EncodeCiphertext(encryptedSecretName)
		if err != nil {
			return nil, errio.Error(err)
		}

		encryptedName := api.EncryptedNameForNodeRequest{
			EncryptedNameRequest: api.EncryptedNameRequest{
				AccountID:     account.AccountID,
				EncryptedName: encodedSecretName,
			},
			NodeID: secret.SecretID,
		}

		encryptedKeys := make([]api.SecretKeyMemberRequest, len(decryptedKeys))
		for keyIndex, decryptedKey := range decryptedKeys {
			encryptedKey, err := crypto.EncryptRSA(decryptedKey.Key.Export(), publicKey)
			if err != nil {
				return nil, errio.Error(err)
			}

			encodedKey, err := api.EncodeCiphertext(encryptedKey)
			if err != nil {
				return nil, errio.Error(err)
			}

			encryptedKeys[keyIndex] = api.SecretKeyMemberRequest{
				AccountID:    account.AccountID,
				SecretKeyID:  decryptedKey.SecretKeyID,
				EncryptedKey: encodedKey,
			}
		}

		results[i] = api.SecretAccessRequest{
			Name: encryptedName,
			Keys: encryptedKeys,
		}
	}

	return results, nil
}

// encryptNameForNodeAccounts encrypts the name for every account and returns a list of ExistingNameMemberRequests.
func encryptNameForNodeAccounts(nodeID *uuid.UUID, name string, accounts ...*api.Account) ([]api.EncryptedNameForNodeRequest, error) {
	encryptedNames, err := encryptNameForAccounts(name, accounts...)
	if err != nil {
		return nil, err
	}

	encryptedExistingNames := make([]api.EncryptedNameForNodeRequest, len(encryptedNames))
	for index, encryptedName := range encryptedNames {
		encryptedExistingNames[index] = api.EncryptedNameForNodeRequest{
			EncryptedNameRequest: api.EncryptedNameRequest{
				AccountID:     encryptedName.AccountID,
				EncryptedName: encryptedName.EncryptedName,
			},
			NodeID: nodeID,
		}
	}

	return encryptedExistingNames, nil
}

// encryptNameForAccounts encrypts the name for every account and returns a list of EncryptedNameRequests.
func encryptNameForAccounts(name string, accounts ...*api.Account) ([]api.EncryptedNameRequest, error) {
	encryptedNames := make([]api.EncryptedNameRequest, len(accounts))
	for i, account := range accounts {
		publicKey, err := crypto.ImportRSAPublicKey(account.PublicKey)
		if err != nil {
			return nil, errio.Error(err)
		}

		encryptedSecretName, err := crypto.EncryptRSA([]byte(name), publicKey)
		if err != nil {
			return nil, errio.Error(err)
		}

		encodedSecretName, err := api.EncodeCiphertext(encryptedSecretName)
		if err != nil {
			return nil, errio.Error(err)
		}

		encryptedNames[i] = api.EncryptedNameRequest{
			AccountID:     account.AccountID,
			EncryptedName: encodedSecretName,
		}
	}

	return encryptedNames, nil
}

// encryptKeyForAccounts encrypts the key for every account and returns a list of EncryptedKeyRequests
func encryptKeyForAccounts(key *crypto.AESKey, accounts ...*api.Account) ([]api.EncryptedKeyRequest, error) {
	encryptedKeys := make([]api.EncryptedKeyRequest, len(accounts))
	for i, account := range accounts {
		publicKey, err := crypto.ImportRSAPublicKey(account.PublicKey)
		if err != nil {
			return nil, errio.Error(err)
		}

		encryptedSecretKey, err := crypto.EncryptRSA(key.Export(), publicKey)
		if err != nil {
			return nil, errio.Error(err)
		}

		encodedSecretKey, err := api.EncodeCiphertext(encryptedSecretKey)
		if err != nil {
			return nil, errio.Error(err)
		}

		encryptedKeys[i] = api.EncryptedKeyRequest{
			AccountID:    account.AccountID,
			EncryptedKey: encodedSecretKey,
		}
	}

	return encryptedKeys, nil
}
