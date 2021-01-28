package secrethub

import (
	"fmt"

	units "github.com/docker/go-units"
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/internals/errio"
	"github.com/secrethub/secrethub-go/pkg/secrethub/iterator"
)

const (
	// MaxSecretSize is the maximum size of a secret before encryption.
	MaxSecretSize = 512 * units.KiB
)

// Errors
var (
	ErrSecretTooBig         = errClient.Code("secret_too_big").Error(fmt.Sprintf("maximum size of a secret is %s", units.BytesSize(MaxSecretSize)))
	ErrEmptySecret          = errClient.Code("empty_secret").Error("secret is empty")
	ErrCannotWriteToVersion = errClient.Code("cannot_write_version").Error("cannot (over)write a specific secret version, they are append only")
)

type errSecretNotFound struct {
	path api.SecretPath
	err  error
}

func (e *errSecretNotFound) Error() string {
	return fmt.Sprintf("cannot find secret: \"%s\": %v", e.path, e.err)
}

func (e *errSecretNotFound) Unwrap() error {
	return e.err
}

// SecretVersionService handles operations on secret versions from SecretHub.
type SecretVersionService interface {
	// GetWithData gets a secret version, with the sensitive data.
	GetWithData(path string) (*api.SecretVersion, error)
	// GetWithoutData gets a secret version, without the sensitive data.
	GetWithoutData(path string) (*api.SecretVersion, error)
	// Delete removes a secret version.
	Delete(path string) error
	// ListWithData lists secret versions, with the sensitive data.
	// Deprecated: Use iterator function instead.
	ListWithData(path string) ([]*api.SecretVersion, error)
	// ListWithoutData lists secret versions, without the sensitive data.
	// Deprecated: Use iterator function instead.
	ListWithoutData(path string) ([]*api.SecretVersion, error)
	// Iterator returns a new iterator that retrieves all secret versions in the given namespace.
	// If the IncludeSensitiveData parameter is set to true, the secret data will also be retrieved.
	Iterator(path string, params *SecretVersionIteratorParams) SecretVersionIterator
}

func newSecretVersionService(client *Client) SecretVersionService {
	return secretVersionService{
		client: client,
	}
}

type secretVersionService struct {
	client *Client
}

// Delete removes a secret version.
func (s secretVersionService) Delete(path string) error {
	secretPath, err := api.NewSecretPath(path)
	if err != nil {
		return errio.Error(err)
	}

	version, err := secretPath.GetVersion()
	if err != nil {
		return errio.Error(err)
	}

	secretBlindName, err := s.client.convertPathToBlindName(secretPath)
	if err != nil {
		return errio.Error(err)
	}

	err = s.client.httpClient.DeleteSecretVersion(secretBlindName, version)
	if err != nil {
		return errio.Error(err)
	}

	return nil
}

// get gets a version of a secret. withData specifies whether the encrypted data should be retrieved.
func (s secretVersionService) get(path api.SecretPath, withData bool) (*api.SecretVersion, error) {
	blindName, err := s.client.convertPathToBlindName(path)
	if api.IsErrNotFound(err) {
		return nil, &errSecretNotFound{path: path, err: err}
	} else if err != nil {
		return nil, errio.Error(err)
	}

	var versionParam string
	if path.HasVersion() {
		versionParam, err = path.GetVersion()
		if err != nil {
			return nil, errio.Error(err)
		}
	} else {
		versionParam = "latest"
	}

	encVersion, err := s.client.httpClient.GetSecretVersion(blindName, versionParam, withData)
	if api.IsErrNotFound(err) {
		return nil, &errSecretNotFound{path: path, err: err}
	} else if err != nil {
		return nil, errio.Error(err)
	}

	accountKey, err := s.client.getAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	secretVersion, err := encVersion.Decrypt(accountKey)
	return secretVersion, errio.Error(err)
}

// GetWithData gets a secret version, with the sensitive data.
func (s secretVersionService) GetWithData(path string) (*api.SecretVersion, error) {
	secretPath, err := api.NewSecretPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.get(secretPath, true)
}

// GetWithoutData gets a secret version, without the sensitive data.
func (s secretVersionService) GetWithoutData(path string) (*api.SecretVersion, error) {
	secretPath, err := api.NewSecretPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.get(secretPath, false)
}

func (s secretVersionService) list(path api.SecretPath, withData bool) ([]*api.SecretVersion, error) {
	blindName, err := s.client.convertPathToBlindName(path)
	if api.IsErrNotFound(err) {
		return nil, &errSecretNotFound{path: path, err: err}
	} else if err != nil {
		return nil, errio.Error(err)
	}

	versions, err := s.client.httpClient.ListSecretVersions(blindName, withData)
	if api.IsErrNotFound(err) {
		return nil, &errSecretNotFound{path: path, err: err}
	} else if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.decryptSecretVersions(versions...)
}

// ListWithData lists secret versions, with the sensitive data.
func (s secretVersionService) ListWithData(path string) ([]*api.SecretVersion, error) {
	secretPath, err := api.NewSecretPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.list(secretPath, true)
}

// ListWithoutData lists secret versions, without the sensitive data.
func (s secretVersionService) ListWithoutData(path string) ([]*api.SecretVersion, error) {
	secretPath, err := api.NewSecretPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.list(secretPath, false)
}

// createSecretVersion creates a new version of an existing secret.
// The provided key should not be a flagged key. When it is,
// createSecretVersion will return an error.
func (c *Client) createSecretVersion(secretPath api.SecretPath, data []byte, secretKey *api.SecretKey) (*api.SecretVersion, error) {
	var err error
	encryptedData, err := secretKey.Key.Encrypt(data)
	if err != nil {
		return nil, errio.Error(err)
	}

	in := &api.CreateSecretVersionRequest{
		EncryptedData: encryptedData,
		SecretKeyID:   secretKey.SecretKeyID,
	}

	blindName, err := c.convertPathToBlindName(secretPath)
	if err != nil {
		return nil, errio.Error(err)
	}

	resp, err := c.httpClient.CreateSecretVersion(blindName, in)
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKey, err := c.getAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	return resp.Decrypt(accountKey)
}

// createSecret creates a new secret, including its first version.
// It generates a secret key, encrypts the key and the secret name
// for the accounts that need access to the secret.
func (c *Client) createSecret(secretPath api.SecretPath, data []byte) (*api.SecretVersion, error) {
	parentPath, err := secretPath.GetParentPath()
	if err != nil {
		return nil, errio.Error(err)
	}

	secretKey, err := crypto.GenerateSymmetricKey()
	if err != nil {
		return nil, errio.Error(err)
	}
	encryptedData, err := secretKey.Encrypt(data)
	if err != nil {
		return nil, errio.Error(err)
	}

	blindName, err := c.convertPathToBlindName(secretPath)
	if err != nil {
		return nil, errio.Error(err)
	}

	parentBlindName, err := c.convertPathToBlindName(parentPath)
	if err != nil {
		return nil, errio.Error(err)
	}

	secretName := secretPath.GetSecret()

	encryptedNamesMap := make(map[uuid.UUID]api.EncryptedNameRequest)
	encryptedKeysMap := make(map[uuid.UUID]api.EncryptedKeyRequest)

	tries := 0
	for {
		// Get all accounts that have permission to read the secret.
		accounts, err := c.listDirAccounts(parentPath)
		if err != nil {
			return nil, errio.Error(err)
		}

		for _, account := range accounts {
			_, ok := encryptedNamesMap[account.AccountID]
			if !ok {
				encryptedName, err := encryptNameForAccount(secretName, account)
				if err != nil {
					return nil, err
				}
				encryptedNamesMap[account.AccountID] = encryptedName
			}

			_, ok = encryptedKeysMap[account.AccountID]
			if !ok {
				encryptedKey, err := encryptKeyForAccount(secretKey, account)
				if err != nil {
					return nil, err
				}
				encryptedKeysMap[account.AccountID] = encryptedKey
			}
		}

		encryptedNames := make([]api.EncryptedNameRequest, len(encryptedNamesMap))
		i := 0
		for _, encryptedName := range encryptedNamesMap {
			encryptedNames[i] = encryptedName
			i++
		}

		encryptedKeys := make([]api.EncryptedKeyRequest, len(encryptedKeysMap))
		i = 0
		for _, encryptedKey := range encryptedKeysMap {
			encryptedKeys[i] = encryptedKey
			i++
		}

		in := &api.CreateSecretRequest{
			BlindName:     blindName,
			EncryptedData: encryptedData,

			EncryptedNames: encryptedNames,
			EncryptedKeys:  encryptedKeys,
		}

		resp, err := c.httpClient.CreateSecret(secretPath.GetNamespace(), secretPath.GetRepo(), parentBlindName, in)
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
			return nil, fmt.Errorf("cannot create secret version: access rules giving access to the secret are simultaneously being created; you may try again")
		}
		tries++
	}
}

// decryptSecretVersions decrypts EncryptedSecretVersions to a list of SecretVersions
func (c *Client) decryptSecretVersions(encVersions ...*api.EncryptedSecretVersion) ([]*api.SecretVersion, error) {
	accountKey, err := c.getAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	versions := make([]*api.SecretVersion, len(encVersions))
	for i, encVersion := range encVersions {
		version, err := encVersion.Decrypt(accountKey)
		if err != nil {
			return nil, errio.Error(err)
		}
		versions[i] = version
	}

	return versions, nil
}

// Iterator returns a new iterator that retrieves all secret versions in the given namespace.
// If the IncludeSensitiveData parameter is set to true, the secret data will also be retrieved.
func (s secretVersionService) Iterator(path string, params *SecretVersionIteratorParams) SecretVersionIterator {
	if params == nil {
		params = &SecretVersionIteratorParams{}
	}

	return &secretVersionIterator{
		iterator: iterator.New(
			iterator.PaginatorFactory(
				func() ([]interface{}, error) {
					secretPath, err := api.NewSecretPath(path)
					if err != nil {
						return nil, errio.Error(err)
					}

					secretVersions, err := s.list(secretPath, params.IncludeSensitiveData)
					if err != nil {
						return nil, err
					}

					res := make([]interface{}, len(secretVersions))
					for i, element := range secretVersions {
						res[i] = element
					}
					return res, nil
				},
			),
		),
	}
}

// SecretVersionIteratorParams defines parameters used when listing SecretVersions.
// If IncludeSensitiveData is set to true, secret data will also be retrieved.
type SecretVersionIteratorParams struct {
	IncludeSensitiveData bool
}

// SecretVersionIterator iterates over secret versions.
type SecretVersionIterator interface {
	Next() (api.SecretVersion, error)
}

type secretVersionIterator struct {
	iterator iterator.Iterator
}

// Next returns the next secret version or iterator.Done as an error if all of them have been returned.
func (it *secretVersionIterator) Next() (api.SecretVersion, error) {
	item, err := it.iterator.Next()
	if err != nil {
		return api.SecretVersion{}, err
	}

	return *item.(*api.SecretVersion), nil
}
