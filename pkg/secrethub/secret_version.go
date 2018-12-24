package secrethub

import (
	"fmt"

	"github.com/docker/go-units"
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/crypto"
	"github.com/keylockerbv/secrethub-go/pkg/errio"
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

// SecretVersionService handles operations on secret versions from SecretHub.
type SecretVersionService interface {
	// Delete removes a secret version.
	Delete(path api.SecretPath) error
	// GetWithData gets a secret version, with the sensitive data.
	GetWithData(path api.SecretPath) (*api.SecretVersion, error)
	// GetWithoutData gets a secret version, without the sensitive data.
	GetWithoutData(path api.SecretPath) (*api.SecretVersion, error)
	// ListWithData lists secret versions, with the sensitive data.
	ListWithData(path api.SecretPath) ([]*api.SecretVersion, error)
	// ListWithoutData lists secret versions, without the sensitive data.
	ListWithoutData(path api.SecretPath) ([]*api.SecretVersion, error)
}

type secretVersionService struct {
	client *Client
}

// Delete removes a secret version.
func (s secretVersionService) Delete(path api.SecretPath) error {
	return s.client.DeleteSecretVersion(path)
}

// GetWithData gets a secret version, with the sensitive data.
func (s secretVersionService) GetWithData(path api.SecretPath) (*api.SecretVersion, error) {
	return s.client.GetSecretVersionWithData(path)
}

// GetWithoutData gets a secret version, without the sensitive data.
func (s secretVersionService) GetWithoutData(path api.SecretPath) (*api.SecretVersion, error) {
	return s.client.GetSecretVersionWithoutData(path)
}

// ListWithData lists secret versions, with the sensitive data.
func (s secretVersionService) ListWithData(path api.SecretPath) ([]*api.SecretVersion, error) {
	return s.client.ListSecretVersions(path, true)
}

// ListWithoutData lists secret versions, without the sensitive data.
func (s secretVersionService) ListWithoutData(path api.SecretPath) ([]*api.SecretVersion, error) {
	return s.client.ListSecretVersions(path, false)
}

// Write encrypts and writes any secret data to SecretHub, always creating
// a new secret version for the written data. This ensures secret data is
// never overwritten.
//
// To ensure forward secrecy, a new secret key is used whenever the previously
// used key has been flagged.
//
// Write accepts any non-empty byte data that is within the size limit of MaxSecretSize.
// Note that data is encrypted as is. Sanitizing data is the responsibility of the
// function caller.
func (c *Client) Write(secretPath api.SecretPath, data []byte) (*api.SecretVersion, error) {

	if len(data) == 0 {
		return nil, ErrEmptySecret
	}

	if len(data) > MaxSecretSize {
		return nil, ErrSecretTooBig
	}

	if secretPath.HasVersion() {
		return nil, ErrCannotWriteToVersion
	}

	key, err := c.GetSecretKey(secretPath)
	if err == api.ErrSecretNotFound {
		return c.createSecret(secretPath, data)
	} else if err == api.ErrNoOKSecretKey {
		key, err = c.CreateSecretKey(secretPath)
		if err != nil {
			return nil, errio.Error(err)
		}
	} else if err != nil {
		return nil, errio.Error(err)
	}

	return c.createSecretVersion(secretPath, data, key)
}

// createSecretVersion creates a new version of an existing secret.
// It creates a new secret key if the provided key is flagged.
func (c *Client) createSecretVersion(secretPath api.SecretPath, data []byte, secretKey *api.SecretKey) (*api.SecretVersion, error) {
	var err error
	if secretKey.Status == api.StatusFlagged {
		secretKey, err = c.CreateSecretKey(secretPath)
		if err != nil {
			return nil, errio.Error(err)
		}
	}

	encryptedData, err := crypto.EncryptAES(data, secretKey.Key)
	if err != nil {
		return nil, errio.Error(err)
	}

	encodedData, err := api.EncodeCiphertext(encryptedData)
	if err != nil {
		return nil, errio.Error(err)
	}

	in := &api.CreateSecretVersionRequest{
		EncryptedData: encodedData,
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

	secretKey, err := crypto.GenerateAESKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	// Get all accounts that have permission to read the secret.
	accounts, err := c.ListDirAccounts(parentPath)
	if err != nil {
		return nil, errio.Error(err)
	}

	encryptedNames, err := encryptNameForAccounts(secretPath.GetSecret(), accounts...)
	if err != nil {
		return nil, errio.Error(err)
	}

	encryptedKeys, err := encryptKeyForAccounts(secretKey, accounts...)
	if err != nil {
		return nil, errio.Error(err)
	}

	encryptedData, err := crypto.EncryptAES(data, secretKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	encodedData, err := api.EncodeCiphertext(encryptedData)
	if err != nil {
		return nil, errio.Error(err)
	}

	blindName, err := c.convertPathToBlindName(secretPath)
	if err != nil {
		return nil, errio.Error(err)
	}

	in := &api.CreateSecretRequest{
		BlindName:     blindName,
		EncryptedData: encodedData,

		EncryptedNames: encryptedNames,
		EncryptedKeys:  encryptedKeys,
	}

	parentBlindName, err := c.convertPathToBlindName(parentPath)
	if err != nil {
		return nil, errio.Error(err)
	}

	resp, err := c.httpClient.CreateSecret(secretPath.GetNamespace(), secretPath.GetRepo(), parentBlindName, in)
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKey, err := c.getAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	return resp.Decrypt(accountKey)
}

// ListSecretVersions lists all versions of a secret by a given path, ordered oldest first.
func (c *Client) ListSecretVersions(path api.SecretPath, withData bool) ([]*api.SecretVersion, error) {
	blindName, err := c.convertPathToBlindName(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	versions, err := c.httpClient.ListSecretVersions(blindName, withData)
	if err != nil {
		return nil, errio.Error(err)
	}

	return c.decryptSecretVersions(versions...)
}

// DeleteSecretVersion deletes a specific version of a secret.
// If the given version is :latest, it will delete the latest version.
func (c *Client) DeleteSecretVersion(secretPath api.SecretPath) error {
	version, err := secretPath.GetVersion()
	if err != nil {
		return errio.Error(err)
	}

	err = api.ValidateSecretName(secretPath.GetSecret())
	if err != nil {
		return errio.Error(err)
	}

	secretBlindName, err := c.convertPathToBlindName(secretPath)
	if err != nil {
		return errio.Error(err)
	}

	err = c.httpClient.DeleteSecretVersion(secretBlindName, version)
	if err != nil {
		return errio.Error(err)
	}

	return nil
}

// ExistsSecretVersion checks if a secret version exists on SecretHub.
func (c *Client) ExistsSecretVersion(path api.SecretPath) (bool, error) {
	_, err := c.GetSecretVersionWithoutData(path)
	if err == api.ErrSecretVersionNotFound || err == api.ErrSecretNotFound {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

// GetSecretVersionWithData gets a secret version, with the sensitive data.
func (c *Client) GetSecretVersionWithData(secretPath api.SecretPath) (*api.SecretVersion, error) {
	return c.GetSecretVersion(secretPath, true)
}

// GetSecretVersionWithoutData gets a secret version, without the sensitive data.
// This is useful for inspecting a secret version.
func (c *Client) GetSecretVersionWithoutData(secretPath api.SecretPath) (*api.SecretVersion, error) {
	return c.GetSecretVersion(secretPath, false)
}

// GetSecretVersion gets a version of a secret.
// withData specifies whether the encrypted data should be retrieved.
func (c *Client) GetSecretVersion(path api.SecretPath, withData bool) (*api.SecretVersion, error) {
	blindName, err := c.convertPathToBlindName(path)
	if err != nil {
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

	encVersion, err := c.httpClient.GetSecretVersion(blindName, versionParam, withData)
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKey, err := c.getAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	secretVersion, err := encVersion.Decrypt(accountKey)
	return secretVersion, errio.Error(err)
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
