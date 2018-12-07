package secrethub

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub/core/errio"
)

// SecretService handles operations on secrets from SecretHub.
type SecretService interface {
	// Delete removes the secret at the given path.
	Delete(path api.SecretPath) error
	// Get retrieves a Secret.
	Get(path api.SecretPath) (*api.Secret, error)
	// ListEvents retrieves all audit events for a given secret.
	ListEvents(path api.SecretPath, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error)

	// Versions returns a SecretVersionService.
	Versions() SecretVersionService

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
	Write(secretPath api.SecretPath, data []byte) (*api.SecretVersion, error)
}

type secretService struct {
	client *Client
}

// Delete removes the secret at the given path.
func (s *secretService) Delete(path api.SecretPath) error {
	return s.client.DeleteSecret(path)
}

// Get retrieves a Secret.
func (s *secretService) Get(path api.SecretPath) (*api.Secret, error) {
	return s.client.GetSecret(path)
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
// TODO SHDEV-1027 Move client implementation here.
func (s *secretService) Write(secretPath api.SecretPath, data []byte) (*api.SecretVersion, error) {
	return s.client.Write(secretPath, data)
}

// ListEvents retrieves all audit events for a given secret.
// If subjectTypes is left empty, the server's default is used.
func (s *secretService) ListEvents(path api.SecretPath, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error) {
	return s.client.ListAuditEventsSecret(path, subjectTypes)
}

// Versions returns a SecretVersionService.
func (s *secretService) Versions() SecretVersionService {
	return &secretVersionService{
		client: s.client,
	}
}

// GetSecret gets a secret by a given path.
func (c *Client) GetSecret(path api.SecretPath) (*api.Secret, error) {
	blindName, err := c.convertPathToBlindName(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	encSecret, err := c.httpClient.GetSecret(blindName)
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKey, err := c.getAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	return encSecret.Decrypt(accountKey)
}

// DeleteSecret deletes a secret by a given path.
func (c *Client) DeleteSecret(secretPath api.SecretPath) error {
	err := api.ValidateSecretName(secretPath.GetSecret())
	if err != nil {
		return errio.Error(err)
	}

	secretBlindName, err := c.convertPathToBlindName(secretPath)
	if err != nil {
		return errio.Error(err)
	}

	err = c.httpClient.DeleteSecret(secretBlindName)
	if err != nil {
		return errio.Error(err)
	}

	return nil
}

// ExistsSecret checks if a secret already exists on SecretHub.
func (c *Client) ExistsSecret(path api.SecretPath) (bool, error) {
	_, err := c.GetSecret(path)
	if err == api.ErrSecretNotFound {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

// decryptSecrets decrypts EncryptedSecrets into a list of Secrets.
func (c *Client) decryptSecrets(encSecrets []*api.EncryptedSecret) ([]*api.Secret, error) {
	accountKey, err := c.getAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	secrets := make([]*api.Secret, len(encSecrets))
	for i, encSecret := range encSecrets {
		secret, err := encSecret.Decrypt(accountKey)
		if err != nil {
			return nil, errio.Error(err)
		}
		secrets[i] = secret
	}

	return secrets, nil
}

// convertsToBlindName will convert a path to a blindname.
func (c *Client) convertPathToBlindName(path api.BlindNamePath) (string, error) {
	repoIndexKey, err := c.getRepoIndexKey(path.GetRepoPath())
	if err != nil {
		return "", errio.Error(err)
	}

	blindName, err := path.BlindName(repoIndexKey)
	if err != nil {
		return "", errio.Error(err)
	}
	return blindName, nil
}
