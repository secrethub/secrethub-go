package secrethub

import (
	"strings"

	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/errio"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

// SecretService handles operations on secrets from SecretHub.
type SecretService interface {
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
	Write(path string, data []byte) (*api.SecretVersion, error)
	// Read is an alias of `Versions().GetWithData` and gets a secret version, with sensitive data decrypted.
	Read(path string) (*api.SecretVersion, error)
	// ReadString is a convenience function to get the secret data as a string.
	//
	// See .Versions() for more elaborate use.
	ReadString(path string) (string, error)
	// Exists returns whether a secret exists on the given path.
	Exists(path string) (bool, error)
	// Get retrieves a Secret.
	Get(path string) (*api.Secret, error)
	// Delete removes the secret at the given path.
	Delete(path string) error
	// EventIterator returns an iterator that retrieves all audit events for a given secret.
	//
	// Usage:
	//  iter := client.Repos().EventIterator(path, &secrethub.AuditEventIteratorParams{})
	//  for {
	//  	event, err := iter.Next()
	//  	if err == iterator.Done {
	//  		break
	//  	} else if err != nil {
	//  		// Handle error
	//  	}
	//
	//  	// Use event
	//  }
	EventIterator(path string, _ *AuditEventIteratorParams) AuditEventIterator
	// ListEvents retrieves all audit events for a given secret.
	ListEvents(path string, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error)
	// Versions returns a SecretVersionService.
	Versions() SecretVersionService
	// Resolve fetches the value of a secret, when the `ref` parameter has the
	// format `secrethub://<path>`. Otherwise it returns `ref` unchanged, as an array of bytes.
	Resolve(ref string) ([]byte, error)
	// ResolveEnv takes a map of environment variables and replaces the values of those
	// which store references of secrets in SecretHub (`secrethub://<path>`) with the value
	// of the respective secret. The other entries in the map remain untouched.
	ResolveEnv(envVars []string) (map[string]string, error)
}

func newSecretService(client *Client) SecretService {
	return secretService{
		client: client,
	}
}

type secretService struct {
	client *Client
}

// Delete removes the secret at the given path.
func (s secretService) Delete(path string) error {
	secretPath, err := api.NewSecretPath(path)
	if err != nil {
		return errio.Error(err)
	}

	secretBlindName, err := s.client.convertPathToBlindName(secretPath)
	if err != nil {
		return errio.Error(err)
	}

	err = s.client.httpClient.DeleteSecret(secretBlindName)
	if err != nil {
		return errio.Error(err)
	}

	return nil
}

// Exists returns whether a secret exists on the given path.
func (s secretService) Exists(path string) (bool, error) {
	secretPath, err := api.NewSecretPath(path)
	if err != nil {
		return false, errio.Error(err)
	}

	blindName, err := s.client.convertPathToBlindName(secretPath)
	if err != nil {
		return false, errio.Error(err)
	}

	_, err = s.client.httpClient.GetSecret(blindName)
	if api.IsErrNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

// Get retrieves a Secret.
func (s secretService) Get(path string) (*api.Secret, error) {
	secretPath, err := api.NewSecretPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	blindName, err := s.client.convertPathToBlindName(secretPath)
	if api.IsErrNotFound(err) {
		return nil, &errSecretNotFound{path: secretPath, err: err}
	} else if err != nil {
		return nil, errio.Error(err)
	}

	encSecret, err := s.client.httpClient.GetSecret(blindName)
	if api.IsErrNotFound(err) {
		return nil, &errSecretNotFound{path: secretPath, err: err}
	} else if err != nil {
		return nil, errio.Error(err)
	}

	accountKey, err := s.client.getAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	return encSecret.Decrypt(accountKey)
}

// Read gets a secret version, with sensitive data decrypted.
func (s secretService) Read(path string) (*api.SecretVersion, error) {
	return s.Versions().GetWithData(path)
}

// ReadString gets the secret data as a string.
func (s secretService) ReadString(path string) (string, error) {
	secret, err := s.Read(path)
	if err != nil {
		return "", err
	}
	return string(secret.Data), nil
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
func (s secretService) Write(path string, data []byte) (*api.SecretVersion, error) {
	secretPath, err := api.NewSecretPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	if secretPath.HasVersion() {
		return nil, ErrCannotWriteToVersion
	}

	if len(data) == 0 {
		return nil, ErrEmptySecret
	}

	if len(data) > MaxSecretSize {
		return nil, ErrSecretTooBig
	}

	key, err := s.client.getSecretKey(secretPath)
	if err == api.ErrSecretNotFound {
		return s.client.createSecret(secretPath, data)
	} else if err == api.ErrNoOKSecretKey {
		key, err = s.client.createSecretKey(secretPath)
		if err != nil {
			return nil, errio.Error(err)
		}
	} else if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.createSecretVersion(secretPath, data, key)
}

// ListEvents retrieves all audit events for a given secret.
// If subjectTypes is left empty, the server's default is used.
func (s secretService) ListEvents(path string, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error) {
	secretPath, err := api.NewSecretPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	blindName, err := s.client.convertPathToBlindName(secretPath)
	if err != nil {
		return nil, errio.Error(err)
	}

	events, err := s.client.httpClient.AuditSecret(blindName, subjectTypes)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = s.client.decryptAuditEvents(events...)
	if err != nil {
		return nil, errio.Error(err)
	}

	return events, nil
}

// EventIterator returns an iterator that retrieves all audit events for a given secret.
//
// Usage:
//  iter := client.Repos().EventIterator(path, &secrethub.AuditEventIteratorParams{})
//  for {
//  	event, err := iter.Next()
//  	if err == iterator.Done {
//  		break
//  	} else if err != nil {
//  		// Handle error
//  	}
//
//  	// Use event
//  }
func (s secretService) EventIterator(path string, _ *AuditEventIteratorParams) AuditEventIterator {
	return newAuditEventIterator(
		func() (*http.AuditPaginator, error) {
			secretPath, err := api.NewSecretPath(path)
			if err != nil {
				return nil, err
			}

			blindName, err := s.client.convertPathToBlindName(secretPath)
			if err != nil {
				return nil, err
			}

			return s.client.httpClient.AuditSecretPaginator(blindName), nil
		},
		s.client,
	)
}

// Versions returns a SecretVersionService.
func (s secretService) Versions() SecretVersionService {
	return newSecretVersionService(s.client)
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

// Resolve fetches the value of a secret, when the `ref` parameter has the
// format `secrethub://<path>`. Otherwise it returns `ref` unchanged, as an array of bytes.
func (s secretService) Resolve(ref string) ([]byte, error) {
	bits := strings.Split(ref, "://")
	if len(bits) == 2 && strings.ToLower(bits[0]) == "secrethub" {
		secret, err := s.Read(bits[1])
		if err != nil {
			return []byte{}, err
		}
		return secret.Data, nil
	}
	return []byte(ref), nil
}

// ResolveEnv takes a map of environment variables and replaces the values of those
// which store references of secrets in SecretHub (`secrethub://<path>`) with the value
// of the respective secret. The other entries in the map remain untouched.
func (s secretService) ResolveEnv(envVars []string) (map[string]string, error) {
	resolvedEnv := make(map[string]string, len(envVars))
	for _, value := range envVars {
		keyValue := strings.Split(value, "=")
		secretValue, err := s.Resolve(keyValue[1])
		if err != nil {
			return map[string]string{}, err
		}
		resolvedEnv[keyValue[0]] = string(secretValue)
	}
	return resolvedEnv, nil
}
