package secrethub

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub/core/errio"
)

// ListAuditEventsRepo retrieves all Audit events for a given repo.
// If subjectTypes is left empty, the server's default is used.
func (c *Client) ListAuditEventsRepo(repoPath api.RepoPath, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error) {
	namespace, repoName := repoPath.GetNamespaceAndRepoName()
	events, err := c.httpClient.AuditRepo(namespace, repoName, subjectTypes)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = c.decryptAuditEvents(events...)
	if err != nil {
		return nil, errio.Error(err)
	}

	return events, nil
}

// ListAuditEventsSecret retrieves all Audit events for a given secret.
// If subjectTypes is left empty, the server's default is used.
func (c *Client) ListAuditEventsSecret(secretPath api.SecretPath, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error) {
	blindName, err := c.convertPathToBlindName(secretPath)
	if err != nil {
		return nil, errio.Error(err)
	}

	events, err := c.httpClient.AuditSecret(blindName, subjectTypes)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = c.decryptAuditEvents(events...)
	if err != nil {
		return nil, errio.Error(err)
	}

	return events, nil
}

func (c *Client) decryptAuditEvents(events ...*api.Audit) error {
	accountKey, err := c.getAccountKey()
	if err != nil {
		return errio.Error(err)
	}

	// Decrypt all Secret names
	for _, event := range events {
		if event.Subject.Deleted {
			continue
		}

		if event.Subject.Type == api.AuditSubjectSecret || event.Subject.Type == api.AuditSubjectSecretMember {
			event.Subject.Secret, err = event.Subject.EncryptedSecret.Decrypt(accountKey)
			if err != nil {
				return errio.Error(err)
			}
		} else if event.Subject.Type == api.AuditSubjectSecretVersion {
			event.Subject.SecretVersion, err = event.Subject.EncryptedSecretVersion.Decrypt(accountKey)
			if err != nil {
				return errio.Error(err)
			}
		}
	}

	return nil
}
