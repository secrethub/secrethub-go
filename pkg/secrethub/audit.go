package secrethub

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/internals/errio"
)

func (c *client) decryptAuditEvents(events ...*api.Audit) error {
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
