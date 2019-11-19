package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/errio"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
	"github.com/secrethub/secrethub-go/pkg/secrethub/iterator"
)

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

func newAuditEventIterator(paginator *http.AuditPaginator, client *Client) AuditEventIterator {
	return AuditEventIterator{
		iterator:           iterator.New(paginator),
		paginator:          paginator,
		decryptAuditEvents: client.decryptAuditEvents,
	}
}

type AuditEventIterator struct {
	iterator           iterator.Iterator
	decryptAuditEvents func(...*api.Audit) error
	paginator          *http.AuditPaginator
}

func (it *AuditEventIterator) Next() (api.Audit, error) {
	item, err := it.iterator.Next()
	if err != nil {
		return api.Audit{}, err
	}
	audit := item.(api.Audit)
	err = it.decryptAuditEvents(&audit)
	if err != nil {
		return api.Audit{}, err
	}
	return audit, nil
}

// AuditEventIteratorParams can be used to configure iteration of audit events.
//
// For now, there's nothing to configure. We'll add filter options soon.
// The struct is already added, so that adding parameters is backwards compatible.
type AuditEventIteratorParams struct{}
