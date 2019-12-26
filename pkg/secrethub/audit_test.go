package secrethub

import (
	"testing"

	"github.com/gofrs/uuid"
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/assert"
	"github.com/secrethub/secrethub-go/pkg/secrethub/iterator"
)

type fakeAuditPaginator struct {
	events   []api.Audit
	returned bool
}

func (pag *fakeAuditPaginator) Next() ([]interface{}, error) {
	if pag.returned {
		return []interface{}{}, nil
	}

	res := make([]interface{}, len(pag.events))
	for i, event := range pag.events {
		res[i] = event
	}
	pag.returned = true
	return res, nil
}

func TestAuditEventIterator_Next(t *testing.T) {
	events := []api.Audit{
		{
			EventID: uuid.Must(uuid.NewV4()),
			Action:  api.AuditActionRead,
		},
	}

	iter := auditEventIterator{
		iterator: iterator.New(func() (iterator.Paginator, error) {
			return &fakeAuditPaginator{events: events}, nil
		}),
		decryptAuditEvents: func(audit ...*api.Audit) error {
			return nil
		},
	}

	for _, event := range events {
		actual, err := iter.Next()

		assert.Equal(t, err, nil)
		assert.Equal(t, actual, event)
	}
	_, err := iter.Next()
	assert.Equal(t, err, iterator.Done)
}
