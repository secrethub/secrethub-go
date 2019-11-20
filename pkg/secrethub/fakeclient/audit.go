package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub/iterator"
)

type AuditEventIterator struct {
	Events []api.Audit
	Err    error
	i      int
}

func (iter *AuditEventIterator) Next() (api.Audit, error) {
	if iter.Err != nil {
		return api.Audit{}, iter.Err
	}

	if iter.i >= len(iter.Events) {
		return api.Audit{}, iterator.Done
	}
	res := iter.Events[iter.i]
	iter.i++
	return res, nil
}
