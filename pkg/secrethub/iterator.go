package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/errio"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

// Errors
var (
	IteratorDone = errio.Namespace("iterator").Code("done").Error("there are no more items left")
)

type iterator struct {
	pag          *http.Paginator
	currentIndex int
	items        []interface{}
}

func (it *iterator) next() (interface{}, error) {
	if it.items == nil || (len(it.items) > 0 && len(it.items) <= it.currentIndex) {
		var err error
		it.items, err = it.pag.Next()
		if err != nil {
			return nil, err
		}
		it.currentIndex = 0
		return it.next()
	}

	if len(it.items) == 0 {
		return nil, IteratorDone
	}

	res := it.items[it.currentIndex]
	it.currentIndex++
	return res, nil
}
