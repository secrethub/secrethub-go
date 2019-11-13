package secrethub

import (
	"sync"

	"github.com/secrethub/secrethub-go/internals/errio"
)

// Errors
var (
	IteratorDone = errio.Namespace("iterator").Code("done").Error("there are no more items left")
)

type paginator interface {
	Next() ([]interface{}, error)
}

type iterator struct {
	paginator    paginator
	currentIndex int
	items        []interface{}
	mutex        *sync.Mutex
}

func newIterator(paginator paginator) iterator {
	return iterator{
		paginator:    paginator,
		currentIndex: 0,
		items:        nil,
		mutex:        &sync.Mutex{},
	}
}

func (it *iterator) next() (interface{}, error) {
	it.mutex.Lock()
	defer it.mutex.Unlock()
	return it.nextUnsafe()
}

// nextUnsafe should only be called from one goroutine at a time,
// with the exception of nextUnsafe calling itself.
// Use next to enforce this.
func (it *iterator) nextUnsafe() (interface{}, error) {
	if it.items == nil || (len(it.items) > 0 && len(it.items) <= it.currentIndex) {
		var err error
		it.items, err = it.paginator.Next()
		if err != nil {
			return nil, err
		}
		it.currentIndex = 0
		return it.nextUnsafe()
	}

	if len(it.items) == 0 {
		return nil, IteratorDone
	}

	res := it.items[it.currentIndex]
	it.currentIndex++
	return res, nil
}
