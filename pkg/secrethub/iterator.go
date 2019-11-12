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
	mutex        sync.Mutex
}

func newIterator(paginator paginator) iterator {
	return iterator{
		paginator:    paginator,
		currentIndex: 0,
		items:        nil,
		mutex:        sync.Mutex{},
	}
}

func (it *iterator) next() (interface{}, error) {
	it.mutex.Lock()
	if it.items == nil || (len(it.items) > 0 && len(it.items) <= it.currentIndex) {
		var err error
		it.items, err = it.paginator.Next()
		if err != nil {
			it.mutex.Unlock()
			return nil, err
		}
		it.currentIndex = 0
		it.mutex.Unlock()
		return it.next()
	}

	if len(it.items) == 0 {
		it.mutex.Unlock()
		return nil, IteratorDone
	}

	res := it.items[it.currentIndex]
	it.currentIndex++
	it.mutex.Unlock()
	return res, nil
}
