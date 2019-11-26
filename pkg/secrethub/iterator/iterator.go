// Package iterator provides a generic iterator to be used as a building block for typed iterators.
// In your applications, use the typed iterators returned by the secrethub package.
package iterator

import (
	"sync"

	"github.com/secrethub/secrethub-go/internals/errio"
)

// Errors
var (
	Done = errio.Namespace("iterator").Code("done").Error("there are no more items left")
)

type Paginator interface {
	Next() ([]interface{}, error)
}

type PaginatorConstructor func() (Paginator, error)

type Iterator struct {
	newPaginator PaginatorConstructor
	paginator    Paginator
	currentIndex int
	items        []interface{}
	mutex        *sync.Mutex
}

func New(newPaginator PaginatorConstructor) Iterator {
	return Iterator{
		newPaginator: newPaginator,
		currentIndex: 0,
		items:        nil,
		mutex:        &sync.Mutex{},
	}
}

func (it *Iterator) Next() (interface{}, error) {
	it.mutex.Lock()
	defer it.mutex.Unlock()

	var err error
	if it.paginator == nil {
		it.paginator, err = it.newPaginator()
		if err != nil {
			return nil, err
		}
	}

	return it.nextUnsafe()
}

// nextUnsafe should only be called from one goroutine at a time,
// with the exception of nextUnsafe calling itself.
// Use Next to enforce this.
func (it *Iterator) nextUnsafe() (interface{}, error) {
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
		return nil, Done
	}

	res := it.items[it.currentIndex]
	it.currentIndex++
	return res, nil
}
