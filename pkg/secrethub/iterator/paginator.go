package iterator

type paginator struct {
	fetched bool
	fetch   func() ([]interface{}, error)
}

// PaginatorFactory returns a paginator constructor that constructs a paginator
// with the provided fetch function.
func PaginatorFactory(fetch func() ([]interface{}, error)) PaginatorConstructor {
	return func() (Paginator, error) {
		return &paginator{
			fetched: false,
			fetch:   fetch,
		}, nil
	}
}

// Next returns the next page of items or an empty page if there are none left.
func (p *paginator) Next() ([]interface{}, error) {
	if p.fetched {
		return make([]interface{}, 0), nil
	}

	res, err := p.fetch()
	if err != nil {
		return nil, err
	}
	p.fetched = true
	return res, nil
}
