package http

import (
	"net/url"
)

func NewPaginator(url url.URL, target interface{}, getStartingAfter func(interface{}) string, toItems func(interface{}) []interface{}, client *Client) *Paginator {
	return &Paginator{
		url:              &url,
		target:           target,
		getStartingAfter: getStartingAfter,
		toItems:          toItems,
		client:           client,
	}
}

type Paginator struct {
	url              *url.URL
	target           interface{}
	getStartingAfter func(interface{}) string
	toItems          func(interface{}) []interface{}

	client *Client
}

func (pag *Paginator) Next() ([]interface{}, error) {
	target := pag.target
	err := pag.client.get(pag.url.String(), true, target)
	if err != nil {
		return nil, err
	}

	items := pag.toItems(target)
	if len(items) > 0 {
		q := pag.url.Query()
		q.Set("starting_after", pag.getStartingAfter(target))
		pag.url.RawQuery = q.Encode()
	}

	return items, nil
}
