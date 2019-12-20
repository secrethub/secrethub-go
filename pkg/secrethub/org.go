package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/errio"
	"github.com/secrethub/secrethub-go/pkg/secrethub/iterator"
)

// OrgService handles operations on organisations on SecretHub.
type OrgService interface {
	// Create creates an organization.
	Create(name string, description string) (*api.Org, error)
	// Get retrieves an organization.
	Get(name string) (*api.Org, error)
	// Members returns an OrgMemberService.
	Members() OrgMemberService
	// Delete removes an organization.
	Delete(name string) error
	// ListMine returns the organizations of the current user.
	ListMine() ([]*api.Org, error)
	// Iterator returns an iterator that lists all organizations of the current users.
	Iterator() OrgIterator
}

func newOrgService(client *Client) OrgService {
	return orgService{
		client: client,
	}
}

type orgService struct {
	client *Client
}

// Create creates an organization and adds the current account as an admin member.
func (s orgService) Create(name string, description string) (*api.Org, error) {
	in := &api.CreateOrgRequest{
		Name:        name,
		Description: description,
	}

	err := in.Validate()
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.httpClient.CreateOrg(in)
}

// Delete permanently deletes an organization and all of its resources.
func (s orgService) Delete(name string) error {
	err := api.ValidateOrgName(name)
	if err != nil {
		return errio.Error(err)
	}

	return s.client.httpClient.DeleteOrg(name)
}

// Get retrieves an organization.
func (s orgService) Get(name string) (*api.Org, error) {
	err := api.ValidateOrgName(name)
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.httpClient.GetOrg(name)
}

// Members returns an OrgMemberService.
func (s orgService) Members() OrgMemberService {
	return newOrgMemberService(s.client)
}

// ListMine returns the organizations of the current user.
func (s orgService) ListMine() ([]*api.Org, error) {
	return s.client.httpClient.ListMyOrgs()
}

// Iterator returns an iterator that lists all organizations of the current users.
func (s orgService) Iterator() OrgIterator {
	data, err := s.ListMine()
	return &orgIterator{
		index: 0,
		data:  data,
		err:   err,
	}
}

// RepoIteratorParams defines parameters used when listing repos.
type OrgIteratorParams struct{}

// RepoIterator iterates over repositories.
type OrgIterator interface {
	Next() (api.Org, error)
}

type orgIterator struct {
	index int
	data  []*api.Org
	err   error
}

// Next returns the next repo or iterator.Done as an error if there are no more repos.
func (it *orgIterator) Next() (api.Org, error) {
	if it.err != nil {
		return api.Org{}, it.err
	}
	if it.index >= len(it.data) {
		return api.Org{}, iterator.Done
	}

	element := *it.data[it.index]
	it.index++
	return element, nil
}
