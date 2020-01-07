package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/errio"
	"github.com/secrethub/secrethub-go/pkg/secrethub/iterator"
)

// OrgMemberService handles operations on organization members.
type OrgMemberService interface {
	// Invite invites a user to an organization.
	Invite(org string, username string, role string) (*api.OrgMember, error)
	// Get retrieves a users organization membership details.
	Get(org string, username string) (*api.OrgMember, error)
	// Update updates the role of a member of the organization.
	Update(org string, username string, role string) (*api.OrgMember, error)
	// Revoke removes the given user from the organization.
	Revoke(org string, username string, opts *api.RevokeOpts) (*api.RevokeOrgResponse, error)
	// List retrieves all members of the given organization.
	List(org string) ([]*api.OrgMember, error)
	// Iterator returns an iterator that lists all members of a given organization.
	Iterator(org string, _ *OrgMemberIteratorParams) OrgMemberIterator
}

func newOrgMemberService(client *Client) OrgMemberService {
	return orgMemberService{
		client: client,
	}
}

type orgMemberService struct {
	client *Client
}

// Get retrieves a users organization membership details.
func (s orgMemberService) Get(org string, username string) (*api.OrgMember, error) {
	err := api.ValidateOrgName(org)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = api.ValidateUsername(username)
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.httpClient.GetOrgMember(org, username)
}

// Invite invites a user to an organization.
func (s orgMemberService) Invite(org string, username string, role string) (*api.OrgMember, error) {
	err := api.ValidateOrgName(org)
	if err != nil {
		return nil, errio.Error(err)
	}

	in := &api.CreateOrgMemberRequest{
		Username: username,
		Role:     role,
	}

	err = in.Validate()
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.httpClient.CreateOrgMember(org, in)
}

// List retrieves all members of the given organization.
func (s orgMemberService) List(org string) ([]*api.OrgMember, error) {
	err := api.ValidateOrgName(org)
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.httpClient.ListOrgMembers(org)
}

// Revoke removes the given user from the organization.
func (s orgMemberService) Revoke(org string, username string, opts *api.RevokeOpts) (*api.RevokeOrgResponse, error) {
	err := api.ValidateOrgName(org)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = api.ValidateUsername(username)
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.httpClient.RevokeOrgMember(org, username, opts)
}

// Update updates the role of a member of the organization.
func (s orgMemberService) Update(org string, username string, role string) (*api.OrgMember, error) {
	err := api.ValidateOrgName(org)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = api.ValidateUsername(username)
	if err != nil {
		return nil, errio.Error(err)
	}

	in := &api.UpdateOrgMemberRequest{
		Role: role,
	}

	err = in.Validate()
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.httpClient.UpdateOrgMember(org, username, in)
}

// Iterator returns an iterator that lists all members of a given organization.
func (s orgMemberService) Iterator(org string, _ *OrgMemberIteratorParams) OrgMemberIterator {
	return &orgMemberIterator{
		iterator: iterator.New(
			iterator.PaginatorFactory(
				func() ([]interface{}, error) {
					err := api.ValidateOrgName(org)
					if err != nil {
						return nil, errio.Error(err)
					}

					orgMembers, err := s.client.httpClient.ListOrgMembers(org)
					if err != nil {
						return nil, err
					}

					res := make([]interface{}, len(orgMembers))
					for i, element := range orgMembers {
						res[i] = element
					}
					return res, nil
				},
			),
		),
	}
}

// OrgMemberIteratorParams defines parameters used when listing members of the organization.
type OrgMemberIteratorParams struct{}

// OrgMemberIterator iterates over organization members.
type OrgMemberIterator interface {
	Next() (api.OrgMember, error)
}

type orgMemberIterator struct {
	iterator iterator.Iterator
}

// Next returns the next organization member or iterator.Done as an error if all of them have been returned.
func (it *orgMemberIterator) Next() (api.OrgMember, error) {
	item, err := it.iterator.Next()
	if err != nil {
		return api.OrgMember{}, err
	}

	return item.(api.OrgMember), nil
}
