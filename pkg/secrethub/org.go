package secrethub

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/errio"
)

// OrgService handles operations on organisations on SecretHub.
type OrgService interface {
	// Create creates an organization.
	Create(name api.OrgName, description string) (*api.Org, error)
	// Delete removes an organization.
	Delete(name api.OrgName) error
	// Get retrieves an organization.
	Get(name api.OrgName) (*api.Org, error)
	// Members returns an OrgMemberService.
	Members() OrgMemberService
	// ListMine returns the organizations of the current user.
	ListMine() ([]*api.Org, error)
}

type orgService struct {
	client *Client
}

// Create creates an organization and adds the current account as an admin member.
func (s *orgService) Create(name api.OrgName, description string) (*api.Org, error) {
	return s.client.CreateOrg(name.String(), description)
}

// Delete permanently deletes an organization and all of its resources.
func (s *orgService) Delete(name api.OrgName) error {
	return s.client.DeleteOrg(name.String())
}

// Get retrieves an organization.
func (s *orgService) Get(name api.OrgName) (*api.Org, error) {
	return s.client.GetOrg(name.String())
}

// Members returns an OrgMemberService.
func (s *orgService) Members() OrgMemberService {
	return &orgMemberService{
		client: s.client,
	}
}

// ListMine returns the organizations of the current user.
func (s *orgService) ListMine() ([]*api.Org, error) {
	return s.client.ListMyOrgs()
}

// CreateOrg creates an organization account and adds the current account as an Admin member.
func (c *Client) CreateOrg(name string, description string) (*api.Org, error) {
	in := &api.CreateOrgRequest{
		Name:        name,
		Description: description,
	}

	err := in.Validate()
	if err != nil {
		return nil, errio.Error(err)
	}

	return c.httpClient.CreateOrg(in)
}

// GetOrg gets an organization's details.
func (c *Client) GetOrg(name string) (*api.Org, error) {
	err := api.ValidateOrgName(name)
	if err != nil {
		return nil, errio.Error(err)
	}

	return c.httpClient.GetOrg(name)
}

// ListMyOrgs lists the organizations an account is a member of.
func (c *Client) ListMyOrgs() ([]*api.Org, error) {
	return c.httpClient.ListMyOrgs()
}

// DeleteOrg permanently deletes an organization and all of its resources.
func (c *Client) DeleteOrg(name string) error {
	err := api.ValidateOrgName(name)
	if err != nil {
		return errio.Error(err)
	}

	return c.httpClient.DeleteOrg(name)
}

// GetOrgMember gets a user's organization membership details.
func (c *Client) GetOrgMember(name string, username string) (*api.OrgMember, error) {
	err := api.ValidateOrgName(name)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = api.ValidateUsername(username)
	if err != nil {
		return nil, errio.Error(err)
	}

	return c.httpClient.GetOrgMember(name, username)
}

// ListOrgMembers lists all members of an organization.
func (c *Client) ListOrgMembers(name string) ([]*api.OrgMember, error) {
	err := api.ValidateOrgName(name)
	if err != nil {
		return nil, errio.Error(err)
	}

	return c.httpClient.ListOrgMembers(name)
}

// InviteOrg invites a user to an organization.
func (c *Client) InviteOrg(name string, username string, role string) (*api.OrgMember, error) {
	err := api.ValidateOrgName(name)
	if err != nil {
		return nil, errio.Error(err)
	}

	in := &api.CreateOrgMemberRequest{
		Username: username,
		Role:     role,
	}

	return c.httpClient.CreateOrgMember(name, in)
}

// UpdateOrgMember updates a user's organization membership.
func (c *Client) UpdateOrgMember(name string, username string, role string) (*api.OrgMember, error) {
	err := api.ValidateOrgName(name)
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

	return c.httpClient.UpdateOrgMember(name, username, in)
}

// RevokeOrgMember revokes a member from an organization.
// Have a look at the opts for this call.
func (c *Client) RevokeOrgMember(name string, username string, opts *api.RevokeOpts) (*api.RevokeOrgResponse, error) {
	err := api.ValidateOrgName(name)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = api.ValidateUsername(username)
	if err != nil {
		return nil, errio.Error(err)
	}

	return c.httpClient.RevokeOrgMember(name, username, opts)
}
