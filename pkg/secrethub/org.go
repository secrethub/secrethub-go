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

func newOrgService(client client) OrgService {
	return orgService{
		client: client,
	}
}

type orgService struct {
	client client
}

// Create creates an organization and adds the current account as an admin member.
func (s orgService) Create(name api.OrgName, description string) (*api.Org, error) {
	in := &api.CreateOrgRequest{
		Name:        name.String(),
		Description: description,
	}

	err := in.Validate()
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.httpClient.CreateOrg(in)
}

// Delete permanently deletes an organization and all of its resources.
func (s orgService) Delete(name api.OrgName) error {
	return s.client.httpClient.DeleteOrg(name.String())
}

// Get retrieves an organization.
func (s orgService) Get(name api.OrgName) (*api.Org, error) {
	return s.client.httpClient.GetOrg(name.String())
}

// Members returns an OrgMemberService.
func (s orgService) Members() OrgMemberService {
	return newOrgMemberService(s.client)
}

// ListMine returns the organizations of the current user.
func (s orgService) ListMine() ([]*api.Org, error) {
	return s.client.httpClient.ListMyOrgs()
}
