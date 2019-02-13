package secrethub

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/errio"
)

// OrgMemberService handles operations on organization members.
type OrgMemberService interface {
	// Get retrieves a users organization membership details.
	Get(org api.OrgName, username string) (*api.OrgMember, error)
	// Invite invites a user to an organization.
	Invite(org api.OrgName, username string, role string) (*api.OrgMember, error)
	// List retrieves all members of the given organization.
	List(name api.OrgName) ([]*api.OrgMember, error)
	// Revoke removes the given user from the organization.
	Revoke(name api.OrgName, username string, opts *api.RevokeOpts) (*api.RevokeOrgResponse, error)
	// Update updates the role of a member of the organization.
	Update(name api.OrgName, username string, role string) (*api.OrgMember, error)
}

func newOrgMemberService(client client) OrgMemberService {
	return orgMemberService{
		client: client,
	}
}

type orgMemberService struct {
	client client
}

// Get retrieves a users organization membership details.
func (s orgMemberService) Get(org api.OrgName, username string) (*api.OrgMember, error) {
	err := api.ValidateUsername(username)
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.httpClient.GetOrgMember(org.String(), username)
}

// Invite invites a user to an organization.
func (s orgMemberService) Invite(org api.OrgName, username string, role string) (*api.OrgMember, error) {
	in := &api.CreateOrgMemberRequest{
		Username: username,
		Role:     role,
	}

	return s.client.httpClient.CreateOrgMember(org.String(), in)
}

// List retrieves all members of the given organization.
func (s orgMemberService) List(name api.OrgName) ([]*api.OrgMember, error) {
	return s.client.httpClient.ListOrgMembers(name.String())
}

// Revoke removes the given user from the organization.
func (s orgMemberService) Revoke(name api.OrgName, username string, opts *api.RevokeOpts) (*api.RevokeOrgResponse, error) {
	err := api.ValidateUsername(username)
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.httpClient.RevokeOrgMember(name.String(), username, opts)
}

// Update updates the role of a member of the organization.
func (s orgMemberService) Update(org api.OrgName, username string, role string) (*api.OrgMember, error) {
	err := api.ValidateUsername(username)
	if err != nil {
		return nil, errio.Error(err)
	}

	in := &api.UpdateOrgMemberRequest{
		Role: role,
	}

	return s.client.httpClient.UpdateOrgMember(org.String(), username, in)
}
