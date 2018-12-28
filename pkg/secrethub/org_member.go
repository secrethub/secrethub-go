package secrethub

import "github.com/keylockerbv/secrethub-go/pkg/api"

// OrgMemberService handles operations on organization members.
type OrgMemberService interface {
	// Invite invites a user to an organization.
	Invite(org api.OrgName, username string, role string) (*api.OrgMember, error)
	// List retrieves all members of the given organization.
	List(name api.OrgName) ([]*api.OrgMember, error)
	// Revoke removes the given user from the organization.
	Revoke(name api.OrgName, username string, opts *api.RevokeOpts) (*api.RevokeOrgResponse, error)
	// Update updates the role of a member of the organization.
	Update(name api.OrgName, username string, role string) (*api.OrgMember, error)
}

type orgMemberService struct {
	client *client
}

// Invite invites a user to an organization.
func (s *orgMemberService) Invite(org api.OrgName, username string, role string) (*api.OrgMember, error) {
	return s.client.InviteOrg(org.String(), username, role)
}

// List retrieves all members of the given organization.
func (s *orgMemberService) List(name api.OrgName) ([]*api.OrgMember, error) {
	return s.client.ListOrgMembers(name.String())
}

// Revoke removes the given user from the organization.
func (s *orgMemberService) Revoke(name api.OrgName, username string, opts *api.RevokeOpts) (*api.RevokeOrgResponse, error) {
	return s.client.RevokeOrgMember(name.String(), username, opts)
}

// Update updates the role of a member of the organization.
func (s *orgMemberService) Update(org api.OrgName, username string, role string) (*api.OrgMember, error) {
	return s.client.UpdateOrgMember(org.String(), username, role)
}
