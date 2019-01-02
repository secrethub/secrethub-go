// +build !production

package fakeclient

import "github.com/keylockerbv/secrethub-go/pkg/api"

// OrgMemberService is a mock of the OrgMemberService interface.
type OrgMemberService struct {
	GetFunc    func(org api.OrgName, username string) (*api.OrgMember, error)
	InviteFunc func(org api.OrgName, username string, role string) (*api.OrgMember, error)
	ListFunc   func(name api.OrgName) ([]*api.OrgMember, error)
	RevokeFunc func(name api.OrgName, username string, opts *api.RevokeOpts) (*api.RevokeOrgResponse, error)
	UpdateFunc func(orgName api.OrgName, username string, role string) (*api.OrgMember, error)
}

// Get implements the OrgMemberService interface Get function.
func (s OrgMemberService) Get(org api.OrgName, username string) (*api.OrgMember, error) {
	return s.GetFunc(org, username)
}

// Invite implements the OrgMemberService interface Invite function.
func (s OrgMemberService) Invite(org api.OrgName, username string, role string) (*api.OrgMember, error) {
	return s.InviteFunc(org, username, role)
}

// List implements the OrgMemberService interface List function.
func (s OrgMemberService) List(name api.OrgName) ([]*api.OrgMember, error) {
	return s.ListFunc(name)
}

// Revoke implements the OrgMemberService interface Revoke function.
func (s OrgMemberService) Revoke(name api.OrgName, username string, opts *api.RevokeOpts) (*api.RevokeOrgResponse, error) {
	return s.RevokeFunc(name, username, opts)
}

// Update implements the OrgMemberService interface Update function.
func (s OrgMemberService) Update(orgName api.OrgName, username string, role string) (*api.OrgMember, error) {
	return s.UpdateFunc(orgName, username, role)
}
