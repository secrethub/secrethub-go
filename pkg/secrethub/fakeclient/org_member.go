// +build !production

package fakeclient

import "github.com/keylockerbv/secrethub-go/pkg/api"

// OrgMemberService is a mock of the OrgMemberService interface.
type OrgMemberService struct {
	Inviter OrgInviter
	Lister  OrgMemberLister
	Revoker OrgMemberRevoker
	Updater OrgMemberUpdater
}

// Invite implements the OrgMemberService interface Invite function.
func (s *OrgMemberService) Invite(org api.OrgName, username string, role string) (*api.OrgMember, error) {
	return s.Inviter.Invite(org, username, role)
}

// List implements the OrgMemberService interface List function.
func (s *OrgMemberService) List(name api.OrgName) ([]*api.OrgMember, error) {
	return s.Lister.List(name)
}

// Revoke implements the OrgMemberService interface Revoke function.
func (s *OrgMemberService) Revoke(name api.OrgName, username string, opts *api.RevokeOpts) (*api.RevokeOrgResponse, error) {
	return s.Revoker.Revoke(name, username, opts)
}

// Update implements the OrgMemberService interface Update function.
func (s *OrgMemberService) Update(orgName api.OrgName, username string, role string) (*api.OrgMember, error) {
	return s.Updater.Update(orgName, username, role)
}

// OrgInviter mocks the Invite function.
type OrgInviter struct {
	ArgOrg           api.OrgName
	ArgUsername      string
	ArgRole          string
	ReturnsOrgMember *api.OrgMember
	Err              error
}

// Invite saves the arguments it was called with and returns the mocked response.
func (l *OrgInviter) Invite(org api.OrgName, username string, role string) (*api.OrgMember, error) {
	l.ArgOrg = org
	l.ArgUsername = username
	l.ArgRole = role
	return l.ReturnsOrgMember, l.Err
}

// OrgMemberLister mocks the List function.
type OrgMemberLister struct {
	ArgName        api.OrgName
	ReturnsMembers []*api.OrgMember
	Err            error
}

// List saves the arguments it was called with and returns the mocked response.
func (l *OrgMemberLister) List(name api.OrgName) ([]*api.OrgMember, error) {
	l.ArgName = name
	return l.ReturnsMembers, l.Err
}

// OrgMemberRevoker mocks the Revoke function.
type OrgMemberRevoker struct {
	ArgOrgName               api.OrgName
	ArgUsername              string
	ArgOpts                  *api.RevokeOpts
	ReturnsRevokeOrgResponse *api.RevokeOrgResponse
	Err                      error
}

// Revoke saves the arguments it was called with and returns the mocked response.
func (r *OrgMemberRevoker) Revoke(orgName api.OrgName, username string, opts *api.RevokeOpts) (*api.RevokeOrgResponse, error) {
	r.ArgOrgName = orgName
	r.ArgUsername = username
	r.ArgOpts = opts
	return r.ReturnsRevokeOrgResponse, r.Err
}

// OrgMemberUpdater mocks the Update function.
type OrgMemberUpdater struct {
	ArgOrgName       api.OrgName
	ArgUsername      string
	ArgRole          string
	ReturnsOrgMember *api.OrgMember
	Err              error
}

// Update saves the arguments it was called with and returns the mocked response.
func (u *OrgMemberUpdater) Update(orgName api.OrgName, username string, role string) (*api.OrgMember, error) {
	u.ArgOrgName = orgName
	u.ArgUsername = username
	u.ArgRole = role
	return u.ReturnsOrgMember, u.Err
}
