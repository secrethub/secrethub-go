// +build !production

package fakeclient

import "github.com/keylockerbv/secrethub-go/internals/api"

// OrgMemberService is a mock of the OrgMemberService interface.
type OrgMemberService struct {
	Inviter OrgInviter
	Lister  OrgMemberLister
	Revoker OrgMemberRevoker
	Updater OrgMemberUpdater
}

// Get implements the OrgMemberService interface Get function.
func (s *OrgMemberService) Get(org string, username string) (*api.OrgMember, error) {
	return nil, nil
}

// Invite implements the OrgMemberService interface Invite function.
func (s *OrgMemberService) Invite(org string, username string, role string) (*api.OrgMember, error) {
	return s.Inviter.Invite(org, username, role)
}

// List implements the OrgMemberService interface List function.
func (s *OrgMemberService) List(name string) ([]*api.OrgMember, error) {
	return s.Lister.List(name)
}

// Revoke implements the OrgMemberService interface Revoke function.
func (s *OrgMemberService) Revoke(name string, username string, opts *api.RevokeOpts) (*api.RevokeOrgResponse, error) {
	return s.Revoker.Revoke(name, username, opts)
}

// Update implements the OrgMemberService interface Update function.
func (s *OrgMemberService) Update(orgName string, username string, role string) (*api.OrgMember, error) {
	return s.Updater.Update(orgName, username, role)
}

// OrgInviter mocks the Invite function.
type OrgInviter struct {
	ArgOrg           string
	ArgUsername      string
	ArgRole          string
	ReturnsOrgMember *api.OrgMember
	Err              error
}

// Invite saves the arguments it was called with and returns the mocked response.
func (l *OrgInviter) Invite(org string, username string, role string) (*api.OrgMember, error) {
	l.ArgOrg = org
	l.ArgUsername = username
	l.ArgRole = role
	return l.ReturnsOrgMember, l.Err
}

// OrgMemberLister mocks the List function.
type OrgMemberLister struct {
	ArgName        string
	ReturnsMembers []*api.OrgMember
	Err            error
}

// List saves the arguments it was called with and returns the mocked response.
func (l *OrgMemberLister) List(name string) ([]*api.OrgMember, error) {
	l.ArgName = name
	return l.ReturnsMembers, l.Err
}

// OrgMemberRevoker mocks the Revoke function.
type OrgMemberRevoker struct {
	ArgOrgName               string
	ArgUsername              string
	ArgOpts                  *api.RevokeOpts
	ReturnsRevokeOrgResponse *api.RevokeOrgResponse
	Err                      error
}

// Revoke saves the arguments it was called with and returns the mocked response.
func (r *OrgMemberRevoker) Revoke(orgName string, username string, opts *api.RevokeOpts) (*api.RevokeOrgResponse, error) {
	r.ArgOrgName = orgName
	r.ArgUsername = username
	r.ArgOpts = opts
	return r.ReturnsRevokeOrgResponse, r.Err
}

// OrgMemberUpdater mocks the Update function.
type OrgMemberUpdater struct {
	ArgOrgName       string
	ArgUsername      string
	ArgRole          string
	ReturnsOrgMember *api.OrgMember
	Err              error
}

// Update saves the arguments it was called with and returns the mocked response.
func (u *OrgMemberUpdater) Update(orgName string, username string, role string) (*api.OrgMember, error) {
	u.ArgOrgName = orgName
	u.ArgUsername = username
	u.ArgRole = role
	return u.ReturnsOrgMember, u.Err
}
