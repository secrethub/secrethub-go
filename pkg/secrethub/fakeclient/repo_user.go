// +build !production

package fakeclient

import "github.com/keylockerbv/secrethub-go/pkg/api"

// RepoUserService is a mock of the RepoUserService interface.
type RepoUserService struct {
	RepoInviter RepoInviter
	Lister      RepoUserLister
	Revoker     RepoRevoker
}

// Invite implements the RepoUserService interface Invite function.
func (s *RepoUserService) Invite(path string, username string) (*api.RepoMember, error) {
	return s.RepoInviter.Invite(path, username)
}

// List implements the RepoUserService interface List function.
func (s *RepoUserService) List(path string) ([]*api.User, error) {
	return s.Lister.List(path)
}

// Revoke implements the RepoUserService interface Revoke function.
func (s *RepoUserService) Revoke(path string, username string) (*api.RevokeRepoResponse, error) {
	return s.Revoker.Revoke(path, username)
}

// RepoUserLister mocks the List function.
type RepoUserLister struct {
	ArgPath      string
	ReturnsUsers []*api.User
	Err          error
}

// List saves the arguments it was called with and returns the mocked response.
func (l *RepoUserLister) List(path string) ([]*api.User, error) {
	l.ArgPath = path
	return l.ReturnsUsers, l.Err
}

// RepoInviter mocks the Invite function.
type RepoInviter struct {
	ArgPath           string
	ArgUsername       string
	ReturnsRepoMember *api.RepoMember
	Err               error
}

// Invite saves the arguments it was called with and returns the mocked response.
func (i *RepoInviter) Invite(path string, username string) (*api.RepoMember, error) {
	i.ArgPath = path
	i.ArgUsername = username
	return i.ReturnsRepoMember, i.Err
}

// RepoRevoker mocks the Revoke function.
type RepoRevoker struct {
	ArgPath               string
	ArgUsername           string
	ReturnsRevokeResponse *api.RevokeRepoResponse
	Err                   error
}

// Revoke saves the arguments it was called with and returns the mocked response.
func (r *RepoRevoker) Revoke(path string, username string) (*api.RevokeRepoResponse, error) {
	r.ArgPath = path
	r.ArgUsername = username
	return r.ReturnsRevokeResponse, r.Err
}
