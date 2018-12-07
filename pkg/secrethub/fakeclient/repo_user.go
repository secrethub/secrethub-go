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
func (s *RepoUserService) Invite(path api.RepoPath, username string) (*api.RepoMember, error) {
	return s.RepoInviter.Invite(path, username)
}

// List implements the RepoUserService interface List function.
func (s *RepoUserService) List(path api.RepoPath) ([]*api.User, error) {
	return s.Lister.List(path)
}

// Revoke implements the RepoUserService interface Revoke function.
func (s *RepoUserService) Revoke(path api.RepoPath, username string) (*api.RevokeRepoResponse, error) {
	return s.Revoker.Revoke(path, username)
}

// RepoUserLister mocks the List function.
type RepoUserLister struct {
	ArgPath      api.RepoPath
	ReturnsUsers []*api.User
	Err          error
}

// List saves the arguments it was called with and returns the mocked response.
func (l *RepoUserLister) List(path api.RepoPath) ([]*api.User, error) {
	l.ArgPath = path
	return l.ReturnsUsers, l.Err
}

// RepoInviter mocks the Invite function.
type RepoInviter struct {
	ArgPath           api.RepoPath
	ArgUsername       string
	ReturnsRepoMember *api.RepoMember
	Err               error
}

// Invite saves the arguments it was called with and returns the mocked response.
func (i *RepoInviter) Invite(path api.RepoPath, username string) (*api.RepoMember, error) {
	i.ArgPath = path
	i.ArgUsername = username
	return i.ReturnsRepoMember, i.Err
}

// RepoRevoker mocks the Revoke function.
type RepoRevoker struct {
	ArgPath               api.RepoPath
	ArgUsername           string
	ReturnsRevokeResponse *api.RevokeRepoResponse
	Err                   error
}

// Revoke saves the arguments it was called with and returns the mocked response.
func (r *RepoRevoker) Revoke(path api.RepoPath, username string) (*api.RevokeRepoResponse, error) {
	r.ArgPath = path
	r.ArgUsername = username
	return r.ReturnsRevokeResponse, r.Err
}
