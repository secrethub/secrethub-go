// +build !production

package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
)

// RepoUserService is a mock of the RepoUserService interface.
type RepoUserService struct {
	InviteFunc   func(path string, username string) (*api.RepoMember, error)
	ListFunc     func(path string) ([]*api.User, error)
	RevokeFunc   func(path string, username string) (*api.RevokeRepoResponse, error)
	IteratorFunc func() secrethub.UserIterator
}

func (s *RepoUserService) Iterator(path string, params *secrethub.UserIteratorParams) secrethub.UserIterator {
	return s.IteratorFunc()
}

// Invite implements the RepoUserService interface Invite function.
func (s *RepoUserService) Invite(path string, username string) (*api.RepoMember, error) {
	return s.InviteFunc(path, username)
}

// List implements the RepoUserService interface List function.
func (s *RepoUserService) List(path string) ([]*api.User, error) {
	return s.ListFunc(path)
}

// Revoke implements the RepoUserService interface Revoke function.
func (s *RepoUserService) Revoke(path string, username string) (*api.RevokeRepoResponse, error) {
	return s.RevokeFunc(path, username)
}
