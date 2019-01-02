// +build !production

package fakeclient

import "github.com/keylockerbv/secrethub-go/pkg/api"

// RepoUserService is a mock of the RepoUserService interface.
type RepoUserService struct {
	InviteFunc func(path api.RepoPath, username string) (*api.RepoMember, error)
	ListFunc   func(path api.RepoPath) ([]*api.User, error)
	RevokeFunc func(path api.RepoPath, username string) (*api.RevokeRepoResponse, error)
}

// Invite implements the RepoUserService interface Invite function.
func (s RepoUserService) Invite(path api.RepoPath, username string) (*api.RepoMember, error) {
	return s.InviteFunc(path, username)
}

// List implements the RepoUserService interface List function.
func (s RepoUserService) List(path api.RepoPath) ([]*api.User, error) {
	return s.ListFunc(path)
}

// Revoke implements the RepoUserService interface Revoke function.
func (s RepoUserService) Revoke(path api.RepoPath, username string) (*api.RevokeRepoResponse, error) {
	return s.RevokeFunc(path, username)
}
