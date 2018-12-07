package secrethub

import "github.com/keylockerbv/secrethub-go/pkg/api"

// RepoUserService handles operations on users of a repository.
type RepoUserService interface {
	// Invite invites the user with given username to the repository at the given path.
	Invite(path api.RepoPath, username string) (*api.RepoMember, error)
	// List lists the users of the given repository.
	List(path api.RepoPath) ([]*api.User, error)
	// Revoke revokes the user with given username from the repository with the given path.
	Revoke(path api.RepoPath, username string) (*api.RevokeRepoResponse, error)
}

type repoUserService struct {
	client *Client
}

// Invite invites the user with given username to the repository at the given path.
func (s repoUserService) Invite(path api.RepoPath, username string) (*api.RepoMember, error) {
	return s.client.InviteRepo(path, username)
}

// List lists the users of the given repository.
func (s repoUserService) List(path api.RepoPath) ([]*api.User, error) {
	return s.client.ListRepoUsers(path)
}

// Revoke revokes the user with given username from the repository with the given path.
func (s repoUserService) Revoke(path api.RepoPath, username string) (*api.RevokeRepoResponse, error) {
	return s.client.RemoveUser(path, username)
}
