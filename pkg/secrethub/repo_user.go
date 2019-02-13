package secrethub

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/errio"
)

// RepoUserService handles operations on users of a repository.
type RepoUserService interface {
	// Invite invites the user with given username to the repository at the given path.
	Invite(path api.RepoPath, username string) (*api.RepoMember, error)
	// List lists the users of the given repository.
	List(path api.RepoPath) ([]*api.User, error)
	// Revoke revokes the user with given username from the repository with the given path.
	Revoke(path api.RepoPath, username string) (*api.RevokeRepoResponse, error)
}

func newRepoUserService(client client) RepoUserService {
	return repoUserService{
		client: client,
	}
}

type repoUserService struct {
	client client
}

// Invite invites the user with given username to the repository at the given path.
func (s repoUserService) Invite(path api.RepoPath, username string) (*api.RepoMember, error) {
	name := api.AccountName(username)
	err := name.Validate()
	if err != nil {
		return nil, err
	}
	if !name.IsUser() {
		return nil, api.ErrUsernameIsService
	}

	account, err := s.client.httpClient.GetAccount(name)
	if err == api.ErrAccountNotFound {
		// return a more context specific error
		return nil, api.ErrUserNotFound
	} else if err != nil {
		return nil, errio.Error(err)
	}

	if len(account.PublicKey) == 0 {
		return nil, api.ErrAccountNotKeyed
	}

	createRepoMember, err := s.client.createRepoMemberRequest(path, account.PublicKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	in := &api.InviteUserRequest{
		AccountID:  account.AccountID,
		RepoMember: createRepoMember,
	}

	repoMember, err := s.client.httpClient.InviteRepo(path.GetNamespace(), path.GetRepo(), in)
	if err != nil {
		return nil, errio.Error(err)
	}

	return repoMember, nil
}

// List lists the users of the given repository.
func (s repoUserService) List(path api.RepoPath) ([]*api.User, error) {
	users, err := s.client.httpClient.ListRepoUsers(path.GetNamespaceAndRepoName())
	if err != nil {
		return nil, errio.Error(err)
	}

	return users, nil
}

// Revoke revokes the user with given username from the repository with the given path.
func (s repoUserService) Revoke(path api.RepoPath, username string) (*api.RevokeRepoResponse, error) {
	resp, err := s.client.httpClient.RemoveUser(path.GetNamespace(), path.GetRepo(), username)
	if err != nil {
		return nil, errio.Error(err)
	}

	return resp, nil
}
