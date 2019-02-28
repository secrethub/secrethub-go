package secrethub

import (
	"github.com/keylockerbv/secrethub-go/internals/api"
	"github.com/keylockerbv/secrethub-go/internals/errio"
)

// RepoUserService handles operations on users of a repository.
type RepoUserService interface {
	// Invite invites the user with given username to the repository at the given path.
	Invite(path string, username string) (*api.RepoMember, error)
	// List lists the users of the given repository.
	List(path string) ([]*api.User, error)
	// Revoke revokes the user with given username from the repository with the given path.
	Revoke(path string, username string) (*api.RevokeRepoResponse, error)
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
func (s repoUserService) Invite(path string, username string) (*api.RepoMember, error) {
	repoPath, err := api.NewRepoPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	accountName, err := api.NewAccountName(username)
	if err != nil {
		return nil, err
	}
	if !accountName.IsUser() {
		return nil, api.ErrUsernameIsService
	}

	account, err := s.client.httpClient.GetAccount(accountName)
	if err == api.ErrAccountNotFound {
		// return a more context specific error
		return nil, api.ErrUserNotFound
	} else if err != nil {
		return nil, errio.Error(err)
	}

	if len(account.PublicKey) == 0 {
		return nil, api.ErrAccountNotKeyed
	}

	createRepoMember, err := s.client.createRepoMemberRequest(repoPath, account.PublicKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	in := &api.InviteUserRequest{
		AccountID:  account.AccountID,
		RepoMember: createRepoMember,
	}

	repoMember, err := s.client.httpClient.InviteRepo(repoPath.GetNamespace(), repoPath.GetRepo(), in)
	if err != nil {
		return nil, errio.Error(err)
	}

	return repoMember, nil
}

// List lists the users of the given repository.
func (s repoUserService) List(path string) ([]*api.User, error) {
	repoPath, err := api.NewRepoPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	users, err := s.client.httpClient.ListRepoUsers(repoPath.GetNamespaceAndRepoName())
	if err != nil {
		return nil, errio.Error(err)
	}

	return users, nil
}

// Revoke revokes the user with given username from the repository with the given path.
func (s repoUserService) Revoke(path string, username string) (*api.RevokeRepoResponse, error) {
	repoPath, err := api.NewRepoPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = api.ValidateUsername(username)
	if err != nil {
		return nil, errio.Error(err)
	}

	resp, err := s.client.httpClient.RemoveUser(repoPath.GetNamespace(), repoPath.GetRepo(), username)
	if err != nil {
		return nil, errio.Error(err)
	}

	return resp, nil
}
