package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/errio"
	"github.com/secrethub/secrethub-go/pkg/secrethub/iterator"
)

// RepoUserService handles operations on users of a repository.
type RepoUserService interface {
	// Invite invites the user with given username to the repository at the given path.
	Invite(path string, username string) (*api.RepoMember, error)
	// Revoke revokes the user with given username from the repository with the given path.
	Revoke(path string, username string) (*api.RevokeRepoResponse, error)
	// List lists the users of the given repository.
	List(path string) ([]*api.User, error)
	// Iterator returns an iterator that lists the users of a given repository.
	Iterator(path string, params *UserIteratorParams) UserIterator
}

func newRepoUserService(client *Client) RepoUserService {
	return repoUserService{
		client: client,
	}
}

type repoUserService struct {
	client *Client
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

// Iterator returns an iterator that lists the users of a given repository.
func (s repoUserService) Iterator(path string, params *UserIteratorParams) UserIterator {
	return &userIterator{
		iterator: iterator.New(
			iterator.PaginatorFactory(
				func() ([]interface{}, error) {
					repoPath, err := api.NewRepoPath(path)
					if err != nil {
						return nil, errio.Error(err)
					}

					users, err := s.client.httpClient.ListRepoUsers(repoPath.GetNamespaceAndRepoName())
					if err != nil {
						return nil, errio.Error(err)
					}

					res := make([]interface{}, len(users))
					for i, element := range users {
						res[i] = element
					}
					return res, nil
				},
			),
		),
	}
}

// UserIteratorParams defines parameters used when listing Users.
type UserIteratorParams struct{}

// UserIterator iterates over users.
type UserIterator interface {
	Next() (api.User, error)
}

type userIterator struct {
	iterator iterator.Iterator
}

// Next returns the next user or iterator.Done as an error if all of them have been returned.
func (it *userIterator) Next() (api.User, error) {
	item, err := it.iterator.Next()
	if err != nil {
		return api.User{}, err
	}

	return item.(api.User), nil
}
