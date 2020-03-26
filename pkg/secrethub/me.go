package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub/iterator"
)

// MeService handles operations on the authenticated account.
type MeService interface {
	// GetUser retrieves the current users details.
	GetUser() (*api.User, error)
	// SendVerificationEmail sends an email to the authenticated user's registered email address
	// for them to prove they own that email address.
	SendVerificationEmail() error
	// ListRepos retrieves all repositories of the current user.
	// Deprecated: Use iterator function instead.
	ListRepos() ([]*api.Repo, error)
	// RepoIterator returns an iterator that retrieves all repos of the current user.
	RepoIterator(_ *RepoIteratorParams) RepoIterator
}

type meService struct {
	client      *Client
	repoService RepoService
	userService UserService
}

func newMeService(client *Client) MeService {
	return meService{
		client:      client,
		repoService: newRepoService(client),
		userService: newUserService(client),
	}
}

// ListRepos retrieves all repositories of the current user.
func (ms meService) ListRepos() ([]*api.Repo, error) {
	return ms.repoService.ListMine()
}

// GetUser retrieves the current users details.
func (ms meService) GetUser() (*api.User, error) {
	return ms.userService.Me()
}

// SendVerificationEmail sends an email to the authenticated user's registered email address
// for them to prove they own that email address.
func (ms meService) SendVerificationEmail() error {
	return ms.client.httpClient.SendVerificationEmail()
}

// RepoIterator returns an iterator that retrieves all repos of the current user.
func (ms meService) RepoIterator(params *RepoIteratorParams) RepoIterator {
	return &repoIterator{
		iterator: iterator.New(
			iterator.PaginatorFactory(
				func() ([]interface{}, error) {
					repos, err := ms.client.httpClient.ListMyRepos()
					if err != nil {
						return nil, err
					}

					res := make([]interface{}, len(repos))
					for i, element := range repos {
						res[i] = element
					}
					return res, nil
				},
			),
		),
	}
}
