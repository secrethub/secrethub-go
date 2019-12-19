package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
)

// MeService handles operations on the authenticated account.
type MeService interface {
	// GetUser retrieves the current users details.
	GetUser() (*api.User, error)
	// SendVerificationEmail sends an email to the authenticated user's registered email address
	// for them to prove they own that email address.
	SendVerificationEmail() error
	// ListRepos retrieves all repositories of the current user.
	ListRepos() ([]*api.Repo, error)
	// Repo iterator returns a RepoIterator that retrieves all repos of the current user.
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

func (ms meService) RepoIterator(params *RepoIteratorParams) RepoIterator {
	data, err := ms.ListRepos()

	return &repoIterator{
		index: 0,
		data:  data,
		err:   err,
	}
}
