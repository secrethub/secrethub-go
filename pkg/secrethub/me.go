package secrethub

import "github.com/secrethub/secrethub-go/internals/api"

// MeService handles operations on the authenticated account.
type MeService interface {
	// ListRepos retrieves all repositories of the current user.
	ListRepos() ([]*api.Repo, error)
	// GetUser retrieves the current users details.
	GetUser() (*api.User, error)
	// SendVerificationEmail sends an email to the authenticated user's registered email address
	// for them to prove they own that email address.
	SendVerificationEmail() error
}

type meService struct {
	client      client
	repoService RepoService
	userService UserService
}

func newMeService(client client, repoService RepoService, userService UserService) MeService {
	return meService{
		client:      client,
		repoService: repoService,
		userService: userService,
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
