package secrethub

import "github.com/secrethub/secrethub-go/internals/api"

// MeService handles operations on the authenticated account.
type MeService interface {
	// Repos retrieves all repositories of the current user.
	Repos() ([]*api.Repo, error)
	// User retrieves the current users details.
	User() (*api.User, error)
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

// Repos retrieves all repositories of the current user.
func (ms meService) Repos() ([]*api.Repo, error) {
	return ms.repoService.ListMine()
}

// User retrieves the current users details.
func (ms meService) User() (*api.User, error) {
	return ms.userService.Me()
}

// SendVerificationEmail sends an email to the authenticated user's registered email address
// for them to prove they own that email address.
func (ms meService) SendVerificationEmail() error {
	return ms.client.httpClient.SendVerificationEmail()
}
