package secrethub

import "github.com/secrethub/secrethub-go/internals/api"

// MeService handles operations on the authenticated account.
type MeService interface {
	// ListRepos retrieves all repositories of the current user.
	ListRepos() ([]*api.Repo, error)
	// GetUser retrieves the current users details.
	GetUser() (*api.User, error)
}

type meService struct {
	repoService RepoService
	userService UserService
}

func newMeService(repoService RepoService, userService UserService) MeService {
	return meService{
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
