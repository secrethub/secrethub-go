package secrethub

import "github.com/secrethub/secrethub-go/internals/api"

// MeService handles operations on the authenticated account.
type MeService interface {
	// Repos retrieves all repositories of the current user.
	Repos() ([]*api.Repo, error)
	// User retrieves the current users details.
	User() (*api.User, error)
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

// Repos retrieves all repositories of the current user.
func (ms meService) Repos() ([]*api.Repo, error) {
	return ms.repoService.ListMine()
}

// User retrieves the current users details.
func (ms meService) User() (*api.User, error) {
	return ms.userService.Me()
}
