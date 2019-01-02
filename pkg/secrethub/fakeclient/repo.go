// +build !production

package fakeclient

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/secrethub"
)

// RepoService is a mock of the RepoService interface.
type RepoService struct {
	CreateFunc       func(path api.RepoPath) (*api.Repo, error)
	DeleteFunc       func(path api.RepoPath) error
	GetFunc          func(path api.RepoPath) (*api.Repo, error)
	ListAccountsFunc func(path api.RepoPath) ([]*api.Account, error)
	ListEventsFunc   func(path api.RepoPath, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error)
	ListFunc         func(namespace api.Namespace) ([]*api.Repo, error)
	ListMineFunc     func() ([]*api.Repo, error)
	UserService      RepoUserService
	ServiceService   RepoServiceService
}

// Create implements the RepoService interface Create function.
func (s RepoService) Create(path api.RepoPath) (*api.Repo, error) {
	return s.CreateFunc(path)
}

// Delete implements the RepoService interface Delete function.
func (s RepoService) Delete(path api.RepoPath) error {
	return s.DeleteFunc(path)
}

// Get implements the RepoService interface Get function.
func (s RepoService) Get(path api.RepoPath) (*api.Repo, error) {
	return s.GetFunc(path)
}

// ListAccounts implements the RepoService interface ListAccounts function.
func (s RepoService) ListAccounts(path api.RepoPath) ([]*api.Account, error) {
	return s.ListAccountsFunc(path)
}

// ListEvents implements the RepoService interface ListEvents function.
func (s RepoService) ListEvents(path api.RepoPath, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error) {
	return s.ListEventsFunc(path, subjectTypes)
}

// List implements the RepoService interface List function.
func (s RepoService) List(namespace api.Namespace) ([]*api.Repo, error) {
	return s.ListFunc(namespace)
}

// ListMine implements the RepoService interface ListMine function.
func (s RepoService) ListMine() ([]*api.Repo, error) {
	return s.ListMineFunc()
}

// Users returns the mocked UserService.
func (s RepoService) Users() secrethub.RepoUserService {
	return s.UserService
}

// Services returns the mocked RepoServiceService.
func (s RepoService) Services() secrethub.RepoServiceService {
	return s.ServiceService
}
