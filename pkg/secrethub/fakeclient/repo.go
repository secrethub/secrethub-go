// +build !production

package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
)

// RepoService is a mock of the RepoService interface.
type RepoService struct {
	ListFunc           func(namespace string) ([]*api.Repo, error)
	ListAccountsFunc   func(path string) ([]*api.Account, error)
	ListEventsFunc     func(path string, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error)
	ListMineFunc       func() ([]*api.Repo, error)
	CreateFunc         func(path string) (*api.Repo, error)
	DeleteFunc         func(path string) error
	GetFunc            func(path string) (*api.Repo, error)
	UserService        secrethub.RepoUserService
	RepoServiceService secrethub.RepoServiceService
	AuditEventIterator *AuditEventIterator
	secrethub.RepoService
}

// List implements the RepoService interface List function.
func (s *RepoService) List(namespace string) ([]*api.Repo, error) {
	return s.ListFunc(namespace)
}

// ListAccounts implements the RepoService interface ListAccounts function.
func (s *RepoService) ListAccounts(path string) ([]*api.Account, error) {
	return s.ListAccountsFunc(path)
}

// ListEvents implements the RepoService interface ListEvents function.
func (s *RepoService) ListEvents(path string, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error) {
	return s.ListEventsFunc(path, subjectTypes)
}

// EventIterator implements the RepoService interface EventIterator function.
func (s *RepoService) EventIterator(path string, config *secrethub.AuditEventIteratorParams) secrethub.AuditEventIterator {
	return s.AuditEventIterator
}

// ListMine implements the RepoService interface ListMine function.
func (s *RepoService) ListMine() ([]*api.Repo, error) {
	return s.ListMineFunc()
}

// Create implements the RepoService interface Create function.
func (s *RepoService) Create(path string) (*api.Repo, error) {
	return s.CreateFunc(path)
}

// Delete implements the RepoService interface Delete function.
func (s *RepoService) Delete(path string) error {
	return s.DeleteFunc(path)
}

// Get implements the RepoService interface Get function.
func (s *RepoService) Get(path string) (*api.Repo, error) {
	return s.GetFunc(path)
}

// Users returns the mocked UserService.
func (s *RepoService) Users() secrethub.RepoUserService {
	return s.UserService
}

// Services returns the mocked RepoServiceService.
func (s *RepoService) Services() secrethub.RepoServiceService {
	return s.RepoServiceService
}
