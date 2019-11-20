// +build !production

package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
)

// RepoService is a mock of the RepoService interface.
type RepoService struct {
	AccountLister      RepoAccountLister
	Creater            RepoCreater
	Deleter            RepoDeleter
	Getter             RepoGetter
	EventLister        RepoEventLister
	Lister             RepoLister
	UserService        *RepoUserService
	ServiceService     *RepoServiceService
	MineLister         RepoMineLister
	AuditEventIterator *AuditEventIterator

	secrethub.RepoService
}

// List implements the RepoService interface List function.
func (s *RepoService) List(namespace string) ([]*api.Repo, error) {
	return s.Lister.List(namespace)
}

// ListAccounts implements the RepoService interface ListAccounts function.
func (s *RepoService) ListAccounts(path string) ([]*api.Account, error) {
	return s.AccountLister.ListAccounts(path)
}

// ListEvents implements the RepoService interface ListEvents function.
func (s *RepoService) ListEvents(path string, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error) {
	return s.EventLister.ListEvents(path, subjectTypes)
}

// EventIterator implements the RepoService interface EventIterator function.
func (s *RepoService) EventIterator(path string, config *secrethub.AuditEventIteratorParams) secrethub.AuditEventIterator {
	return s.AuditEventIterator
}

// ListMine implements the RepoService interface ListMine function.
func (s *RepoService) ListMine() ([]*api.Repo, error) {
	return s.MineLister.ListMine()
}

// Create implements the RepoService interface Create function.
func (s *RepoService) Create(path string) (*api.Repo, error) {
	return s.Creater.Create(path)
}

// Delete implements the RepoService interface Delete function.
func (s *RepoService) Delete(path string) error {
	return s.Deleter.Delete(path)
}

// Get implements the RepoService interface Get function.
func (s *RepoService) Get(path string) (*api.Repo, error) {
	return s.Getter.Get(path)
}

// Users returns the mocked UserService.
func (s *RepoService) Users() secrethub.RepoUserService {
	return s.UserService
}

// Services returns the mocked RepoServiceService.
func (s *RepoService) Services() secrethub.RepoServiceService {
	return s.ServiceService
}

// RepoDeleter mocks the Delete function.
type RepoDeleter struct {
	ArgPath string
	Err     error
}

// Delete saves the arguments it was called with and returns the mocked response.
func (d *RepoDeleter) Delete(path string) error {
	d.ArgPath = path
	return d.Err
}

// RepoGetter mocks the Get function.
type RepoGetter struct {
	ArgPath     string
	ReturnsRepo *api.Repo
	Err         error
}

// Get saves the arguments it was called with and returns the mocked response.
func (g *RepoGetter) Get(path string) (*api.Repo, error) {
	g.ArgPath = path
	return g.ReturnsRepo, g.Err
}

// RepoLister mocks the List function.
type RepoLister struct {
	ArgNamespace string
	ReturnsRepos []*api.Repo
	Err          error
}

// List saves the argument it was called with and returns the mocked response.
func (g *RepoLister) List(namespace string) ([]*api.Repo, error) {
	g.ArgNamespace = namespace
	return g.ReturnsRepos, g.Err
}

// RepoEventLister mocks the ListEvents function.
type RepoEventLister struct {
	ArgPath            string
	ArgSubjectTypes    api.AuditSubjectTypeList
	ReturnsAuditEvents []*api.Audit
	Err                error
}

// ListEvents saves the arguments it was called with and returns the mocked response.
func (el *RepoEventLister) ListEvents(path string, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error) {
	el.ArgPath = path
	el.ArgSubjectTypes = subjectTypes
	return el.ReturnsAuditEvents, el.Err
}

// RepoCreater mocks the Create function.
type RepoCreater struct {
	Argpath     string
	ReturnsRepo *api.Repo
	Err         error
}

// Create saves the arguments it was called with and returns the mocked response.
func (creater *RepoCreater) Create(path string) (*api.Repo, error) {
	creater.Argpath = path
	return creater.ReturnsRepo, creater.Err
}

// RepoAccountLister mocks the ListAccounts function.
type RepoAccountLister struct {
	ArgPath         string
	ReturnsAccounts []*api.Account
	Err             error
}

// ListAccounts saves the arguments it was called with and returns the mocked response.
func (l *RepoAccountLister) ListAccounts(path string) ([]*api.Account, error) {
	l.ArgPath = path
	return l.ReturnsAccounts, l.Err
}

// RepoMineLister mocks the ListMine function.
type RepoMineLister struct {
	ReturnsRepos []*api.Repo
	Err          error
}

// ListMine returns the mocked response.
func (m *RepoMineLister) ListMine() ([]*api.Repo, error) {
	return m.ReturnsRepos, m.Err
}
