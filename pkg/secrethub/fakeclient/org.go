// +build !production

package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
)

// OrgService is a mock of the RepoService interface.
type OrgService struct {
	CreateFunc func(name string, description string) (*api.Org, error)
	DeleteFunc func(name string) error
	GetFunc func(name string) (*api.Org, error)
	MembersService secrethub.OrgMemberService
	ListMineFunc func() ([]*api.Org, error)
	IteratorFunc func(params *secrethub.OrgIteratorParams) secrethub.OrgIterator
}

func (s *OrgService) Iterator(params *secrethub.OrgIteratorParams) secrethub.OrgIterator {
	return s.IteratorFunc(params)
}

// Create implements the RepoService interface Create function.
func (s *OrgService) Create(name string, description string) (*api.Org, error) {
	return s.CreateFunc(name, description)
}

// Delete implements the RepoService interface Delete function.
func (s *OrgService) Delete(name string) error {
	return s.DeleteFunc(name)
}

// Get implements the RepoService interface Get function.
func (s *OrgService) Get(name string) (*api.Org, error) {
	return s.GetFunc(name)
}

// Members returns a mock of the OrgMemberService interface.
func (s *OrgService) Members() secrethub.OrgMemberService {
	return s.MembersService
}

// ListMine implements the RepoService interface ListMine function.
func (s *OrgService) ListMine() ([]*api.Org, error) {
	return s.ListMineFunc()
}
