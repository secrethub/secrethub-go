// +build !production

package fakeclient

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/secrethub"
)

// OrgService is a mock of the RepoService interface.
type OrgService struct {
	CreateFunc    func(name api.OrgName, description string) (*api.Org, error)
	DeleteFunc    func(name api.OrgName) error
	GetFunc       func(name api.OrgName) (*api.Org, error)
	ListMineFunc  func() ([]*api.Org, error)
	MemberService OrgMemberService
}

// Create implements the RepoService interface Create function.
func (s OrgService) Create(name api.OrgName, description string) (*api.Org, error) {
	return s.CreateFunc(name, description)
}

// Delete implements the RepoService interface Delete function.
func (s OrgService) Delete(name api.OrgName) error {
	return s.DeleteFunc(name)
}

// Get implements the RepoService interface Get function.
func (s OrgService) Get(name api.OrgName) (*api.Org, error) {
	return s.GetFunc(name)
}

// Members returns a mock of the OrgMemberService interface.
func (s OrgService) Members() secrethub.OrgMemberService {
	return s.MemberService
}

// ListMine implements the RepoService interface ListMine function.
func (s OrgService) ListMine() ([]*api.Org, error) {
	return s.ListMineFunc()
}
