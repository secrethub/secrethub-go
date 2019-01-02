// +build !production

package fakeclient

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/secrethub"
)

// ServiceService is a mock of the ServiceService interface.
type ServiceService struct {
	CreateFunc func(path api.RepoPath, description string, credential secrethub.Credential) (*api.Service, error)
	DeleteFunc func(id string) (*api.RevokeRepoResponse, error)
	GetFunc    func(id string) (*api.Service, error)
	ListFunc   func(path api.RepoPath) ([]*api.Service, error)
}

// Create implements the ServiceService interface Create function.
func (s ServiceService) Create(path api.RepoPath, description string, credential secrethub.Credential) (*api.Service, error) {
	return s.CreateFunc(path, description, credential)
}

// Delete implements the ServiceService interface Delete function.
func (s ServiceService) Delete(id string) (*api.RevokeRepoResponse, error) {
	return s.DeleteFunc(id)
}

// Get implements the ServiceService interface Get function.
func (s ServiceService) Get(id string) (*api.Service, error) {
	return s.GetFunc(id)
}

// List implements the ServiceService interface List function.
func (s ServiceService) List(path api.RepoPath) ([]*api.Service, error) {
	return s.ListFunc(path)
}
