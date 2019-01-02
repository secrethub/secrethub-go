// +build !production

package fakeclient

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
)

// DirService is a mock of the DirService interface.
type DirService struct {
	CreateFunc  func(path api.DirPath) (*api.Dir, error)
	DeleteFunc  func(path api.DirPath) error
	GetTreeFunc func(path api.DirPath, depth int) (*api.Tree, error)
}

// Create implements the DirService interface Create function.
func (s DirService) Create(path api.DirPath) (*api.Dir, error) {
	return s.CreateFunc(path)
}

// Delete implements the DirService interface Delete function.
func (s DirService) Delete(path api.DirPath) error {
	return s.DeleteFunc(path)
}

// GetTree implements the DirService interface GetTree function.
func (s DirService) GetTree(path api.DirPath, depth int) (*api.Tree, error) {
	return s.GetTreeFunc(path, depth)
}
