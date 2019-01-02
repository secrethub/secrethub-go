// +build !production

package fakeclient

import "github.com/keylockerbv/secrethub-go/pkg/api"

// SecretVersionService can be used to mock a SecretVersionService.
type SecretVersionService struct {
	DeleteFunc          func(path api.SecretPath) error
	GetWithDataFunc     func(path api.SecretPath) (*api.SecretVersion, error)
	GetWithoutDataFunc  func(path api.SecretPath) (*api.SecretVersion, error)
	ListWithDataFunc    func(path api.SecretPath) ([]*api.SecretVersion, error)
	ListWithoutDataFunc func(path api.SecretPath) ([]*api.SecretVersion, error)
}

// Delete implements the SecretVersionService interface Delete function.
func (s SecretVersionService) Delete(path api.SecretPath) error {
	return s.DeleteFunc(path)
}

// GetWithData implements the SecretVersionService interface GetWithData function.
func (s SecretVersionService) GetWithData(path api.SecretPath) (*api.SecretVersion, error) {
	return s.GetWithDataFunc(path)
}

// GetWithoutData implements the SecretVersionService interface GetWithoutData function.
func (s SecretVersionService) GetWithoutData(path api.SecretPath) (*api.SecretVersion, error) {
	return s.GetWithoutDataFunc(path)
}

// ListWithData implements the SecretVersionService interface ListWithData function.
func (s SecretVersionService) ListWithData(path api.SecretPath) ([]*api.SecretVersion, error) {
	return s.ListWithDataFunc(path)
}

// ListWithoutData implements the SecretVersionService interface ListWithoutData function.
func (s SecretVersionService) ListWithoutData(path api.SecretPath) ([]*api.SecretVersion, error) {
	return s.ListWithoutDataFunc(path)
}
