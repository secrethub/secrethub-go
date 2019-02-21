// +build !production

package fakeclient

import "github.com/keylockerbv/secrethub-go/pkg/api"

// SecretVersionService can be used to mock a SecretVersionService.
type SecretVersionService struct {
	Deleter           SecretVersionDeleter
	WithDataGetter    WithDataGetter
	WithoutDataGetter WithoutDataGetter
	WithDataLister    WithDataLister
	WithoutDataLister WithoutDataLister
}

// Delete implements the SecretVersionService interface Delete function.
func (s *SecretVersionService) Delete(path string) error {
	return s.Deleter.Delete(path)
}

// GetWithData implements the SecretVersionService interface GetWithData function.
func (s *SecretVersionService) GetWithData(path string) (*api.SecretVersion, error) {
	return s.WithDataGetter.GetWithData(path)
}

// GetWithoutData implements the SecretVersionService interface GetWithoutData function.
func (s *SecretVersionService) GetWithoutData(path string) (*api.SecretVersion, error) {
	return s.WithoutDataGetter.GetWithoutData(path)
}

// ListWithData implements the SecretVersionService interface ListWithData function.
func (s *SecretVersionService) ListWithData(path string) ([]*api.SecretVersion, error) {
	return s.WithDataLister.ListWithData(path)
}

// ListWithoutData implements the SecretVersionService interface ListWithoutData function.
func (s *SecretVersionService) ListWithoutData(path string) ([]*api.SecretVersion, error) {
	return s.WithoutDataLister.ListWithoutData(path)
}

// SecretVersionDeleter mocks the Delete function.
type SecretVersionDeleter struct {
	ArgPath string
	Err     error
}

// Delete saves the arguments it was called with and returns the mocked response.
func (d *SecretVersionDeleter) Delete(path string) error {
	d.ArgPath = path
	return d.Err
}

// WithDataGetter mocks the GetWithData function.
type WithDataGetter struct {
	ArgPath        string
	ReturnsVersion *api.SecretVersion
	Err            error
}

// GetWithData saves the arguments it was called with and returns the mocked response.
func (g *WithDataGetter) GetWithData(path string) (*api.SecretVersion, error) {
	g.ArgPath = path
	return g.ReturnsVersion, g.Err
}

// WithoutDataGetter mocks the GetWithoutData function.
type WithoutDataGetter struct {
	ArgPath        string
	ReturnsVersion *api.SecretVersion
	Err            error
}

// GetWithoutData saves the arguments it was called with and returns the mocked response.
func (g *WithoutDataGetter) GetWithoutData(path string) (*api.SecretVersion, error) {
	g.ArgPath = path
	return g.ReturnsVersion, g.Err
}

// WithDataLister mocks the ListWithData function.
type WithDataLister struct {
	ArgPath         string
	ReturnsVersions []*api.SecretVersion
	Err             error
}

// ListWithData saves the arguments it was called with and returns the mocked response.
func (l *WithDataLister) ListWithData(path string) ([]*api.SecretVersion, error) {
	l.ArgPath = path
	return l.ReturnsVersions, l.Err
}

// WithoutDataLister mocks the ListWithoutData function.
type WithoutDataLister struct {
	ArgPath         string
	ReturnsVersions []*api.SecretVersion
	Err             error
}

// ListWithoutData saves the arguments it was called with and returns the mocked response.
func (l *WithoutDataLister) ListWithoutData(path string) ([]*api.SecretVersion, error) {
	l.ArgPath = path
	return l.ReturnsVersions, l.Err
}
