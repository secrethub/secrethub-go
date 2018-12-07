// +build !production

package fakeclient

import "github.com/keylockerbv/secrethub-go/pkg/api"

// UserService is a mock of the UserService interface.
type UserService struct {
	Getter      UserGetter
	MeGetter    MeGetter
	UserCreater UserCreater
}

// Get implements the UserService interface Get function.
func (s *UserService) Get(username string) (*api.User, error) {
	return s.Getter.Get(username)
}

// Me implements the UserService interface Me function.
func (s *UserService) Me() (*api.User, error) {
	return s.MeGetter.Me()
}

// Create implements the UserService interface Create function.
func (s *UserService) Create(username, email, fullName string) (*api.User, error) {
	return s.UserCreater.Create(username, email, fullName)
}

// MeGetter is a wrapper for the return values of the mocked MeGetter method.
type MeGetter struct {
	ReturnsUser *api.User
	Err         error
}

// Me returns the mocked response.
func (g *MeGetter) Me() (*api.User, error) {
	return g.ReturnsUser, g.Err
}

// UserGetter mocks the Get function.
type UserGetter struct {
	ArgUsername string
	ReturnsUser *api.User
	Err         error
}

// Get saves the arguments it was called with and returns the mocked response.
func (g *UserGetter) Get(username string) (*api.User, error) {
	g.ArgUsername = username
	return g.ReturnsUser, g.Err
}

// UserCreater mocks the Create function.
type UserCreater struct {
	ArgUsername string
	ArgEmail    string
	ArgFullName string
	ReturnsUser *api.User
	Err         error
}

// Create saves the arguments it was called with and returns the mocked response.
func (s *UserCreater) Create(username, email, fullName string) (*api.User, error) {
	s.ArgUsername = username
	s.ArgEmail = email
	s.ArgFullName = fullName
	return s.ReturnsUser, s.Err
}
