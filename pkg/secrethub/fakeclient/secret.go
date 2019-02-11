// +build !production

package fakeclient

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/secrethub"
)

// SecretService is a mock of the SecretService interface.
type SecretService struct {
	VersionService secrethub.SecretVersionService

	Deleter     SecretDeleter
	Getter      SecretGetter
	EventLister SecretEventLister
	Writer      Writer
}

// Delete implements the SecretService interface Delete function.
func (s *SecretService) Delete(path api.SecretPath) error {
	return s.Deleter.Delete(path)
}

// Exists implements the SecretService interface Exists function.
func (s *SecretService) Exists(path api.SecretPath) (bool, error) {
	return false, nil
}

// Get implements the SecretService interface Get function.
func (s *SecretService) Get(path api.SecretPath) (*api.Secret, error) {
	return s.Getter.Get(path)
}

// Write implements the SecretService interface Write function.
func (s *SecretService) Write(path api.SecretPath, data []byte) (*api.SecretVersion, error) {
	return s.Writer.Write(path, data)
}

// ListEvents implements the SecretService interface ListEvents function.
func (s *SecretService) ListEvents(path api.SecretPath, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error) {
	return s.EventLister.ListEvents(path, subjectTypes)
}

// Versions returns a mock of the VersionService interface.
func (s *SecretService) Versions() secrethub.SecretVersionService {
	return s.VersionService
}

// SecretDeleter mocks the Delete function.
type SecretDeleter struct {
	ArgPath api.SecretPath
	Err     error
}

// Delete saves the arguments it was called with and returns the mocked response.
func (d *SecretDeleter) Delete(path api.SecretPath) error {
	d.ArgPath = path
	return d.Err
}

// SecretGetter mocks the Get function.
type SecretGetter struct {
	ArgPath       api.SecretPath
	ReturnsSecret *api.Secret
	Err           error
}

// Get saves the arguments it was called with and returns the mocked response.
func (g *SecretGetter) Get(path api.SecretPath) (*api.Secret, error) {
	g.ArgPath = path
	return g.ReturnsSecret, g.Err
}

// SecretEventLister mocks the ListEvents function.
type SecretEventLister struct {
	ArgPath            api.SecretPath
	ArgSubjectTypes    api.AuditSubjectTypeList
	ReturnsAuditEvents []*api.Audit
	Err                error
}

// ListEvents saves the arguments it was called with and returns the mocked response.
func (s *SecretEventLister) ListEvents(path api.SecretPath, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error) {
	s.ArgPath = path
	s.ArgSubjectTypes = subjectTypes
	return s.ReturnsAuditEvents, s.Err
}

// Writer is a wrapper for the arguments and return values of the mocked Writer method.
type Writer struct {
	ArgPath        api.SecretPath
	ArgData        []byte
	ReturnsVersion *api.SecretVersion
	Err            error
}

// Writer saves the arguments it was called with and returns the mocked response.
func (w *Writer) Write(path api.SecretPath, data []byte) (*api.SecretVersion, error) {
	w.ArgPath = path
	w.ArgData = data
	return w.ReturnsVersion, w.Err
}
