// +build !production

package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
)

var _ secrethub.SecretService = (*SecretService)(nil)

// SecretService is a mock of the SecretService interface.
type SecretService struct {
	VersionService     secrethub.SecretVersionService
	DeleteFunc         func(path string) error
	GetFunc            func(path string) (*api.Secret, error)
	ReadFunc           func(path string) (*api.SecretVersion, error)
	ReadStringFunc     func(path string) (string, error)
	ExistsFunc         func(path string) (bool, error)
	WriteFunc          func(path string, data []byte) (*api.SecretVersion, error)
	ListEventsFunc     func(path string, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error)
	ResolveFunc        func(ref string) ([]byte, error)
	ResolveEnvFunc     func(envVars []string) (map[string]string, error)
	AuditEventIterator *AuditEventIterator
}

func (s *SecretService) Resolve(ref string) ([]byte, error) {
	return s.ResolveFunc(ref)
}

func (s *SecretService) ResolveEnv(envVars []string) (map[string]string, error) {
	return s.ResolveEnvFunc(envVars)
}

// Delete implements the SecretService interface Delete function.
func (s *SecretService) Delete(path string) error {
	return s.DeleteFunc(path)
}

// Exists implements the SecretService interface Exists function.
func (s *SecretService) Exists(path string) (bool, error) {
	return s.ExistsFunc(path)
}

// Get implements the SecretService interface Get function.
func (s *SecretService) Get(path string) (*api.Secret, error) {
	return s.GetFunc(path)
}

// Write implements the SecretService interface Write function.
func (s *SecretService) Write(path string, data []byte) (*api.SecretVersion, error) {
	return s.WriteFunc(path, data)
}

// ListEvents implements the SecretService interface ListEvents function.
func (s *SecretService) ListEvents(path string, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error) {
	return s.ListEventsFunc(path, subjectTypes)
}

// EventIterator implements the SecretService interface EventIterator function.
func (s *SecretService) EventIterator(path string, config *secrethub.AuditEventIteratorParams) secrethub.AuditEventIterator {
	return s.AuditEventIterator
}

// Versions returns a mock of the VersionService interface.
func (s *SecretService) Versions() secrethub.SecretVersionService {
	return s.VersionService
}

func (s *SecretService) Read(path string) (*api.SecretVersion, error) {
	return s.ReadFunc(path)
}

func (s *SecretService) ReadString(path string) (string, error) {
	return s.ReadStringFunc(path)
}

// SecretDeleter mocks the Delete function.
type SecretDeleter struct {
	ArgPath string
	Err     error
}

// Delete saves the arguments it was called with and returns the mocked response.
func (d *SecretDeleter) Delete(path string) error {
	d.ArgPath = path
	return d.Err
}

// SecretGetter mocks the Get function.
type SecretGetter struct {
	ArgPath       string
	ReturnsSecret *api.Secret
	Err           error
}

// Get saves the arguments it was called with and returns the mocked response.
func (g *SecretGetter) Get(path string) (*api.Secret, error) {
	g.ArgPath = path
	return g.ReturnsSecret, g.Err
}

// SecretEventLister mocks the ListEvents function.
type SecretEventLister struct {
	ArgPath            string
	ArgSubjectTypes    api.AuditSubjectTypeList
	ReturnsAuditEvents []*api.Audit
	Err                error
}

// ListEvents saves the arguments it was called with and returns the mocked response.
func (s *SecretEventLister) ListEvents(path string, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error) {
	s.ArgPath = path
	s.ArgSubjectTypes = subjectTypes
	return s.ReturnsAuditEvents, s.Err
}

// Writer is a wrapper for the arguments and return values of the mocked Writer method.
type Writer struct {
	ArgPath        string
	ArgData        []byte
	ReturnsVersion *api.SecretVersion
	Err            error
}

// Writer saves the arguments it was called with and returns the mocked response.
func (w *Writer) Write(path string, data []byte) (*api.SecretVersion, error) {
	w.ArgPath = path
	w.ArgData = data
	return w.ReturnsVersion, w.Err
}

// SecretReader mocks the Read function
type SecretReader struct {
	ArgPath        string
	ReturnsVersion *api.SecretVersion
	Err            error
}

// Read saves the arguments it was called with and returns the mocked response
func (r *SecretReader) Read(path string) (*api.SecretVersion, error) {
	r.ArgPath = path
	return r.ReturnsVersion, r.Err
}

// ReadString saves the arguments it was called with and returns the mocked response
func (r *SecretReader) ReadString(path string) (string, error) {
	r.ArgPath = path
	return string(r.ReturnsVersion.Data), r.Err
}
