// +build !production

package fakeclient

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/secrethub"
)

// SecretService is a mock of the SecretService interface.
type SecretService struct {
	DeleteFunc     func(path api.SecretPath) error
	GetFunc        func(path api.SecretPath) (*api.Secret, error)
	ListEventsFunc func(path api.SecretPath, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error)
	WriteFunc      func(path api.SecretPath, data []byte) (*api.SecretVersion, error)

	VersionService SecretVersionService
}

// Delete implements the SecretService interface Delete function.
func (s SecretService) Delete(path api.SecretPath) error {
	return s.DeleteFunc(path)
}

// Get implements the SecretService interface Get function.
func (s SecretService) Get(path api.SecretPath) (*api.Secret, error) {
	return s.GetFunc(path)
}

// Write implements the SecretService interface Write function.
func (s SecretService) Write(path api.SecretPath, data []byte) (*api.SecretVersion, error) {
	return s.WriteFunc(path, data)
}

// ListEvents implements the SecretService interface ListEvents function.
func (s SecretService) ListEvents(path api.SecretPath, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error) {
	return s.ListEventsFunc(path, subjectTypes)
}

// Versions returns a mock of the VersionService interface.
func (s SecretService) Versions() secrethub.SecretVersionService {
	return s.VersionService
}
