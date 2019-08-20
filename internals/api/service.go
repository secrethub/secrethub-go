package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/secrethub/secrethub-go/internals/api/uuid"
)

// Errors
var (
	ErrInvalidServiceID = errAPI.Code("invalid_service_id").StatusError(
		"service id is 14 characters long and starts with s-",
		http.StatusBadRequest,
	)
	ErrInvalidServiceDescription = errAPI.Code("invalid_service_description").StatusError(
		fmt.Sprintf(
			"service descriptions can at most be %d long and cannot contain any newlines or tabs",
			serviceDescriptionMaxLength,
		),
		http.StatusBadRequest,
	)
)

type ServiceType string

// Service types
const (
	ServiceTypeAWS ServiceType = "aws"
	ServiceTypeRSA ServiceType = "rsa"
)

// Service represents a service account on SecretHub.
type Service struct {
	AccountID   *uuid.UUID        `json:"account_id"`
	ServiceID   string            `json:"service_id"`
	Repo        *Repo             `json:"repo"`
	Description string            `json:"description"`
	CreatedBy   *uuid.UUID        `json:"created_by,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	Type        ServiceType       `json:"type"`
	MetaData    map[string]string `json:"meta_data,omitempty"`
}

// Trim removes all non-essential fields from Service for output
func (a Service) Trim() *Service {
	return &Service{
		AccountID:   a.AccountID,
		ServiceID:   a.ServiceID,
		Description: a.Description,
	}
}

// ToAuditSubject converts an Service to an AuditSubject
func (a Service) ToAuditSubject() *AuditSubject {
	return &AuditSubject{
		SubjectID: a.AccountID,
		Type:      AuditSubjectService,
		Service:   a.Trim(),
	}
}

// ToAuditActor converts an Service to an AuditActor
func (a Service) ToAuditActor() *AuditActor {
	return &AuditActor{
		ActorID: a.AccountID,
		Type:    "service",
		Service: a.Trim(),
	}
}

// CreateServiceRequest contains the required fields for creating an Service.
type CreateServiceRequest struct {
	Description string                   `json:"description"`
	Credential  *CreateCredentialRequest `json:"credential"`
	AccountKey  *CreateAccountKeyRequest `json:"account_key"`
	RepoMember  *CreateRepoMemberRequest `json:"repo_member"`
}

// Validate validates the request fields.
func (req CreateServiceRequest) Validate() error {
	err := ValidateServiceDescription(req.Description)
	if err != nil {
		return err
	}

	err = req.Credential.Validate()
	if err != nil {
		return err
	}

	err = req.AccountKey.Validate()
	if err != nil {
		return err
	}

	err = req.RepoMember.Validate()
	if err != nil {
		return err
	}

	return nil
}
