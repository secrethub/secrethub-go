package api

import (
	"net/http"
	"strconv"
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
		"service descriptions can at most be "+strconv.Itoa(serviceDescriptionMaxLength)+" long and cannot contain any newlines or tabs",
		http.StatusBadRequest,
	)
	ErrAccessDeniedToKMSKey = errAPI.Code("access_denied").StatusError("access to KMS key is denied", http.StatusForbidden)
)

// Service represents a service account on SecretHub.
type Service struct {
	AccountID   uuid.UUID   `json:"account_id"`
	ServiceID   string      `json:"service_id"`
	Repo        *Repo       `json:"repo"`
	Description string      `json:"description"`
	CreatedBy   uuid.UUID   `json:"created_by"`
	CreatedAt   time.Time   `json:"created_at"`
	Credential  *Credential `json:"credential"`
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
	if err := ValidateServiceDescription(req.Description); err != nil {
		return err
	}

	if req.Credential == nil {
		return ErrMissingField("credential")
	}
	if err := req.Credential.Validate(); err != nil {
		return err
	}

	if req.AccountKey == nil {
		return ErrMissingField("account_key")
	}
	if err := req.AccountKey.Validate(); err != nil {
		return err
	}

	if req.RepoMember == nil {
		return ErrMissingField("repo_member")
	}
	if err := req.RepoMember.Validate(); err != nil {
		return err
	}

	return nil
}
