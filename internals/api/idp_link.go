package api

import (
	"net/http"
	"regexp"
	"time"

	"github.com/secrethub/secrethub-go/pkg/oauthorizer"
)

var (
	ErrInvalidIDPLinkType      = errAPI.Code("invalid_idP_link_type").StatusError("invalid IDP link type", http.StatusBadRequest)
	ErrInvalidGCPProjectID     = errAPI.Code("invalid_gcp_project_id").StatusErrorPref("invalid GCP project ID: %s", http.StatusBadRequest)
	ErrVerifyingGCPAccessProof = errAPI.Code("gcp_verification_error").StatusError("could not verify GCP authorization", http.StatusPreconditionFailed)
	ErrGCPLinkPermissionDenied = errAPI.Code("gcp_permission_denied").StatusError("missing required projects.get permission to create link to GCP project", http.StatusPreconditionFailed)

	gcpProjectIDPattern = regexp.MustCompile("^[a-z][a-z0-9-]*[a-z0-9]$")
)

type CreateIdentityProviderLinkGCPRequest struct {
	RedirectURL       string `json:"redirect_url"`
	AuthorizationCode string `json:"authorization_code"`
}

type IdentityProviderLinkType string

const (
	IdentityProviderLinkGCP IdentityProviderLinkType = "gcp"
)

type IdentityProviderLink struct {
	Type      IdentityProviderLinkType `json:"type"`
	Namespace string                   `json:"namespace"`
	LinkedID  string                   `json:"linked_id"`
	CreatedAt time.Time                `json:"created_at"`
}

type OAuthConfig struct {
	ClientID string   `json:"client_id"`
	AuthURI  string   `json:"auth_uri"`
	Scopes   []string `json:"scopes"`
}

func (c OAuthConfig) Authorizer() oauthorizer.Authorizer {
	return oauthorizer.NewAuthorizer(c.AuthURI, c.ClientID, c.Scopes...)
}

// ValidateLinkedID calls the validation function corresponding to the link type and returns the corresponding result.
func ValidateLinkedID(linkType IdentityProviderLinkType, linkedID string) error {
	switch linkType {
	case IdentityProviderLinkGCP:
		return ValidateGCPProjectID(linkedID)
	default:
		return ErrInvalidIDPLinkType
	}
}

// ValidateGCPProjectID returns an error if the provided value is not a valid GCP project ID.
func ValidateGCPProjectID(projectID string) error {
	if len(projectID) < 6 || len(projectID) > 30 {
		return ErrInvalidGCPProjectID("length must be 6 to 30 character")
	}
	if !gcpProjectIDPattern.MatchString(projectID) {
		return ErrInvalidGCPProjectID("can only contains lowercase letter, digits and hyphens")
	}
	return nil
}
