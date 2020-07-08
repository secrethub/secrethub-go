package api

import (
	"net/http"
	"net/url"
	"regexp"
	"time"
)

var (
	ErrInvalidIDPLinkType          = errAPI.Code("invalid_idp_link_type").StatusError("invalid IDP link type", http.StatusBadRequest)
	ErrInvalidGCPProjectID         = errAPI.Code("invalid_gcp_project_id").StatusErrorPref("invalid GCP project ID: %s", http.StatusBadRequest)
	ErrVerifyingGCPAccessProof     = errAPI.Code("gcp_verification_error").StatusError("could not verify GCP authorization", http.StatusInternalServerError)
	ErrInvalidGCPAuthorizationCode = errAPI.Code("invalid_authorization_code").StatusError("authorization code was not accepted by GCP", http.StatusPreconditionFailed)
	ErrGCPLinkPermissionDenied     = errAPI.Code("gcp_permission_denied").StatusError("missing required projects.get permission to create link to GCP project", http.StatusPreconditionFailed)

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

// IdentityProviderLink is a prerequisite for creating some identity provider backed service accounts.
// These links prove that a namespace's member has access to a resource (identified by the LinkedID) within
// the identity provider. Once a link between a namespace and an identity provider has been created, from then on
// service accounts can be created within the scope described by the LinkedID. For example, after creating a link
// to a GCP Project, GCP service accounts within that project can be used for the GCP Identity Provider.
//
// The meaning of LinkedID depends on the type of the IdentityProviderLink in the following way:
// - GCP: LinkedID is a GCP Project ID.
type IdentityProviderLink struct {
	Type      IdentityProviderLinkType `json:"type"`
	Namespace string                   `json:"namespace"`
	LinkedID  string                   `json:"linked_id"`
	CreatedAt time.Time                `json:"created_at"`
}

type OAuthConfig struct {
	ClientID  string   `json:"client_id"`
	AuthURI   string   `json:"auth_uri"`
	Scopes    []string `json:"scopes"`
	ResultURL *url.URL `json:"result_url"`
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
