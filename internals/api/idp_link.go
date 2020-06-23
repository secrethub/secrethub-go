package api

import (
	"time"

	"github.com/secrethub/secrethub-go/pkg/oauthorizer"
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
