// +build !production

// Package fakeclient provides mock implementations of
// the client to be used for testing.
package fakeclient

import "github.com/secrethub/secrethub-go/pkg/secrethub"

// Client implements the secrethub.Client interface.
type Client struct {
	AccessRuleService *AccessRuleService
	AccountService    *AccountService
	CredentialService *CredentialService
	DirService        *DirService
	IDPLinkService    *IDPLinkService
	MeService         *MeService
	OrgService        *OrgService
	RepoService       *RepoService
	SecretService     *SecretService
	ServiceService    *ServiceService
	UserService       *UserService
}

// AccessRules implements the secrethub.Client interface.
func (c Client) AccessRules() secrethub.AccessRuleService {
	return c.AccessRuleService
}

// Accounts implements the secrethub.Client interface.
func (c Client) Accounts() secrethub.AccountService {
	return c.AccountService
}

// Dirs implements the secrethub.Client interface.
func (c Client) Dirs() secrethub.DirService {
	return c.DirService
}

// Me implements the secrethub.Client interface.
func (c Client) Me() secrethub.MeService {
	return nil
}

// Orgs implements the secrethub.Client interface.
func (c Client) Orgs() secrethub.OrgService {
	return c.OrgService
}

// Repos implements the secrethub.Client interface.
func (c Client) Repos() secrethub.RepoService {
	return c.RepoService
}

// Secrets implements the secrethub.Client interface.
func (c Client) Secrets() secrethub.SecretService {
	return c.SecretService
}

// Services implements the secrethub.Client interface.
func (c Client) Services() secrethub.ServiceService {
	return c.ServiceService
}

// Users implements the secrethub.Client interface.
func (c Client) Users() secrethub.UserService {
	return c.UserService
}
