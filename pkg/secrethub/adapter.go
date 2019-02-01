package secrethub

// Client is the SecretHub client.
type Client interface {
	AccessRules() AccessRuleService
	Accounts() AccountService
	Dirs() DirService
	Orgs() OrgService
	Repos() RepoService
	Secrets() SecretService
	Services() ServiceService
	Users() UserService
}

type clientAdapter struct {
	client client
}

// AccessRules returns an AccessRuleService.
func (c clientAdapter) AccessRules() AccessRuleService {
	return newAccessRuleService(c.client)
}

// Accounts returns an AccountService.
func (c clientAdapter) Accounts() AccountService {
	return newAccountService(c.client)
}

// Dirs returns an DirService.
func (c clientAdapter) Dirs() DirService {
	return newDirService(c.client)
}

// Orgs returns an OrgService.
func (c clientAdapter) Orgs() OrgService {
	return newOrgService(c.client)
}

// Repos returns an RepoService.
func (c clientAdapter) Repos() RepoService {
	return newRepoService(c.client)
}

// Secrets returns an SecretService.
func (c clientAdapter) Secrets() SecretService {
	return newSecretService(c.client)
}

// Services returns an ServiceService.
func (c clientAdapter) Services() ServiceService {
	return newServiceService(c.client)
}

// Users returns an UserService.
func (c clientAdapter) Users() UserService {
	return newUserService(c.client)
}

// NewClient creates a new SecretHub client.
// It overrides the default configuration with the options when given.
func NewClient(credential Credential, opts *ClientOptions) Client {
	return &clientAdapter{
		client: newClient(credential, opts),
	}
}
